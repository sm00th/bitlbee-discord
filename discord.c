/*
 * Copyright 2015 Artem Savkov <artem.savkov@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <time.h>
#include <libwebsockets.h>
#include <bitlbee/bitlbee.h>
#include <bitlbee/http_client.h>
#include <bitlbee/json.h>
#include <bitlbee/json_util.h>

#define DISCORD_HOST "discordapp.com"
#define DEFAULT_KA_INTERVAL 30000

typedef enum {
  WS_IDLE,
  WS_CONNECTING,
  WS_CONNECTED,
  WS_READY,
  WS_CLOSING,
} ws_state;

typedef enum {
  ACTION_CREATE,
  ACTION_DELETE,
  ACTION_UPDATE
} handler_action;

typedef struct _discord_data {
  char     *token;
  char     *id;
  char     *uname;
  char     *gateway;
  struct libwebsocket_context *lwsctx;
  struct libwebsocket *lws;
  GSList   *servers;
  GSList   *pchannels;
  gint     main_loop_id;
  GString  *ws_buf;
  ws_state state;
  gint     ka_interval;
  gint     ka_loop_id;
} discord_data;

typedef struct _server_info {
  char                 *name;
  char                 *id;
  GSList               *users;
  GSList               *channels;
  struct im_connection *ic;
} server_info;

typedef struct _channel_info {
  char                 *id;
  guint64              last_msg;
  union {
    struct {
      struct groupchat     *gc;
      server_info          *sinfo;
    } channel;
    struct {
      char                 *handle;
      struct im_connection *ic;
    } user;
  } to;
  gboolean             is_private;
} channel_info;

typedef struct _user_info {
  char                 *id;
  char                 *name;
  bee_user_t           *user;
} user_info;

typedef struct _cadd {
  server_info *sinfo;
  char *name;
  char *id;
  char *last_msg;
  char *topic;
} cadd;

static void discord_http_get(struct im_connection *ic, const char *api_path,
                             http_input_function cb_func, gpointer data);

static void free_cadd(cadd *ca) {
  g_free(ca->last_msg);
  g_free(ca->topic);
  g_free(ca->name);
  g_free(ca->id);
  g_free(ca);
}

static void free_user_info(user_info *uinfo) {
  g_free(uinfo->name);
  g_free(uinfo->id);
  g_free(uinfo);
}

static void free_channel_info(channel_info *cinfo) {
  g_free(cinfo->id);
  cinfo->id = NULL;

  if (cinfo->is_private) {
    g_free(cinfo->to.user.handle);
  } else {
    imcb_chat_free(cinfo->to.channel.gc);
  }

  g_free(cinfo);
}

static void free_server_info(server_info *sinfo) {
  g_free(sinfo->name);
  g_free(sinfo->id);

  g_slist_free_full(sinfo->channels, (GDestroyNotify)free_channel_info);
  g_slist_free_full(sinfo->users, (GDestroyNotify)free_user_info);

  g_free(sinfo);
}

static void discord_logout(struct im_connection *ic) {
  discord_data *dd = ic->proto_data;

  if (dd->lwsctx != NULL) {
    libwebsocket_context_destroy(dd->lwsctx);
  }

  g_slist_free_full(dd->pchannels, (GDestroyNotify)free_channel_info);
  g_slist_free_full(dd->servers, (GDestroyNotify)free_server_info);

  g_free(dd->gateway);
  g_free(dd->token);
  g_free(dd->uname);
  g_free(dd->id);

  g_free(dd);
}

static void discord_dump_http_reply(struct http_request *req) {
  g_print("============================\nstatus=%d\n", req->status_code);
  g_print("\nrh=%s\nrb=%s\n", req->reply_headers, req->reply_body);
}

static void discord_send_msg_cb(struct http_request *req) {
  struct im_connection *ic = req->data;
  if (req->status_code != 200) {
    imcb_error(ic, "Failed to send message (%d).", req->status_code);
  }
}

static int lws_send_payload(struct libwebsocket *wsi, const char *pload,
                            size_t psize) {
  int ret = 0;
  unsigned char *buf = g_malloc0(LWS_SEND_BUFFER_PRE_PADDING + \
                                 psize + LWS_SEND_BUFFER_POST_PADDING);
  strncpy((char*)&buf[LWS_SEND_BUFFER_PRE_PADDING], pload, psize);
  ret = libwebsocket_write(wsi, &buf[LWS_SEND_BUFFER_PRE_PADDING], psize,
                           LWS_WRITE_TEXT);
  g_free(buf);
  return ret;
}

static gint cmp_chan_id(const channel_info *cinfo, const char *chan_id) {
  return g_strcmp0(cinfo->id, chan_id);
}

static gint cmp_user_id(const user_info *uinfo, const char *user_id) {
  return g_strcmp0(uinfo->id, user_id);
}

static gint cmp_server_id(const server_info *sinfo, const char *server_id) {
  return g_strcmp0(sinfo->id, server_id);
}

static server_info *get_server_by_id(discord_data *dd, const char *server_id) {
  GSList *sl = g_slist_find_custom(dd->servers, server_id,
                                   (GCompareFunc)cmp_server_id);

  return sl == NULL ?  NULL : sl->data;
}

static channel_info *get_channel_by_id(discord_data *dd, const char *channel_id,
                                      const char *server_id) {
  GSList *cl = g_slist_find_custom(dd->pchannels, channel_id,
                                   (GCompareFunc)cmp_chan_id);

  if (cl == NULL && server_id != NULL) {
    server_info *sinfo = get_server_by_id(dd, server_id);
    cl = g_slist_find_custom(sinfo->channels, channel_id,
                             (GCompareFunc)cmp_chan_id);
  }

  return cl == NULL ?  NULL : cl->data;
}

static gboolean lws_ka_loop(gpointer data, gint fd,
                                 b_input_condition cond) {
  struct im_connection *ic = data;
  discord_data *dd = ic->proto_data;

  if (dd->state == WS_READY) {
    libwebsocket_callback_on_writable(dd->lwsctx, dd->lws);
  }
  return TRUE;
}

static gboolean lws_service_loop(gpointer data, gint fd,
                                 b_input_condition cond) {
  struct im_connection *ic = data;

  discord_data *dd = ic->proto_data;

  libwebsocket_service(dd->lwsctx, 0);

  if (dd->state == WS_CLOSING) {
    imc_logout(ic, TRUE);
  }

  return TRUE;
}

static void discord_add_channel(cadd *ca) {
  struct im_connection *ic = ca->sinfo->ic;
  discord_data *dd = ic->proto_data;

  char *title;

  title = g_strdup_printf("%s/%s", ca->sinfo->name,
                          ca->name);
  struct groupchat *gc = imcb_chat_new(ic, title);
  imcb_chat_name_hint(gc, ca->name);
  if (ca->topic != NULL) {
    imcb_chat_topic(gc, "root", ca->topic, 0);
  }
  g_free(title);

  for (GSList *ul = ca->sinfo->users; ul; ul = g_slist_next(ul)) {
    user_info *uinfo = ul->data;
    if (uinfo->user->flags & BEE_USER_ONLINE) {
      imcb_chat_add_buddy(gc, uinfo->user->handle);
    }
  }

  imcb_chat_add_buddy(gc, dd->uname);

  channel_info *cinfo = g_new0(channel_info, 1);
  cinfo->is_private = FALSE;
  cinfo->to.channel.gc = gc;
  cinfo->to.channel.sinfo = ca->sinfo;
  cinfo->id = g_strdup(ca->id);
  if (ca->last_msg != NULL) {
    cinfo->last_msg = g_ascii_strtoull(ca->last_msg, NULL, 10);
  }

  gc->data = cinfo;

  ca->sinfo->channels = g_slist_prepend(ca->sinfo->channels, cinfo);
}

static void handle_presence(struct im_connection *ic, json_value *pinfo,
                            const char *server_id) {
  discord_data *dd = ic->proto_data;
  server_info *sinfo = get_server_by_id(dd, server_id);

  if (sinfo == NULL) {
    return;
  }

  GSList *ul = g_slist_find_custom(sinfo->users,
                                   json_o_str(
                                     json_o_get(pinfo, "user"),
                                     "id"),
                                   (GCompareFunc)cmp_user_id);

  if (ul != NULL) {
    user_info *uinfo = (user_info*)ul->data;
    const char *status = json_o_str(pinfo, "status");
    int flags = 0;

    if (uinfo->user->ic != ic ||
        g_strcmp0(uinfo->user->handle, dd->uname) == 0) {
      return;
    }

    if (g_strcmp0(status, "online") == 0) {
      flags = BEE_USER_ONLINE;
    } else if (g_strcmp0(status, "idle") == 0) {
      flags = BEE_USER_ONLINE | BEE_USER_AWAY;
    }

    for (GSList *cl = sinfo->channels; cl; cl = g_slist_next(cl)) {
      channel_info *cinfo = cl->data;

      if (flags) {
        imcb_chat_add_buddy(cinfo->to.channel.gc, uinfo->user->handle);
      } else {
        imcb_chat_remove_buddy(cinfo->to.channel.gc, uinfo->user->handle,
                               NULL);
      }
    }

    imcb_buddy_status(ic, uinfo->name, flags, NULL, NULL);
  }
}

static void handle_channel(struct im_connection *ic, json_value *cinfo,
                           const char *server_id, handler_action action) {

  discord_data *dd = ic->proto_data;
  server_info *sinfo = get_server_by_id(dd, server_id);

  if (sinfo == NULL) {
    return;
  }

  const char *id    = json_o_str(cinfo, "id");
  const char *name  = json_o_str(cinfo, "name");
  const char *type  = json_o_str(cinfo, "type");
  const char *lmid  = json_o_str(cinfo, "last_message_id");
  const char *topic = json_o_str(cinfo, "topic");

  if (action == ACTION_CREATE) {
    if (g_strcmp0(type, "text") == 0) {
      cadd *ca = g_new0(cadd, 1);
      ca->sinfo = sinfo;
      ca->topic = g_strdup(topic);
      ca->id = g_strdup(id);
      ca->name = g_strdup(name);
      ca->last_msg = g_strdup(lmid);

      // TODO: Check access
      discord_add_channel(ca);
      free_cadd(ca);
    }
  } else {
    channel_info *cdata = get_channel_by_id(dd, id, server_id);
    if (cdata == NULL) {
      return;
    }

    if (action == ACTION_DELETE) {
      GSList *clist;
      if (cdata->is_private == TRUE) {
        clist = dd->pchannels;
      } else {
        clist = sinfo->channels;
      }

      clist = g_slist_remove(clist, cdata);
      free_channel_info(cdata);
    } else if (action == ACTION_UPDATE) {
      if (cdata->is_private == FALSE) {
        if (g_strcmp0(topic, cdata->to.channel.gc->topic) != 0) {
          imcb_chat_topic(cdata->to.channel.gc, "root", (char*)topic, 0);
        }
      }
    }
  }
}

static void handle_user(struct im_connection *ic, json_value *uinfo,
                           const char *server_id, handler_action action) {
  discord_data *dd = ic->proto_data;
  server_info *sinfo = get_server_by_id(dd, server_id);

  if (sinfo == NULL) {
    return;
  }

  const char *id   = json_o_str(uinfo, "id");
  const char *name = json_o_str(uinfo, "username");

  if (action == ACTION_CREATE) {
    if (name && !bee_user_by_handle(ic->bee, ic, name)) {
      user_info *ui = g_new0(user_info, 1);

      imcb_add_buddy(ic, name, NULL);
      imcb_buddy_status(ic, name, 0, NULL, NULL);

      ui->user = bee_user_by_handle(ic->bee, ic, name);
      ui->id = g_strdup(id);
      ui->name = g_strdup(name);

      sinfo->users = g_slist_prepend(sinfo->users, ui);
    }
  } else if (action == ACTION_DELETE) {
    GSList *ul = g_slist_find_custom(sinfo->users, id,
                                     (GCompareFunc)cmp_user_id);

    if (ul == NULL) {
      return;
    }
    user_info *udata = ul->data;
    imcb_remove_buddy(ic, name, NULL);
    sinfo->users = g_slist_remove(sinfo->users, udata);
    free_user_info(udata);
  }
  // XXX: Should warn about unhandled action _UPDATE if we switch to some
  // centralized handling solution.
}

static void handle_server(struct im_connection *ic, json_value *sinfo,
                          handler_action action) {
  discord_data *dd = ic->proto_data;

  const char *id   = json_o_str(sinfo, "id");
  const char *name = json_o_str(sinfo, "name");

  if (action == ACTION_CREATE) {
    server_info *sdata = g_new0(server_info, 1);

    sdata->name = g_strdup(name);
    sdata->id = g_strdup(id);
    sdata->ic = ic;
    dd->servers = g_slist_prepend(dd->servers, sdata);

    json_value *channels = json_o_get(sinfo, "channels");
    if (channels != NULL && channels->type == json_array) {
      for (int cidx = 0; cidx < channels->u.array.length; cidx++) {
        json_value *cinfo = channels->u.array.values[cidx];
        handle_channel(ic, cinfo, sdata->id, ACTION_CREATE);
      }
    }

    json_value *members = json_o_get(sinfo, "members");
    if (members != NULL && members->type == json_array) {
      for (int midx = 0; midx < members->u.array.length; midx++) {
        json_value *uinfo = json_o_get(members->u.array.values[midx],
                                       "user");
        handle_user(ic, uinfo, sdata->id, ACTION_CREATE);
      }
    }

    json_value *presences = json_o_get(sinfo, "presences");
    if (presences != NULL && presences->type == json_array) {
      for (int pidx = 0; pidx < presences->u.array.length; pidx++) {
        json_value *pinfo = presences->u.array.values[pidx];
        handle_presence(ic, pinfo, sdata->id);
      }
    }
  } else {
    server_info *sdata = get_server_by_id(dd, id);
    if (sdata == NULL) {
      return;
    }

    if (action == ACTION_DELETE) {
      for (GSList *ul = sdata->users; ul; ul = g_slist_next(ul)) {
        user_info *uinfo = ul->data;
        imcb_remove_buddy(ic, uinfo->name, NULL);
      }
      dd->servers = g_slist_remove(dd->servers, sdata);
      free_server_info(sdata);
    }
  }
}

static void parse_message(struct im_connection *ic) {
  discord_data *dd = ic->proto_data;
  json_value *js = json_parse(dd->ws_buf->str, dd->ws_buf->len);
  if (!js || js->type != json_object) {
    imcb_error(ic, "Failed to parse json reply.");
    imc_logout(ic, TRUE);
    goto exit;
  }

  const char *event = json_o_str(js, "t");
  if (g_strcmp0(event, "READY") == 0) {
    dd->state = WS_READY;
    json_value *data = json_o_get(js, "d");

    if (data == NULL || data->type != json_object) {
      goto exit;
    }

    json_value *hbeat = json_o_get(data, "heartbeat_interval");
    if (hbeat != NULL && hbeat->type == json_integer) {
      dd->ka_interval = hbeat->u.integer;
      if (dd->ka_interval == 0) {
        dd->ka_interval = DEFAULT_KA_INTERVAL;
      }
    }
    dd->ka_loop_id = b_timeout_add(dd->ka_interval, lws_ka_loop, ic);

    json_value *user = json_o_get(data, "user");
    if (user != NULL && user->type == json_object) {
      dd->id = json_o_strdup(user, "id");
      dd->uname = json_o_strdup(user, "username");
    }

    json_value *guilds = json_o_get(data, "guilds");
    if (guilds != NULL && guilds->type == json_array) {
      for (int gidx = 0; gidx < guilds->u.array.length; gidx++) {
        if (guilds->u.array.values[gidx]->type == json_object) {
          json_value *ginfo = guilds->u.array.values[gidx];
          handle_server(ic, ginfo, ACTION_CREATE);
        }
      }
    }

    json_value *pcs = json_o_get(data, "private_channels");
    if (pcs != NULL && pcs->type == json_array) {
      for (int pcidx = 0; pcidx < pcs->u.array.length; pcidx++) {
        if (pcs->u.array.values[pcidx]->type == json_object) {
          json_value *pcinfo = pcs->u.array.values[pcidx];

          char *lmsg = (char *)json_o_str(pcinfo, "last_message_id");

          channel_info *ci = g_new0(channel_info, 1);
          ci->is_private = TRUE;
          if (lmsg != NULL) {
            ci->last_msg = g_ascii_strtoull(lmsg, NULL, 10);
          }
          ci->to.user.handle = json_o_strdup(json_o_get(pcinfo, "recipient"),
                     "username");
          ci->id = json_o_strdup(pcinfo, "id");
          ci->to.user.ic = ic;

          dd->pchannels = g_slist_prepend(dd->pchannels, ci);
        }
      }
    }

    imcb_connected(ic);
  } else if (g_strcmp0(event, "TYPING_START") == 0) {
    // Ignoring those for now
  } else if (g_strcmp0(event, "PRESENCE_UPDATE") == 0) {
    json_value *pinfo = json_o_get(js, "d");
    handle_presence(ic, pinfo, json_o_str(pinfo, "guild_id"));
  } else if (g_strcmp0(event, "CHANNEL_CREATE") == 0) {
    json_value *cinfo = json_o_get(js, "d");
    handle_channel(ic, cinfo, json_o_str(cinfo, "guild_id"), ACTION_CREATE);
  } else if (g_strcmp0(event, "CHANNEL_DELETE") == 0) {
    json_value *cinfo = json_o_get(js, "d");
    handle_channel(ic, cinfo, json_o_str(cinfo, "guild_id"), ACTION_DELETE);
  } else if (g_strcmp0(event, "CHANNEL_UPDATE") == 0) {
    json_value *cinfo = json_o_get(js, "d");
    handle_channel(ic, cinfo, json_o_str(cinfo, "guild_id"), ACTION_UPDATE);
  } else if (g_strcmp0(event, "GUILD_MEMBER_ADD") == 0) {
    json_value *data = json_o_get(js, "d");
    handle_user(ic, json_o_get(data, "user"), json_o_str(data, "guild_id"),
                ACTION_CREATE);
  } else if (g_strcmp0(event, "GUILD_MEMBER_REMOVE") == 0) {
    json_value *data = json_o_get(js, "d");
    handle_user(ic, json_o_get(data, "user"), json_o_str(data, "guild_id"),
                ACTION_DELETE);
  } else if (g_strcmp0(event, "GUILD_CREATE") == 0) {
    json_value *sinfo = json_o_get(js, "d");
    handle_server(ic, sinfo, ACTION_CREATE);
  } else if (g_strcmp0(event, "GUILD_DELETE") == 0) {
    json_value *sinfo = json_o_get(js, "d");
    handle_server(ic, sinfo, ACTION_DELETE);
  } else if (g_strcmp0(event, "MESSAGE_CREATE") == 0) {
    json_value *minfo = json_o_get(js, "d");

    if (minfo == NULL || minfo->type != json_object) {
      goto exit;
    }

    guint64 msgid = g_ascii_strtoull(json_o_str(minfo, "id"), NULL, 10);
    const char *channel_id = json_o_str(minfo, "channel_id");
    GSList *cl = g_slist_find_custom(dd->pchannels, channel_id,
                                     (GCompareFunc)cmp_chan_id);
    if (cl == NULL) {
      for (GSList *sl = dd->servers; sl; sl = g_slist_next(sl)) {
        server_info *sinfo = sl->data;
        cl = g_slist_find_custom(sinfo->channels, channel_id,
                                 (GCompareFunc)cmp_chan_id);
        if (cl != NULL) {
          break;
        }
      }
      if (cl == NULL) {
        goto exit;
      }
    }
    channel_info *cinfo = cl->data;

    if (msgid > cinfo->last_msg) {
      if (cinfo->is_private) {
        if (!g_strcmp0(json_o_str(json_o_get(minfo, "author"), "username"),
                 cinfo->to.user.handle)) {
          imcb_buddy_msg(cinfo->to.user.ic,
                         cinfo->to.user.handle,
                         (char *)json_o_str(minfo, "content"), 0, 0);
        }
      } else {
        struct groupchat *gc = cinfo->to.channel.gc;
        gchar *msg = json_o_strdup(minfo, "content");
        json_value *mentions = json_o_get(minfo, "mentions");
        if (mentions != NULL && mentions->type == json_array) {
          for (int midx = 0; midx < mentions->u.array.length; midx++) {
            json_value *uinfo = mentions->u.array.values[midx];
            gchar *newmsg = NULL;
            gchar *idstr = g_strdup_printf("<@%s>", json_o_str(uinfo, "id"));
            gchar *unstr = g_strdup_printf("@%s",
                                           json_o_str(uinfo, "username"));
            GRegex *regex = g_regex_new(idstr, 0, 0, NULL);
            newmsg = g_regex_replace_literal(regex, msg, -1, 0,
                                             unstr, 0, NULL);
            g_free(msg);
            msg = newmsg;
            g_regex_unref(regex);
            g_free(idstr);
            g_free(unstr);
          }
        }

        imcb_chat_msg(gc, json_o_str(json_o_get(minfo, "author"), "username"),
                      msg, 0, 0);
        g_free(msg);
      }
      cinfo->last_msg = msgid;
    }
  } else {
    g_print("%s: unhandled event: %s\n", __func__, event);
    g_print("%s\n", dd->ws_buf->str);
  }

exit:
  json_value_free(js);
  return;
}

static int
discord_lws_http_only_cb(struct libwebsocket_context *this,
                         struct libwebsocket *wsi,
                         enum libwebsocket_callback_reasons reason,
                         void *user, void *in, size_t len) {
  struct im_connection *ic = libwebsocket_context_user(this);

  discord_data *dd = ic->proto_data;
  switch(reason) {
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
      dd->state = WS_CONNECTED;
      libwebsocket_callback_on_writable(this, wsi);
      break;
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
      imcb_error(ic, "Websocket connection error");
      if (in != NULL) {
        imcb_error(ic, in);
      }
      b_event_remove(dd->ka_loop_id);
      dd->state = WS_CLOSING;
      break;
    case LWS_CALLBACK_CLIENT_WRITEABLE:
      if (dd->state == WS_CONNECTED) {
        GString *buf = g_string_new("");
        g_string_printf(buf, "{\"d\":{\"v\":3,\"token\":\"%s\",\"properties\":{\"$referring_domain\":\"\",\"$browser\":\"bitlbee-discord\",\"$device\":\"bitlbee\",\"$referrer\":\"\",\"$os\":\"linux\"}},\"op\":2}", dd->token);
        lws_send_payload(wsi, buf->str, buf->len);
        g_string_free(buf, TRUE);
      } else if (dd->state == WS_READY) {
        GString *buf = g_string_new("");

        g_string_printf(buf, "{\"op\":1,\"d\":%tu}", time(NULL));
        lws_send_payload(dd->lws, buf->str, buf->len);
        g_string_free(buf, TRUE);
      } else {
        g_print("%s: Unhandled writable callback\n", __func__);
      }
      break;
    case LWS_CALLBACK_CLIENT_RECEIVE:
      {
        size_t rpload = libwebsockets_remaining_packet_payload(wsi);
        if (dd->ws_buf == NULL) {
          dd->ws_buf = g_string_new("");
        }
        dd->ws_buf = g_string_append(dd->ws_buf, in);
        if (rpload == 0) {
          parse_message(ic);
          g_string_free(dd->ws_buf, TRUE);
          dd->ws_buf = NULL;
        }
        break;
      }
    case LWS_CALLBACK_CLOSED:
      b_event_remove(dd->ka_loop_id);
      dd->state = WS_CLOSING;
      libwebsocket_cancel_service(dd->lwsctx);
      break;
    case LWS_CALLBACK_ADD_POLL_FD:
      {
        struct libwebsocket_pollargs *pargs = in;
        dd->main_loop_id = b_input_add(pargs->fd, B_EV_IO_READ,
                                       lws_service_loop, ic);
        break;
      }
    case LWS_CALLBACK_DEL_POLL_FD:
      b_event_remove(dd->main_loop_id);
      break;
    case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
      {
        struct libwebsocket_pollargs *pargs = in;
        int flags = 0;
        b_event_remove(dd->main_loop_id);
        if (pargs->events & POLLIN) {
          flags |= B_EV_IO_READ;
        }
        if (pargs->events & POLLOUT) {
          flags |= B_EV_IO_WRITE;
        }
        dd->main_loop_id = b_input_add(pargs->fd, flags, lws_service_loop, ic);
        break;
      }
    case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
    case LWS_CALLBACK_GET_THREAD_ID:
    case LWS_CALLBACK_LOCK_POLL:
    case LWS_CALLBACK_UNLOCK_POLL:
    case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:
    case LWS_CALLBACK_PROTOCOL_INIT:
    case LWS_CALLBACK_PROTOCOL_DESTROY:
    case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
    case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
    case LWS_CALLBACK_WSI_CREATE:
    case LWS_CALLBACK_WSI_DESTROY:
      // Ignoring these, this block should be removed when defult is set to
      // stay silent.
      break;
    default:
      g_print("%s: unknown rsn=%d\n", __func__, reason);
      break;
  }
  return 0;
}

static struct libwebsocket_protocols protocols[] = {
  { "http-only,chat", discord_lws_http_only_cb, 0, 0 },
  { NULL, NULL, 0, 0 } /* end */
};

static void discord_gateway_cb(struct http_request *req) {
  struct im_connection *ic = req->data;

  //discord_dump_http_reply(req);

  if (req->status_code == 200) {
    json_value *js = json_parse(req->reply_body, req->body_size);
    if (!js || js->type != json_object) {
      imcb_error(ic, "Failed to parse json reply.");
      imc_logout(ic, TRUE);
      json_value_free(js);
      return;
    }
    discord_data *dd = ic->proto_data;

    const char *gw = json_o_str(js, "url");
    char *tmp;
    if ((tmp = g_strstr_len(gw, MIN(strlen(gw), 6), "://"))) {
      dd->gateway = g_strdup(tmp + 3);
    } else {
      dd->gateway = g_strdup(gw);
    }

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.extensions = NULL;
#ifndef LWS_NO_EXTENSIONS
    info.extensions = libwebsocket_get_internal_extensions();
#endif
    info.gid = -1;
    info.uid = -1;
    info.user = ic;

    lws_set_log_level(0, NULL);

    dd->lwsctx = libwebsocket_create_context(&info);
    if (dd->lwsctx == NULL) {
      imcb_error(ic, "Failed to create websockets context.");
      imc_logout(ic, TRUE);
      json_value_free(js);
      return;
    }

    dd->lws = libwebsocket_client_connect(dd->lwsctx, dd->gateway,
                      443, 2, "/", dd->gateway,
                      "discordapp.com",
                      protocols[0].name, -1);

    dd->state = WS_CONNECTING;

    json_value_free(js);
  } else {
    imcb_error(ic, "Failed to get info about self.");
    imc_logout(ic, TRUE);
  }
}

static void discord_login_cb(struct http_request *req) {
  struct im_connection *ic = req->data;

  if (req->status_code == 200) {
    json_value *js = json_parse(req->reply_body, req->body_size);
    if (!js || js->type != json_object) {
      imcb_error(ic, "Failed to parse json reply.");
      imc_logout(ic, TRUE);
      json_value_free(js);
      return;
    }
    if (req->status_code == 200) {
      discord_data *dd = ic->proto_data;
      dd->token = json_o_strdup(js, "token");

      discord_http_get(ic, "gateway", discord_gateway_cb, ic);
    } else {
      JSON_O_FOREACH(js, k, v){
        if (v->type != json_array) {
          continue;
        }

        int i;
        GString *err = g_string_new("");
        g_string_printf(err, "%s:", k);
        for (i = 0; i < v->u.array.length; i++) {
          if (v->u.array.values[i]->type == json_string) {
            g_string_append_printf(err, " %s",
                                   v->u.array.values[i]->u.string.ptr);
          }
        }
        imcb_error(ic, err->str);
        g_string_free(err, TRUE);
      }
    }
    json_value_free(js);
  } else {
    imcb_error(ic, "Failed to login: %d.", req->status_code);
    imc_logout(ic, TRUE);
  }
}

static void discord_login(account_t *acc) {
  struct im_connection *ic = imcb_new(acc);
  GString *request = g_string_new("");
  GString *jlogin = g_string_new("");


  discord_data *dd = g_new0(discord_data, 1);
  dd->ka_interval = DEFAULT_KA_INTERVAL;
  ic->proto_data = dd;

  g_string_printf(jlogin, "{\"email\":\"%s\",\"password\":\"%s\"}",
                  acc->user,
                  acc->pass);

  g_string_printf(request, "POST /api/auth/login HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "User-Agent: Bitlbee-Discord\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: %zd\r\n\r\n"
                  "%s",
                  set_getstr(&ic->acc->set, "host"),
                  jlogin->len,
                  jlogin->str);

  (void) http_dorequest(set_getstr(&ic->acc->set, "host"), 80, 0,
                        request->str, discord_login_cb, acc->ic);

  g_string_free(jlogin, TRUE);
  g_string_free(request, TRUE);
}

static gboolean discord_is_self(struct im_connection *ic, const char *who) {
  discord_data *dd = ic->proto_data;
  return !g_strcmp0(dd->uname, who);
}

static void discord_send_msg(struct im_connection *ic, char *id, char *msg) {
  discord_data *dd = ic->proto_data;
  GString *request = g_string_new("");
  GString *content = g_string_new("");

  g_string_printf(content, "{\"content\":\"%s\"}", msg);
  g_string_printf(request, "POST /api/channels/%s/messages HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "User-Agent: Bitlbee-Discord\r\n"
                  "authorization: %s\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: %zd\r\n\r\n"
                  "%s",
                  id,
                  set_getstr(&ic->acc->set, "host"),
                  dd->token,
                  content->len,
                  content->str);

  (void) http_dorequest(set_getstr(&ic->acc->set, "host"), 80, 0,
                        request->str, discord_send_msg_cb, ic);

  g_string_free(content, TRUE);
  g_string_free(request, TRUE);
}

static void discord_chat_msg(struct groupchat *gc, char *msg, int flags) {
  channel_info *cinfo = gc->data;

  discord_send_msg(cinfo->to.channel.gc->ic, cinfo->id, msg);
}

static int discord_buddy_msg(struct im_connection *ic, char *to, char *msg,
                             int flags) {
  discord_data *dd = ic->proto_data;

  for (GSList *cl = dd->pchannels; cl; cl = g_slist_next(cl)) {
    channel_info *cinfo = cl->data;
    if (cinfo->is_private && g_strcmp0(cinfo->to.user.handle, to) == 0) {
      discord_send_msg(ic, cinfo->id, msg);
      return 0;
    }
  }

  return 1;
}

static void discord_init(account_t *acc) {
  set_t *s;

  s = set_add(&acc->set, "host", DISCORD_HOST, NULL, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;
}

G_MODULE_EXPORT void init_plugin(void)
{
  struct prpl *dpp;

  static const struct prpl pp = {
    .name = "discord",
    .init = discord_init,
    .login = discord_login,
    .logout = discord_logout,
    .chat_msg = discord_chat_msg,
    .buddy_msg = discord_buddy_msg,
    .handle_cmp = g_strcmp0,
    .handle_is_self = discord_is_self
  };
  dpp = g_memdup(&pp, sizeof pp);
  register_protocol(dpp);
}

static void discord_http_get(struct im_connection *ic, const char *api_path,
                             http_input_function cb_func, gpointer data) {
  discord_data *dd = ic->proto_data;
  GString *request = g_string_new("");
  g_string_printf(request, "GET /api/%s HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "User-Agent: Bitlbee-Discord\r\n"
                  "Content-Type: application/json\r\n"
                  "authorization: %s\r\n\r\n",
                  api_path,
                  set_getstr(&ic->acc->set, "host"),
                  dd->token);

  (void) http_dorequest(set_getstr(&ic->acc->set, "host"), 80, 0,
                        request->str, cb_func, data);
  g_string_free(request, TRUE);
}

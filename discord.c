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
#include <bitlbee/bitlbee.h>
#include <bitlbee/http_client.h>
#include <bitlbee/json.h>
#include <bitlbee/json_util.h>

#define DISCORD_HOST "discordapp.com"

typedef enum {
  SERVER_UNKNOWN,
  SERVER_CONNECTING,
  SERVER_CONNECTED
} server_state;

typedef struct _discord_data {
  char     *token;
  char     *id;
  char     *uname;
  GSList   *servers;
  GSList   *channels;
  gint     main_loop_id;
} discord_data;

typedef struct _server_info {
  char                 *name;
  char                 *id;
  GSList               *users;
  struct im_connection *ic;
  server_state         state;
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

static void free_user_info(user_info *uinfo) {
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

  g_slist_free_full(sinfo->users, (GDestroyNotify)free_user_info);

  g_free(sinfo);
}

static void discord_logout(struct im_connection *ic) {
  discord_data *dd = ic->proto_data;

  b_event_remove(dd->main_loop_id);

  g_slist_free_full(dd->channels, (GDestroyNotify)free_channel_info);
  g_slist_free_full(dd->servers, (GDestroyNotify)free_server_info);

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

static void discord_messages_cb(struct http_request *req) {
  channel_info *cinfo = req->data;
  struct im_connection *ic;
  discord_data *dd;

  // Channel got freed, we are exiting, so don't try anything.
  if (cinfo->id == NULL) {
    return;
  }

  if (cinfo->is_private) {
    ic = cinfo->to.user.ic;
  } else {
    ic = cinfo->to.channel.gc->ic;
  }
  dd = ic->proto_data;

  if (req->status_code == 200) {
    int i;
    json_value *js = json_parse(req->reply_body, req->body_size);
    if (!js || js->type != json_array) {
      imcb_error(ic, "Failed to parse json reply.");
      imc_logout(ic, TRUE);
      json_value_free(js);
      return;
    }

    for (i = js->u.array.length - 1; i >= 0; i--) {
      if (js->u.array.values[i]->type == json_object) {
        json_value *minfo = js->u.array.values[i];
        guint64 msgid = g_ascii_strtoull(json_o_str(minfo, "id"), NULL, 10);
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
            imcb_chat_msg(gc, json_o_str(json_o_get(minfo, "author"), "username"),
                          (char *)json_o_str(minfo, "content"), 0, 0);
          }
          cinfo->last_msg = msgid;
        }
      }
    }
    json_value_free(js);
  } else {
    if (cinfo->is_private) {
      imcb_error(ic, "Failed to get messages from handle: %s (%d).",
                 cinfo->to.user.handle, req->status_code);
    } else {
      imcb_error(ic, "Failed to get messages from channel: %s (%d).",
                 cinfo->to.channel.gc->title, req->status_code);
    }
    if (req->status_code == 403) {
      dd->channels = g_slist_remove(dd->channels, cinfo);
      free_channel_info(cinfo);
    } else {
      imc_logout(ic, TRUE);
    }
  }
}

static gboolean discord_main_loop(gpointer data, gint fd,
                                  b_input_condition cond) {
  struct im_connection *ic = data;
  discord_data *dd = ic->proto_data;
  GSList *l;

  for (l = dd->channels; l; l = l->next) {
    channel_info *cinfo = l->data;
    GString *api_path = g_string_new("");
    g_string_printf(api_path, "channels/%s/messages", cinfo->id);
    if (cinfo->last_msg != 0) {
      g_string_append_printf(api_path, "?limit=%d",
                             set_getint(&ic->acc->set, "fetch_interval") * 3);
    }
    discord_http_get(ic, api_path->str, discord_messages_cb, cinfo);
    g_string_free(api_path, TRUE);
  }
  return TRUE;
}

static void try_start_loop(struct im_connection *ic) {
  discord_data *dd = ic->proto_data;
  gboolean all_connected = TRUE;
  GSList *l;

  for (l = dd->servers; l; l = l->next) {
    server_info *sinfo = l->data;
    if (sinfo->state != SERVER_CONNECTED) {
      all_connected = FALSE;
      break;
    }
  }

  if (all_connected) {
    discord_main_loop(ic, -1, 0);
    imcb_connected(ic);

    dd->main_loop_id = b_timeout_add(set_getint(&ic->acc->set,
                                     "fetch_interval") * 1000,
                                     discord_main_loop, ic);
  }
}

static void discord_add_channel(cadd *ca) {
  struct im_connection *ic = ca->sinfo->ic;
  discord_data *dd = ic->proto_data;

  char *title;
  GSList *l;

  title = g_strdup_printf("%s/%s", ca->sinfo->name,
                          ca->name);
  struct groupchat *gc = imcb_chat_new(ic, title);
  imcb_chat_name_hint(gc, ca->name);
  if (ca->topic != NULL) {
    imcb_chat_topic(gc, "root", ca->topic, 0);
  }
  g_free(title);

  for (l = ca->sinfo->users; l; l = l->next) {
    user_info *uinfo = l->data;
    if (uinfo->user->ic == ic &&
        g_strcmp0(uinfo->user->handle, dd->uname) != 0) {
      imcb_chat_add_buddy(gc, uinfo->user->handle);
    }
  }

  imcb_chat_add_buddy(gc, dd->uname);

  channel_info *ci = g_new0(channel_info, 1);
  ci->is_private = FALSE;
  ci->to.channel.gc = gc;
  ci->to.channel.sinfo = ca->sinfo;
  ci->id = g_strdup(ca->id);
  if (ca->last_msg != NULL) {
    ci->last_msg = g_ascii_strtoull(ca->last_msg, NULL, 10);
  }

  gc->data = ci;

  dd->channels = g_slist_prepend(dd->channels, ci);
}

static void discord_check_access_cb(struct http_request *req) {
  cadd *ca = req->data;
  if (req->status_code == 200) {
    discord_add_channel(ca);
  } else {
    imcb_error(ca->sinfo->ic, "Failed to get test messages from chat: %s (%d)."
               " Not joining.", ca->name, req->status_code);
  }
  g_free(ca->id);
  g_free(ca->name);
  g_free(ca->topic);
  g_free(ca->last_msg);
  g_free(ca);
}

static void discord_channels_cb(struct http_request *req) {
  server_info *sinfo = req->data;
  struct im_connection *ic = sinfo->ic;

  //discord_dump_http_reply(req);

  if (req->status_code == 200) {
    int i;
    json_value *js = json_parse(req->reply_body, req->body_size);
    if (!js || js->type != json_array) {
      imcb_error(ic, "Failed to parse json reply.");
      imc_logout(ic, TRUE);
      json_value_free(js);
      return;
    }

    for (i = 0; i < js->u.array.length; i++) {
      if (js->u.array.values[i]->type == json_object) {
        json_value *cinfo = js->u.array.values[i];
        if (g_strcmp0(json_o_str(cinfo, "type"), "text") == 0) {
          GString *api_path = g_string_new("");
          cadd *ca = g_new0(cadd, 1);
          ca->sinfo = sinfo;
          ca->topic = json_o_strdup(cinfo, "topic");
          ca->id = json_o_strdup(cinfo, "id");
          ca->name = json_o_strdup(cinfo, "name");
          ca->last_msg = json_o_strdup(cinfo, "last_message_id");

          g_string_printf(api_path, "channels/%s/messages?limit=1",
                          ca->id);
          discord_http_get(ic, api_path->str, discord_check_access_cb, ca);
          g_string_free(api_path, TRUE);
        }
      }
    }
    json_value_free(js);

    sinfo->state = SERVER_CONNECTED;

    try_start_loop(ic);
  } else {
    imcb_error(ic, "Failed to get channel info.");
    imc_logout(ic, TRUE);
  }
}

static void discord_pchans_cb(struct http_request *req) {
  struct im_connection *ic = req->data;
  discord_data *dd = ic->proto_data;

  if (req->status_code == 200) {
    int i;
    json_value *js = json_parse(req->reply_body, req->body_size);
    if (!js || js->type != json_array) {
      imcb_error(ic, "Failed to parse json reply.");
      imc_logout(ic, TRUE);
      json_value_free(js);
      return;
    }

    for (i = 0; i < js->u.array.length; i++) {
      if (js->u.array.values[i]->type == json_object) {
        json_value *cinfo = js->u.array.values[i];
        char *lmsg = (char *)json_o_str(cinfo, "last_message_id");

        channel_info *ci = g_new0(channel_info, 1);
        ci->is_private = TRUE;
        if (lmsg != NULL) {
          ci->last_msg = g_ascii_strtoull(lmsg, NULL, 10);
        }
        ci->to.user.handle = json_o_strdup(json_o_get(cinfo, "recipient"),
                                           "username");
        ci->id = json_o_strdup(cinfo, "id");
        ci->to.user.ic = ic;

        dd->channels = g_slist_prepend(dd->channels, ci);
      }
    }
    json_value_free(js);
  } else {
    imcb_error(ic, "Failed to get private channel info.");
    imc_logout(ic, TRUE);
  }
}

static void discord_users_cb(struct http_request *req) {
  server_info *sinfo = req->data;
  struct im_connection *ic = sinfo->ic;

  //discord_dump_http_reply(req);

  if (req->status_code == 200) {
    int i;
    json_value *js = json_parse(req->reply_body, req->body_size);
    if (!js || js->type != json_array) {
      imcb_error(ic, "Failed to parse json reply.");
      imc_logout(ic, TRUE);
      json_value_free(js);
      return;
    }

    for (i = 0; i < js->u.array.length; i++) {
      if (js->u.array.values[i]->type == json_object) {
        json_value *uinfo = json_o_get(js->u.array.values[i], "user");
        const char *name = json_o_str(uinfo, "username");

        if (name && !bee_user_by_handle(ic->bee, ic, name)) {
          user_info *ui = g_new0(user_info, 1);

          imcb_add_buddy(ic, name, NULL);

          ui->user = bee_user_by_handle(ic->bee, ic, name);
          ui->id = json_o_strdup(uinfo, "id");

          sinfo->users = g_slist_prepend(sinfo->users, ui);
        }

      }
    }

    json_value_free(js);

    GString *api_path = g_string_new("");
    g_string_printf(api_path, "guilds/%s/channels", sinfo->id);
    discord_http_get(ic, api_path->str, discord_channels_cb, sinfo);
    g_string_free(api_path, TRUE);
  } else {
    imcb_error(ic, "Failed to get user list.");
    imc_logout(ic, TRUE);
  }
}

static void discord_servers_cb(struct http_request *req) {
  struct im_connection *ic = req->data;

  //discord_dump_http_reply(req);

  if (req->status_code == 200) {
    int i;
    json_value *js = json_parse(req->reply_body, req->body_size);
    if (!js || js->type != json_array) {
      imcb_error(ic, "Failed to parse json reply.");
      imc_logout(ic, TRUE);
      json_value_free(js);
      return;
    }

    for (i = 0; i < js->u.array.length; i++) {
      if (js->u.array.values[i]->type == json_object) {
        discord_data *dd = ic->proto_data;
        server_info *sinfo = g_new0(server_info, 1);
        GString *api_path = g_string_new("");
        json_value *ginfo = js->u.array.values[i];

        sinfo->name = json_o_strdup(ginfo, "name");
        sinfo->id = json_o_strdup(ginfo, "id");
        sinfo->ic = ic;
        sinfo->state = SERVER_CONNECTING;

        g_string_printf(api_path, "guilds/%s/members", json_o_str(ginfo, "id"));
        discord_http_get(ic, api_path->str, discord_users_cb, sinfo);

        dd->servers = g_slist_prepend(dd->servers, sinfo);
        g_string_free(api_path, TRUE);
      }
    }
    json_value_free(js);
  } else {
    imcb_error(ic, "Failed to get server info.");
    imc_logout(ic, TRUE);
  }
}

static void discord_me_cb(struct http_request *req) {
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
    GString *api_path = g_string_new("");

    dd->id = json_o_strdup(js, "id");
    dd->uname = json_o_strdup(js, "username");

    g_string_printf(api_path, "users/%s/guilds", dd->id);
    discord_http_get(ic, api_path->str, discord_servers_cb, ic);

    g_string_free(api_path, TRUE);
    json_value_free(js);
  } else {
    imcb_error(ic, "Failed to get info about self.");
    imc_logout(ic, TRUE);
  }
}

static void discord_login_cb(struct http_request *req) {
  struct im_connection *ic = req->data;

  //discord_dump_http_reply(req);

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

    discord_http_get(ic, "users/@me", discord_me_cb, ic);
    discord_http_get(ic, "users/@me/channels", discord_pchans_cb, ic);
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
      imc_logout(ic, FALSE);
    }
  }
  json_value_free(js);
}

static void discord_login(account_t *acc) {
  struct im_connection *ic = imcb_new(acc);
  GString *request = g_string_new("");
  GString *jlogin = g_string_new("");

  ic->proto_data = g_new0(discord_data, 1);
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
  GSList *l;

  for (l = dd->channels; l; l = l->next) {
    channel_info *cinfo = l->data;
    if (cinfo->is_private && g_strcmp0(cinfo->to.user.handle, to) == 0) {
      discord_send_msg(ic, cinfo->id, msg);
    }
  }

  return 0;
}

static void discord_init(account_t *acc) {
  set_t *s;

  s = set_add(&acc->set, "host", DISCORD_HOST, NULL, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  s = set_add(&acc->set, "fetch_interval", "5", set_eval_int, acc);
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

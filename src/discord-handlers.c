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
#include <bitlbee/json_util.h>

#include "discord-util.h"
#include "discord-handlers.h"
#include "discord-http.h"
#include "discord-websockets.h"

static void discord_handle_voice_state(struct im_connection *ic,
                                       json_value *vsinfo,
                                       const char *server_id)
{
  discord_data *dd = ic->proto_data;
  server_info *sinfo = get_server_by_id(dd, server_id);

  if (sinfo == NULL) {
    return;
  }

  user_info *uinfo = get_user(dd, json_o_str(vsinfo, "user_id"), server_id,
                              SEARCH_ID);

  if (uinfo == NULL || g_strcmp0(uinfo->id, dd->id) == 0) {
    return;
  }

  const char *channel_id = json_o_str(vsinfo, "channel_id");

  if (channel_id == NULL) {
    uinfo->voice_channel = NULL;
    if (set_getbool(&ic->acc->set, "voice_status_notify") == TRUE) {
      imcb_log(ic, "User %s is no longer in any voice channel.", uinfo->name);
    }
    return;
  }

  channel_info *cinfo = get_channel_by_id(dd, channel_id, server_id);
  if (cinfo == NULL || cinfo->type != CHANNEL_VOICE ||
      cinfo == uinfo->voice_channel) {
    return;
  }

  uinfo->voice_channel = cinfo;
  if (set_getbool(&ic->acc->set, "voice_status_notify") == TRUE) {
    imcb_log(ic, "User %s switched to voice channel '%s'.", uinfo->name,
             cinfo->to.handle.name);
  }
}

static void discord_handle_presence(struct im_connection *ic,
                                    json_value *pinfo, const char *server_id)
{
  discord_data *dd = ic->proto_data;
  server_info *sinfo = get_server_by_id(dd, server_id);

  if (sinfo == NULL) {
    return;
  }

  user_info *uinfo = get_user(dd, json_o_str(json_o_get(pinfo, "user"), "id"),
                              server_id, SEARCH_ID);

  if (uinfo == NULL) {
    return;
  }

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

    if (cinfo->type == CHANNEL_TEXT) {
      if (flags) {
        imcb_chat_add_buddy(cinfo->to.channel.gc, uinfo->user->handle);
      } else {
        imcb_chat_remove_buddy(cinfo->to.channel.gc, uinfo->user->handle,
                               NULL);
      }
    }
  }

  imcb_buddy_status(ic, uinfo->name, flags, NULL, NULL);
}

static void discord_handle_channel(struct im_connection *ic, json_value *cinfo,
                                   const char *server_id,
                                   handler_action action)
{
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
      char *title;

      title = g_strdup_printf("%s/%s", sinfo->name, name);
      struct groupchat *gc = imcb_chat_new(ic, title);
      imcb_chat_name_hint(gc, name);
      if (topic != NULL) {
        imcb_chat_topic(gc, "root", (char*)topic, 0);
      }
      g_free(title);

      for (GSList *ul = sinfo->users; ul; ul = g_slist_next(ul)) {
        user_info *uinfo = ul->data;
        if (uinfo->user->flags & BEE_USER_ONLINE) {
          imcb_chat_add_buddy(gc, uinfo->user->handle);
        }
      }

      imcb_chat_add_buddy(gc, dd->uname);

      channel_info *cinfo = g_new0(channel_info, 1);
      cinfo->type = CHANNEL_TEXT;
      cinfo->to.channel.gc = gc;
      cinfo->to.channel.sinfo = sinfo;
      cinfo->id = g_strdup(id);
      if (lmid != NULL) {
        cinfo->last_msg = g_ascii_strtoull(lmid, NULL, 10);
      }

      gc->data = cinfo;

      sinfo->channels = g_slist_prepend(sinfo->channels, cinfo);
    } else if (g_strcmp0(type, "voice") == 0) {
      channel_info *cinfo = g_new0(channel_info, 1);
      cinfo->type = CHANNEL_VOICE;
      cinfo->last_msg = 0;
      cinfo->to.handle.name = g_strdup(name);
      cinfo->id = g_strdup(id);
      cinfo->to.handle.ic = ic;

      sinfo->channels = g_slist_prepend(sinfo->channels, cinfo);
    }
  } else {
    channel_info *cdata = get_channel_by_id(dd, id, server_id);
    if (cdata == NULL) {
      return;
    }

    if (action == ACTION_DELETE) {
      GSList *clist;
      if (cdata->type == CHANNEL_PRIVATE) {
        clist = dd->pchannels;
      } else {
        clist = sinfo->channels;
      }

      clist = g_slist_remove(clist, cdata);
      free_channel_info(cdata);
    } else if (action == ACTION_UPDATE) {
      if (cdata->type == CHANNEL_TEXT) {
        if (g_strcmp0(topic, cdata->to.channel.gc->topic) != 0) {
          imcb_chat_topic(cdata->to.channel.gc, "root", (char*)topic, 0);
        }
      }
    }
  }
}

static void discord_handle_user(struct im_connection *ic, json_value *uinfo,
                                const char *server_id,
                                handler_action action)
{
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
    user_info *udata = get_user(dd, id, server_id, SEARCH_ID);

    if (udata == NULL) {
      return;
    }
    imcb_remove_buddy(ic, name, NULL);
    sinfo->users = g_slist_remove(sinfo->users, udata);
    free_user_info(udata);
  }
  // XXX: Should warn about unhandled action _UPDATE if we switch to some
  // centralized handling solution.
}

static void discord_handle_server(struct im_connection *ic, json_value *sinfo,
                                  handler_action action)
{
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
        discord_handle_channel(ic, cinfo, sdata->id, ACTION_CREATE);
      }
    }

    json_value *members = json_o_get(sinfo, "members");
    if (members != NULL && members->type == json_array) {
      for (int midx = 0; midx < members->u.array.length; midx++) {
        json_value *uinfo = json_o_get(members->u.array.values[midx],
                                       "user");
        discord_handle_user(ic, uinfo, sdata->id, ACTION_CREATE);
      }
    }

    json_value *presences = json_o_get(sinfo, "presences");
    if (presences != NULL && presences->type == json_array) {
      for (int pidx = 0; pidx < presences->u.array.length; pidx++) {
        json_value *pinfo = presences->u.array.values[pidx];
        discord_handle_presence(ic, pinfo, sdata->id);
      }
    }

    json_value *vstates = json_o_get(sinfo, "voice_states");
    if (vstates != NULL && vstates->type == json_array) {
      for (int vidx = 0; vidx < vstates->u.array.length; vidx++) {
        json_value *vsinfo = vstates->u.array.values[vidx];
        discord_handle_voice_state(ic, vsinfo, sdata->id);
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

static void discord_post_message(channel_info *cinfo, const gchar *author,
                                 gchar *msg)
{
  if (cinfo->type == CHANNEL_PRIVATE) {
    imcb_buddy_msg(cinfo->to.handle.ic, author, msg, 0, 0);
  } else if (cinfo->type == CHANNEL_TEXT) {
    imcb_chat_msg(cinfo->to.channel.gc, author, msg, 0, 0);
  }
}

static void discord_prepare_message(struct im_connection *ic,
                                    json_value *minfo,
                                    channel_info *cinfo, gboolean is_edit)
{
  gchar *msg = json_o_strdup(minfo, "content");

  if (is_edit == TRUE) {
    gchar *epx = set_getstr(&ic->acc->set, "edit_prefix");
    gchar *newmsg = g_strconcat(epx, msg, NULL);
    g_free(msg);
    msg = newmsg;
  }

  if (cinfo->type == CHANNEL_PRIVATE) {
    if (!g_strcmp0(json_o_str(json_o_get(minfo, "author"), "username"),
                   cinfo->to.handle.name)) {

      discord_post_message(cinfo, cinfo->to.handle.name, msg);
    }
  } else if (cinfo->type == CHANNEL_TEXT) {
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

    discord_post_message(cinfo, json_o_str(json_o_get(minfo, "author"),
                                           "username"), msg);
  }
  g_free(msg);
}

void discord_handle_message(struct im_connection *ic, json_value *minfo,
                            handler_action action)
{
  discord_data *dd = ic->proto_data;

  if (minfo == NULL || minfo->type != json_object) {
    return;
  }

  channel_info *cinfo = get_channel_by_id(dd, json_o_str(minfo, "channel_id"),
                                          NULL);
  if (cinfo == NULL) {
    return;
  }

  if (action == ACTION_CREATE) {
    guint64 msgid = g_ascii_strtoull(json_o_str(minfo, "id"), NULL, 10);
    if (msgid > cinfo->last_msg) {
      discord_prepare_message(ic, minfo, cinfo, FALSE);
      if (g_strcmp0(json_o_str(json_o_get(minfo, "author"), "id"), dd->id)) {
        discord_http_send_ack(ic, cinfo->id, json_o_str(minfo, "id"));
      }
      cinfo->last_msg = msgid;
    }
  } else if (action == ACTION_UPDATE) {
    if (json_o_str(json_o_get(minfo, "author"), "username") != NULL) {
      discord_prepare_message(ic, minfo, cinfo, TRUE);
    } else {
      json_value *embeds = json_o_get(minfo, "embeds");
      if (embeds != NULL && embeds->type == json_array) {
        for (int eidx = 0; eidx < embeds->u.array.length; eidx++) {
          gchar *msg = NULL;
          const char *author = NULL;

          if (cinfo->type == CHANNEL_PRIVATE) {
            author = cinfo->to.handle.name;
          } else if (cinfo->type == CHANNEL_TEXT) {
            author = set_getstr(&ic->acc->set, "urlinfo_handle");
          }

          const char *title = json_o_str(embeds->u.array.values[eidx], "title");
          if (title != NULL) {
            msg = g_strconcat("title: ", title, NULL);
            discord_post_message(cinfo, author, msg);
            g_free(msg);
          }

          const char *description = json_o_str(embeds->u.array.values[eidx],
                                               "description");
          if (description != NULL) {
            msg = g_strconcat("description: ", description, NULL);
            discord_post_message(cinfo, author, msg);
            g_free(msg);
          }
        }
      }
    }
  }
}

void discord_parse_message(struct im_connection *ic)
{
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
      dd->keepalive_interval = hbeat->u.integer;
      if (dd->keepalive_interval == 0) {
        dd->keepalive_interval = DEFAULT_KEEPALIVE_INTERVAL;
      }
    }
    dd->keepalive_loop_id = b_timeout_add(dd->keepalive_interval,
                                          discord_ws_keepalive_loop, ic);

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
          discord_handle_server(ic, ginfo, ACTION_CREATE);
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
          ci->type = CHANNEL_PRIVATE;
          if (lmsg != NULL) {
            ci->last_msg = g_ascii_strtoull(lmsg, NULL, 10);
          }
          ci->to.handle.name = json_o_strdup(json_o_get(pcinfo, "recipient"),
                                             "username");
          ci->id = json_o_strdup(pcinfo, "id");
          ci->to.handle.ic = ic;

          dd->pchannels = g_slist_prepend(dd->pchannels, ci);
        }
      }
    }

    if (set_getint(&ic->acc->set, "max_backlog") > 0) {
      json_value *rs = json_o_get(data, "read_state");
      if (rs != NULL && rs->type == json_array) {
        for (int rsidx = 0; rsidx < rs->u.array.length; rsidx++) {
          if (rs->u.array.values[rsidx]->type == json_object) {
            json_value *rsinfo = rs->u.array.values[rsidx];

            const char *channel_id = json_o_str(rsinfo, "id");
            const char *lmsg = json_o_str(rsinfo, "last_message_id");
            guint64 lm = g_ascii_strtoull(lmsg, NULL, 10);
            channel_info *cinfo = get_channel_by_id(dd, channel_id, NULL);
            if (cinfo->last_msg > lm) {
              char *rlmsg = g_strdup_printf("%lu", cinfo->last_msg);
              cinfo->last_msg = lm;
              discord_http_get_backlog(ic, channel_id);
              discord_http_send_ack(ic, cinfo->id, rlmsg);
              g_free(rlmsg);
            }
          }
        }
      }
    }

    imcb_connected(ic);
  } else if (g_strcmp0(event, "VOICE_STATE_UPDATE") == 0) {
    json_value *vsinfo = json_o_get(js, "d");
    discord_handle_voice_state(ic, vsinfo, json_o_str(vsinfo, "guild_id"));
  } else if (g_strcmp0(event, "PRESENCE_UPDATE") == 0) {
    json_value *pinfo = json_o_get(js, "d");
    discord_handle_presence(ic, pinfo, json_o_str(pinfo, "guild_id"));
  } else if (g_strcmp0(event, "CHANNEL_CREATE") == 0) {
    json_value *cinfo = json_o_get(js, "d");
    discord_handle_channel(ic, cinfo, json_o_str(cinfo, "guild_id"),
                           ACTION_CREATE);
  } else if (g_strcmp0(event, "CHANNEL_DELETE") == 0) {
    json_value *cinfo = json_o_get(js, "d");
    discord_handle_channel(ic, cinfo, json_o_str(cinfo, "guild_id"),
                           ACTION_DELETE);
  } else if (g_strcmp0(event, "CHANNEL_UPDATE") == 0) {
    json_value *cinfo = json_o_get(js, "d");
    discord_handle_channel(ic, cinfo, json_o_str(cinfo, "guild_id"),
                           ACTION_UPDATE);
  } else if (g_strcmp0(event, "GUILD_MEMBER_ADD") == 0) {
    json_value *data = json_o_get(js, "d");
    discord_handle_user(ic, json_o_get(data, "user"),
                        json_o_str(data, "guild_id"), ACTION_CREATE);
  } else if (g_strcmp0(event, "GUILD_MEMBER_REMOVE") == 0) {
    json_value *data = json_o_get(js, "d");
    discord_handle_user(ic, json_o_get(data, "user"),
                        json_o_str(data, "guild_id"), ACTION_DELETE);
  } else if (g_strcmp0(event, "GUILD_CREATE") == 0) {
    json_value *sinfo = json_o_get(js, "d");
    discord_handle_server(ic, sinfo, ACTION_CREATE);
  } else if (g_strcmp0(event, "GUILD_DELETE") == 0) {
    json_value *sinfo = json_o_get(js, "d");
    discord_handle_server(ic, sinfo, ACTION_DELETE);
  } else if (g_strcmp0(event, "MESSAGE_CREATE") == 0) {
    json_value *minfo = json_o_get(js, "d");
    discord_handle_message(ic, minfo, ACTION_CREATE);
  } else if (g_strcmp0(event, "MESSAGE_UPDATE") == 0) {
    json_value *minfo = json_o_get(js, "d");
    discord_handle_message(ic, minfo, ACTION_UPDATE);
  } else if (g_strcmp0(event, "TYPING_START") == 0) {
    // Ignoring those for now
  } else if (g_strcmp0(event, "MESSAGE_ACK") == 0) {
    // Ignoring those for now
  } else {
    g_print("%s: unhandled event: %s\n", __func__, event);
    g_print("%s\n", dd->ws_buf->str);
  }

exit:
  json_value_free(js);
  return;
}

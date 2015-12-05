#include <bitlbee/json.h>
#include <bitlbee/json_util.h>

#include "discord-util.h"
#include "discord-handlers.h"
#include "discord-websockets.h"

static void discord_handle_presence(struct im_connection *ic,
                                    json_value *pinfo, const char *server_id)
{
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
      cinfo->is_private = FALSE;
      cinfo->to.channel.gc = gc;
      cinfo->to.channel.sinfo = sinfo;
      cinfo->id = g_strdup(id);
      if (lmid != NULL) {
        cinfo->last_msg = g_ascii_strtoull(lmid, NULL, 10);
      }

      gc->data = cinfo;

      sinfo->channels = g_slist_prepend(sinfo->channels, cinfo);
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

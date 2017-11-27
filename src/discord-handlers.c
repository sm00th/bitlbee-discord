/*
 * Copyright 2015-2016 Artem Savkov <artem.savkov@gmail.com>
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

#include <config.h>
#include <json_util.h>

#include "discord-util.h"
#include "discord-handlers.h"
#include "discord-http.h"
#include "discord-websockets.h"

#define GLOBAL_SERVER_ID "0"

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

  channel_info *cinfo = get_channel(dd, channel_id, server_id, SEARCH_ID);
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

  if (uinfo->user->ic != ic ||
      g_strcmp0(uinfo->user->handle, dd->uname) == 0) {
    return;
  }

  if (g_strcmp0(status, "online") == 0) {
    uinfo->flags = BEE_USER_ONLINE;
  } else if (g_strcmp0(status, "idle") == 0 ||
             set_getbool(&ic->acc->set, "never_offline") == TRUE) {
    uinfo->flags = BEE_USER_ONLINE | BEE_USER_AWAY;
  } else {
    uinfo->flags = 0;
  }

  for (GSList *cl = sinfo->channels; cl; cl = g_slist_next(cl)) {
    channel_info *cinfo = cl->data;

    if (cinfo->type == CHANNEL_TEXT) {
      if (cinfo->to.channel.gc != NULL) {
        if (uinfo->flags) {
          imcb_chat_add_buddy(cinfo->to.channel.gc, uinfo->user->handle);
        } else {
          imcb_chat_remove_buddy(cinfo->to.channel.gc, uinfo->user->handle,
                                 NULL);
        }
      }
    }
  }

  bee_user_t *bu = bee_user_by_handle(ic->bee, ic, uinfo->name);
  if (bu) {
    if (set_getbool(&ic->acc->set, "friendship_mode") != TRUE ||
        GPOINTER_TO_INT(bu->data) == TRUE) {
      imcb_buddy_status(ic, uinfo->name, uinfo->flags, NULL, NULL);
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
  char *name = discord_canonize_name(json_o_str(uinfo, "username"));

  if (action == ACTION_CREATE) {
    if (name) {
      guint32 flags = 0;
      user_info *ui = NULL;
      bee_user_t *bu = bee_user_by_handle(ic->bee, ic, name);

      if (bu == NULL) {
        imcb_add_buddy(ic, name, NULL);
        if (set_getbool(&ic->acc->set, "never_offline") == TRUE) {
          flags = BEE_USER_ONLINE | BEE_USER_AWAY;
          if (set_getbool(&ic->acc->set, "friendship_mode") == FALSE) {
            imcb_buddy_status(ic, name, flags, NULL, NULL);
          }
        } else {
          imcb_buddy_status(ic, name, 0, NULL, NULL);
        }
        bu = bee_user_by_handle(ic->bee, ic, name);
      }

      if (bu != NULL) {
        ui = g_new0(user_info, 1);
        ui->user = bu;
        ui->id = g_strdup(id);
        ui->name = g_strdup(name);
        ui->flags = flags;

        sinfo->users = g_slist_prepend(sinfo->users, ui);
      }
    }
  } else if (action == ACTION_DELETE) {
    user_info *udata = get_user(dd, id, server_id, SEARCH_ID);

    if (udata != NULL) {
      sinfo->users = g_slist_remove(sinfo->users, udata);
      free_user_info(udata);

      udata = get_user(dd, name, NULL, SEARCH_NAME);
      if (udata == NULL) {
        imcb_remove_buddy(ic, name, NULL);
      }
    }
  }

  g_free(name);
  // XXX: Should warn about unhandled action _UPDATE if we switch to some
  // centralized handling solution.
}

static void discord_handle_relationship(struct im_connection *ic, json_value *rinfo,
                                        handler_action action)
{
  discord_data *dd = ic->proto_data;
  relationship_type rtype = 0;
  json_value *uinfo = json_o_get(rinfo, "user");
  json_value *tjs = json_o_get(rinfo, "type");
  char *name = discord_canonize_name(json_o_str(uinfo, "username"));
  bee_user_t *bu = bee_user_by_handle(ic->bee, ic, name);

  if (action == ACTION_CREATE) {
    rtype = (tjs && tjs->type == json_integer) ? tjs->u.integer : 0;

    if (rtype == RELATIONSHIP_FRIENDS) {
      if (!bu) {
        discord_handle_user(ic, uinfo, GLOBAL_SERVER_ID, ACTION_CREATE);
        bu = bee_user_by_handle(ic->bee, ic, name);
      }
      if (bu) {
        bu->data = GINT_TO_POINTER(TRUE);
        if (set_getbool(&ic->acc->set, "friendship_mode") == TRUE) {
          user_info *uinfo = get_user(dd, name, NULL, SEARCH_NAME);
          imcb_buddy_status(ic, name, uinfo->flags, NULL, NULL);
        }
      }
    } else if (rtype == RELATIONSHIP_REQUEST_RECEIVED) {
      // call imcb_ask() here
    }

  } else if (action == ACTION_DELETE) {
    if (bu) {
      bu->data = GINT_TO_POINTER(FALSE);
      if (set_getbool(&ic->acc->set, "friendship_mode") == TRUE) {
        imcb_buddy_status(ic, name, 0, NULL, NULL);
      }
    }
  }

  g_free(name);
}

void discord_handle_channel(struct im_connection *ic, json_value *cinfo,
                            const char *server_id, handler_action action)
{
  discord_data *dd = ic->proto_data;
  server_info *sinfo = get_server_by_id(dd, server_id);

  const char *id    = json_o_str(cinfo, "id");
  const char *name  = json_o_str(cinfo, "name");
  const char *lmid  = json_o_str(cinfo, "last_message_id");
  const char *topic = json_o_str(cinfo, "topic");
  json_value *tjs = NULL;
  channel_type ctype = 0;

  tjs = json_o_get(cinfo, "type");
  if (tjs != NULL && tjs->type == json_integer) {
    ctype = tjs->u.integer;
  }

  if (ctype != CHANNEL_PRIVATE && ctype != CHANNEL_GROUP_PRIVATE
      && sinfo == NULL) {
    return;
  }

  if (action == ACTION_CREATE) {
    switch(ctype) {
      case CHANNEL_PRIVATE:
      {
        channel_info *ci = g_new0(channel_info, 1);
        ci->type = ctype;
        if (lmid != NULL) {
          ci->last_msg = g_ascii_strtoull(lmid, NULL, 10);
        }

        json_value *rcplist = json_o_get(cinfo, "recipients");
        if (rcplist != NULL && rcplist->type == json_array) {
          json_value *rcp = rcplist->u.array.values[0];

          ci->to.handle.name = discord_canonize_name(json_o_str(rcp, "username"));
          ci->id = json_o_strdup(cinfo, "id");
          ci->to.handle.ic = ic;

          dd->pchannels = g_slist_prepend(dd->pchannels, ci);
          discord_handle_user(ic, rcp, sinfo ? sinfo->id : GLOBAL_SERVER_ID,
                              ACTION_CREATE);
        } else {
          g_print("Failed to get recepient for private channel.\n");
          free_channel_info(ci);
        }
        break;
      }
      case CHANNEL_TEXT:
      {
        gint plen = set_getint(&ic->acc->set, "server_prefix_len");
        gchar *prefix = NULL;
        gchar *fullname = NULL;

        if (plen == 0) {
          fullname = g_strdup(name);
        } else {
          if (plen < 0) {
            prefix = g_strdup(sinfo->name);
          } else {
            prefix = discord_utf8_strndup(sinfo->name, plen);
          }
          fullname = g_strconcat(prefix, ".", name, NULL);
        }

        bee_chat_info_t *bci = g_new0(bee_chat_info_t, 1);
        while (get_channel(dd, fullname, NULL, SEARCH_FNAME) != NULL) {
          gchar *tmpname = fullname;
          fullname = g_strconcat(tmpname, "_", NULL);
          g_free(tmpname);
        }
        bci->title = g_strdup(fullname);
        if (topic != NULL && strlen(topic) > 0) {
          bci->topic = g_strdup(topic);
        } else {
          bci->topic = g_strdup_printf("%s/%s", sinfo->name, name);
        }

        ic->chatlist = g_slist_prepend(ic->chatlist, bci);

        g_free(prefix);
        g_free(fullname);

        channel_info *ci = g_new0(channel_info, 1);
        ci->type = ctype;
        ci->to.channel.name = g_strdup(name);
        ci->to.channel.bci = bci;
        ci->to.channel.sinfo = sinfo;
        ci->id = g_strdup(id);
        if (lmid != NULL) {
          ci->last_msg = g_ascii_strtoull(lmid, NULL, 10);
        }

        sinfo->channels = g_slist_prepend(sinfo->channels, ci);
        break;
      }
      case CHANNEL_GROUP_PRIVATE:
      {
        gchar *fullname = g_strdup(id);

        bee_chat_info_t *bci = g_new0(bee_chat_info_t, 1);
        while (get_channel(dd, fullname, NULL, SEARCH_FNAME) != NULL) {
          gchar *tmpname = fullname;
          fullname = g_strconcat(tmpname, "_", NULL);
          g_free(tmpname);
        }
        bci->title = g_strdup(fullname);
        if (topic != NULL && strlen(topic) > 0) {
          bci->topic = g_strdup(topic);
        } else {
          bci->topic = g_strdup_printf("Group DM: %s", name);
        }

        ic->chatlist = g_slist_prepend(ic->chatlist, bci);

        g_free(fullname);

        channel_info *ci = g_new0(channel_info, 1);
        ci->type = ctype;
        ci->to.group.name = g_strdup(name);
        ci->to.group.bci = bci;
        ci->to.group.ic = ic;
        ci->id = g_strdup(id);
        if (lmid != NULL) {
          ci->last_msg = g_ascii_strtoull(lmid, NULL, 10);
        }

        json_value *rcplist = json_o_get(cinfo, "recipients");
        if (rcplist != NULL && rcplist->type == json_array) {
          for (int ridx = 0; ridx < rcplist->u.array.length; ridx++) {
            json_value *rcp = rcplist->u.array.values[ridx];

            discord_handle_user(ic, rcp, GLOBAL_SERVER_ID, ACTION_CREATE);

            user_info *ui = get_user(dd, json_o_str(rcp, "id"), GLOBAL_SERVER_ID, SEARCH_ID);

            ci->to.group.users = g_slist_prepend(ci->to.group.users, ui);
          }

          dd->pchannels = g_slist_prepend(dd->pchannels, ci);
        } else {
          g_print("Failed to get recepients for private channel.\n");
          free_channel_info(ci);
        }

        break;
      }
      case CHANNEL_VOICE:
      {
        channel_info *ci = g_new0(channel_info, 1);
        ci->type = CHANNEL_VOICE;
        ci->last_msg = 0;
        ci->to.handle.name = g_strdup(name);
        ci->id = g_strdup(id);
        ci->to.handle.ic = ic;

        sinfo->channels = g_slist_prepend(sinfo->channels, ci);
        break;
      }
    }
  } else {
    channel_info *cdata = get_channel(dd, id, server_id, SEARCH_ID);
    if (cdata == NULL) {
      return;
    }

    if (action == ACTION_DELETE) {
      GSList **clist;
      if (cdata->type == CHANNEL_PRIVATE || cdata->type == CHANNEL_GROUP_PRIVATE) {
        clist = &dd->pchannels;
      } else {
        clist = &sinfo->channels;
      }

      if (cdata->type == CHANNEL_TEXT) {
        ic->chatlist = g_slist_remove(ic->chatlist, cdata->to.channel.bci);
      } else if (cdata->type == CHANNEL_GROUP_PRIVATE) {
        ic->chatlist = g_slist_remove(ic->chatlist, cdata->to.group.bci);
      }

      *clist = g_slist_remove(*clist, cdata);
      free_channel_info(cdata);
    } else if (action == ACTION_UPDATE) {
      if (cdata->type == CHANNEL_TEXT && cdata->to.channel.gc != NULL) {
        if (g_strcmp0(topic, cdata->to.channel.gc->topic) != 0) {
          imcb_chat_topic(cdata->to.channel.gc, "root", (char*)topic, 0);
        }
      } else if (cdata->type == CHANNEL_GROUP_PRIVATE && cdata->to.group.gc != NULL) {
        if (g_strcmp0(topic, cdata->to.group.gc->topic) != 0) {
          imcb_chat_topic(cdata->to.group.gc, "root", (char*)topic, 0);
        }
      }
    }
  }
}

static void discord_add_global_server(struct im_connection *ic) {
  discord_data *dd = ic->proto_data;
  server_info *sinfo = g_new0(server_info, 1);

  sinfo->name = g_strdup("_global");
  sinfo->id = g_strdup(GLOBAL_SERVER_ID);
  sinfo->ic = ic;
  dd->servers = g_slist_prepend(dd->servers, sinfo);
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

    discord_ws_sync_server(dd, sdata->id);
    dd->pending_sync++;
  } else {
    server_info *sdata = get_server_by_id(dd, id);
    if (sdata == NULL) {
      return;
    }

    if (action == ACTION_DELETE) {
      dd->servers = g_slist_remove(dd->servers, sdata);
      for (GSList *ul = sdata->users; ul; ul = g_slist_next(ul)) {
        user_info *uinfo = ul->data;
        user_info *udata = get_user(dd, uinfo->name, NULL, SEARCH_NAME);
        if (udata == NULL) {
          imcb_remove_buddy(ic, uinfo->name, NULL);
        }
      }
      free_server_info(sdata);
    }
  }
}

static gboolean discord_post_message(channel_info *cinfo, const gchar *author,
                                 gchar *msg, gboolean is_self)
{
  int flags = 0;

  if (strlen(msg) == 0) {
    return FALSE;
  }

  if (is_self) {
    flags |= OPT_SELFMESSAGE;
  }

  if (cinfo->type == CHANNEL_PRIVATE) {
    imcb_buddy_msg(cinfo->to.handle.ic, author, msg, flags, 0);
    return TRUE;
  } else if (cinfo->type == CHANNEL_GROUP_PRIVATE && cinfo->to.group.gc != NULL) {
    imcb_chat_msg(cinfo->to.group.gc, author, msg, flags, 0);
    return TRUE;
  } else if (cinfo->type == CHANNEL_TEXT && cinfo->to.channel.gc != NULL) {
    imcb_chat_msg(cinfo->to.channel.gc, author, msg, flags, 0);
    return TRUE;
  }
  return FALSE;
}

static gboolean discord_replace_channel(const GMatchInfo *match,
                                        GString *result,
                                        gpointer user_data)
{
  discord_data *dd = (discord_data *)user_data;
  gchar *mstring = g_match_info_fetch(match, 0);
  gchar *chid = g_match_info_fetch(match, 1);

  channel_info *cinfo = get_channel(dd, chid, NULL, SEARCH_ID);
  if (cinfo != NULL && cinfo->type == CHANNEL_TEXT) {
    gchar *r = g_strdup_printf("#%s", cinfo->to.channel.name);
    result = g_string_append(result, r);
    g_free(r);
  } else if (cinfo != NULL && cinfo->type == CHANNEL_GROUP_PRIVATE) {
    gchar *r = g_strdup_printf("#%s", cinfo->to.group.name);
    result = g_string_append(result, r);
    g_free(r);
  } else {
    result = g_string_append(result, mstring);
  }
  g_free(chid);
  g_free(mstring);

  return FALSE;
}

static gboolean discord_prepare_message(struct im_connection *ic,
                                    json_value *minfo,
                                    channel_info *cinfo, gboolean is_edit)
{
  discord_data *dd = ic->proto_data;
  gboolean posted = FALSE;
  gchar *msg = json_o_strdup(minfo, "content");
  json_value *jpinned = json_o_get(minfo, "pinned");
  gboolean pinned = (jpinned != NULL && jpinned->type == json_boolean) ?
                       jpinned->u.boolean : FALSE;

  gchar *author = discord_canonize_name(json_o_str(json_o_get(minfo,
                                        "author"), "username"));
  const char *nonce = json_o_str(minfo, "nonce");
  gboolean is_self = discord_is_self(ic, author);

  // Don't echo self messages that we sent in this session
  if (is_self && nonce != NULL && g_strcmp0(nonce, dd->nonce) == 0) {
    g_free(author);
    g_free(msg);
    return FALSE;
  }

  if (pinned == TRUE) {
    gchar *newmsg = g_strconcat("PINNED: ", msg, NULL);
    g_free(msg);
    msg = newmsg;

    if (!g_slist_find_custom(cinfo->pinned, json_o_str(minfo, "id"),
          (GCompareFunc)g_strcmp0)) {
      cinfo->pinned = g_slist_prepend(cinfo->pinned,
                                      json_o_strdup(minfo, "id"));
    }
  } else if (is_edit == TRUE) {
    GSList *link = g_slist_find_custom(cinfo->pinned, json_o_str(minfo, "id"),
                                      (GCompareFunc)g_strcmp0);
    if (link) {
      g_free(link->data);
      cinfo->pinned = g_slist_delete_link(cinfo->pinned, link);
      gchar *newmsg = g_strconcat("UNPINNED: ", msg, NULL);
      g_free(msg);
      msg = newmsg;
    } else {
      gchar *epx = set_getstr(&ic->acc->set, "edit_prefix");
      gchar *newmsg = g_strconcat(epx, msg, NULL);
      g_free(msg);
      msg = newmsg;
    }
  }

  if (set_getbool(&ic->acc->set, "incoming_me_translation") == TRUE &&
      g_regex_match_simple("^[\\*_].*[\\*_]$", msg, 0, 0) == TRUE) {
    GString *tstr = g_string_new(msg);
    tstr = g_string_erase(tstr, 0, 1);
    tstr = g_string_truncate(tstr, tstr->len - 1);
    tstr = g_string_prepend(tstr, "/me ");

    g_free(msg);
    msg = tstr->str;
    g_string_free(tstr, FALSE);
  }

  if (cinfo->type == CHANNEL_PRIVATE) {
    posted = discord_post_message(cinfo, cinfo->to.handle.name, msg, is_self);
  } else if (cinfo->type == CHANNEL_TEXT || cinfo->type == CHANNEL_GROUP_PRIVATE) {
    json_value *mentions = json_o_get(minfo, "mentions");
    if (mentions != NULL && mentions->type == json_array) {
      for (int midx = 0; midx < mentions->u.array.length; midx++) {
        json_value *uinfo = mentions->u.array.values[midx];
        gchar *uname = discord_canonize_name(json_o_str(uinfo, "username"));
        gchar *newmsg = NULL;
        gchar *idstr = g_strdup_printf("<@!?%s>", json_o_str(uinfo, "id"));
        gchar *unstr = g_strdup_printf("@%s", uname);
        GRegex *regex = g_regex_new(idstr, 0, 0, NULL);
        newmsg = g_regex_replace_literal(regex, msg, -1, 0,
                                         unstr, 0, NULL);
        g_free(msg);
        msg = newmsg;
        g_regex_unref(regex);
        g_free(idstr);
        g_free(unstr);
        g_free(uname);
      }
    }

    // Replace custom emoji with code and a URL
    GRegex *emoji_regex = g_regex_new("<(:[^:]+:)(\\d+)>", 0, 0, NULL);
    gchar *emoji_msg = g_regex_replace(emoji_regex, msg, -1, 0, "\\1 https://cdn.discordapp.com/emojis/\\2.png", 0, NULL);
    g_free(msg);
    msg = emoji_msg;
    g_regex_unref(emoji_regex);
    
    GRegex *cregex = g_regex_new("<#(\\d+)>", 0, 0, NULL);
    gchar *fmsg = g_regex_replace_eval(cregex, msg, -1, 0, 0,
                                       discord_replace_channel,
                                       ic->proto_data, NULL);
    g_regex_unref(cregex);

    posted = discord_post_message(cinfo, author, fmsg, is_self);
    g_free(fmsg);
  }

  json_value *attachments = json_o_get(minfo, "attachments");
  if (attachments != NULL && attachments->type == json_array) {
    for (int aidx = 0; aidx < attachments->u.array.length; aidx++) {
      const char *url = json_o_str(attachments->u.array.values[aidx], "url");
      posted = discord_post_message(cinfo, author, (char *)url, is_self);
    }
  }
  g_free(author);
  g_free(msg);
  return posted;
}

void discord_handle_message(struct im_connection *ic, json_value *minfo,
                            handler_action action)
{
  discord_data *dd = ic->proto_data;

  if (minfo == NULL || minfo->type != json_object) {
    return;
  }

  channel_info *cinfo = get_channel(dd, json_o_str(minfo, "channel_id"),
                                    NULL, SEARCH_ID);
  if (cinfo == NULL) {
    return;
  }

  if (action == ACTION_CREATE) {
    guint64 msgid = g_ascii_strtoull(json_o_str(minfo, "id"), NULL, 10);
    json_value *jpinned = json_o_get(minfo, "pinned");
    gboolean pinned = (jpinned != NULL && jpinned->type == json_boolean) ?
                       jpinned->u.boolean : FALSE;

    if ((msgid > cinfo->last_read) || (pinned &&
          !g_slist_find_custom(cinfo->pinned, json_o_str(minfo, "id"),
          (GCompareFunc)g_strcmp0))) {
      gboolean posted = discord_prepare_message(ic, minfo, cinfo, FALSE);
      if (posted) {
        if (g_strcmp0(json_o_str(json_o_get(minfo, "author"), "id"), dd->id)) {
          discord_http_send_ack(ic, cinfo->id, json_o_str(minfo, "id"));
        }
        if (msgid > cinfo->last_read) {
          cinfo->last_read = msgid;
        }
        if (msgid > cinfo->last_msg) {
          cinfo->last_msg = msgid;
        }
      }
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
          } else if (cinfo->type == CHANNEL_TEXT || cinfo->type == CHANNEL_GROUP_PRIVATE) {
            author = set_getstr(&ic->acc->set, "urlinfo_handle");
          }

          const char *title = json_o_str(embeds->u.array.values[eidx], "title");
          if (title != NULL) {
            msg = g_strconcat("title: ", title, NULL);
            discord_post_message(cinfo, author, msg, FALSE);
            g_free(msg);
          }

          const char *description = json_o_str(embeds->u.array.values[eidx],
                                               "description");
          if (description != NULL) {
            msg = g_strconcat("description: ", description, NULL);
            discord_post_message(cinfo, author, msg, FALSE);
            g_free(msg);
          }
        }
      }
    }
  }
}

void discord_parse_message(struct im_connection *ic, gchar *buf, guint64 size)
{
  discord_data *dd = ic->proto_data;
  json_value *js = json_parse((gchar*)buf, size);

  discord_debug("<<< (%s) %s %"G_GUINT64_FORMAT"\n%s\n", dd->uname, __func__, size, buf);

  if (!js || js->type != json_object) {
    imcb_error(ic, "Failed to parse json reply.");
    imc_logout(ic, TRUE);
    goto exit;
  }

  const char *event = json_o_str(js, "t");
  gint op = 0;
  json_value *jsop = json_o_get(js, "op");
  if (jsop != NULL && jsop->type == json_integer) {
    op = jsop->u.integer;
  }
  json_value *seq = json_o_get(js, "s");
  if (seq != NULL && seq->type == json_integer) {
    dd->seq = seq->u.integer;
  }

  if (op == OPCODE_HELLO) {
    json_value *data = json_o_get(js, "d");
    json_value *hbeat = json_o_get(data, "heartbeat_interval");
    if (hbeat != NULL && hbeat->type == json_integer) {
      dd->keepalive_interval = hbeat->u.integer;
      if (dd->keepalive_interval == 0) {
        dd->keepalive_interval = DEFAULT_KEEPALIVE_INTERVAL;
      }
    }

    dd->keepalive_loop_id = b_timeout_add(dd->keepalive_interval,
                                          discord_ws_keepalive_loop, ic);
  } else if (op == OPCODE_HEARTBEAT_ACK) {
    // heartbeat ack
  } else if (g_strcmp0(event, "READY") == 0) {
    dd->state = WS_ALMOST_READY;
    json_value *data = json_o_get(js, "d");

    if (data == NULL || data->type != json_object) {
      goto exit;
    }

    json_value *user = json_o_get(data, "user");
    if (user != NULL && user->type == json_object) {
      dd->id = json_o_strdup(user, "id");
      dd->uname = discord_canonize_name(json_o_str(user, "username"));
    }

    discord_add_global_server(ic);
    json_value *guilds = json_o_get(data, "guilds");
    if (guilds != NULL && guilds->type == json_array &&
        guilds->u.array.length > 0) {
      for (int gidx = 0; gidx < guilds->u.array.length; gidx++) {
        if (guilds->u.array.values[gidx]->type == json_object) {
          json_value *ginfo = guilds->u.array.values[gidx];
          discord_handle_server(ic, ginfo, ACTION_CREATE);
        }
      }
    } else {
      dd->state = WS_READY;
      imcb_connected(ic);
    }

    json_value *pcs = json_o_get(data, "private_channels");
    if (pcs != NULL && pcs->type == json_array) {
      for (int pcidx = 0; pcidx < pcs->u.array.length; pcidx++) {
        if (pcs->u.array.values[pcidx]->type == json_object) {
          json_value *pcinfo = pcs->u.array.values[pcidx];
          discord_handle_channel(ic, pcinfo, NULL, ACTION_CREATE);
        }
      }
    }

    json_value *rels = json_o_get(data, "relationships");
    if (rels != NULL && rels->type == json_array) {
      for (int relidx = 0; relidx < rels->u.array.length; relidx++) {
        if (rels->u.array.values[relidx]->type == json_object) {
          json_value *rinfo = rels->u.array.values[relidx];
          discord_handle_relationship(ic, rinfo, ACTION_CREATE);
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
            guint64 lm = 0;
            if (lmsg != NULL) {
              lm = g_ascii_strtoull(lmsg, NULL, 10);
            }
            channel_info *cinfo = get_channel(dd, channel_id, NULL, SEARCH_ID);
            if (cinfo != NULL) {
              cinfo->last_read = lm;
            }
          }
        }
      }
    }

  } else if (g_strcmp0(event, "GUILD_SYNC") == 0) {
    json_value *data = json_o_get(js, "d");
    const char *id   = json_o_str(data, "id");

    json_value *members = json_o_get(data, "members");
    if (members != NULL && members->type == json_array) {
      for (int midx = 0; midx < members->u.array.length; midx++) {
        json_value *uinfo = json_o_get(members->u.array.values[midx],
                                       "user");
        discord_handle_user(ic, uinfo, id, ACTION_CREATE);
      }
    }

    json_value *presences = json_o_get(data, "presences");
    if (presences != NULL && presences->type == json_array) {
      for (int pidx = 0; pidx < presences->u.array.length; pidx++) {
        json_value *pinfo = presences->u.array.values[pidx];
        discord_handle_presence(ic, pinfo, id);
      }
    }

    dd->pending_sync--;
    if (dd->pending_sync < 1 && dd->state == WS_ALMOST_READY) {
      dd->state = WS_READY;
      imcb_connected(ic);
    }
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
  } else if (g_strcmp0(event, "RELATIONSHIP_ADD") == 0) {
    json_value *rinfo = json_o_get(js, "d");
    discord_handle_relationship(ic, rinfo, ACTION_CREATE);
  } else if (g_strcmp0(event, "RELATIONSHIP_REMOVE") == 0) {
    json_value *rinfo = json_o_get(js, "d");
    discord_handle_relationship(ic, rinfo, ACTION_DELETE);
  } else if (g_strcmp0(event, "TYPING_START") == 0) {
    // Ignoring those for now
  } else if (g_strcmp0(event, "MESSAGE_ACK") == 0) {
    // Ignoring those for now
  } else if (g_strcmp0(event, "MESSAGE_DELETE") == 0) {
    // Ignoring those for now
  } else if (g_strcmp0(event, "MESSAGE_REACTION_ADD") == 0) {
    // Ignoring those for now
  } else if (g_strcmp0(event, "MESSAGE_REACTION_REMOVE") == 0) {
    // Ignoring those for now
  } else if (g_strcmp0(event, "GUILD_MEMBER_UPDATE") == 0) {
    // Ignoring those for now
  } else if (g_strcmp0(event, "GUILD_EMOJIS_UPDATE") == 0) {
    // Ignoring those for now
  } else if (g_strcmp0(event, "GUILD_INTEGRATIONS_UPDATE") == 0) {
    // Ignoring those for now
  } else if (g_strcmp0(event, "WEBHOOKS_UPDATE") == 0) {
    // Ignoring those for now
  } else {
    g_print("%s: unhandled event: %s\n", __func__, event);
    g_print("%s\n", buf);
  }

exit:
  json_value_free(js);
  return;
}

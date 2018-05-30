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
#include "config.h"
#include "discord.h"
#include "discord-http.h"
#include "discord-util.h"
#include "discord-websockets.h"
#include "help.h"

#define HELPFILE_NAME "discord-help.txt"

static void discord_help_init()
{
  /* Figure out where our help file is by looking at the global helpfile. */
  gchar *dir = g_path_get_dirname (global.helpfile);
  if (strcmp(dir, ".") == 0) {
    log_message(LOGLVL_WARNING, "Error finding the directory of helpfile %s.", global.helpfile);
    g_free(dir);
    return;
  }
  gchar *df = g_strjoin("/", dir, HELPFILE_NAME, NULL);
  g_free(dir);

  /* Load help from our own help file. */
  help_t *dh;
  help_init(&dh, df);
  if(dh == NULL) {
    log_message(LOGLVL_WARNING, "Error opening helpfile: %s.", df);
    g_free(df);
    return;
  }
  g_free(df);

  /* Link the last entry of global.help with first entry of our help. */
  help_t *h, *l = NULL;
  for (h = global.help; h; h = h->next) {
    l = h;
  }
  if (l) {
    l->next = dh;
  } else {
    /* No global help but ours? */
    global.help = dh;
  }
}

#ifdef BITLBEE_ABI_VERSION_CODE
struct plugin_info *init_plugin_info(void)
{
  static struct plugin_info info = {
    BITLBEE_ABI_VERSION_CODE,
    "bitlbee-discord",
    PACKAGE_VERSION,
    "Bitlbee plugin for discordapp.com",
    "Artem Savkov <artem.savkov@gmail.com>",
    "https://github.com/sm00th/bitlbee-discord"
  };

  return &info;
}
#endif

static void discord_init(account_t *acc)
{
  set_t *s;

  s = set_add(&acc->set, "host", DISCORD_HOST, NULL, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  s = set_add(&acc->set, "voice_status_notify", "off", set_eval_bool, acc);
  s = set_add(&acc->set, "send_acks", "on", set_eval_bool, acc);
  s = set_add(&acc->set, "edit_prefix", "EDIT: ", NULL, acc);
  s = set_add(&acc->set, "urlinfo_handle", "urlinfo", NULL, acc);
  s = set_add(&acc->set, "mention_suffix", ":", NULL, acc);
  s = set_add(&acc->set, "mention_ignorecase", "off", set_eval_bool, acc);
  s = set_add(&acc->set, "incoming_me_translation", "on", set_eval_bool, acc);
  s = set_add(&acc->set, "fetch_pinned", "off", set_eval_bool, acc);

  s = set_add(&acc->set, "auto_join", "off", set_eval_bool, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  s = set_add(&acc->set, "auto_join_exclude", "", NULL, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  s = set_add(&acc->set, "max_backlog", "50", set_eval_int, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  s = set_add(&acc->set, "never_offline", "off", set_eval_bool, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  s = set_add(&acc->set, "server_prefix_len", "3", set_eval_int, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  s = set_add(&acc->set, "token_cache", NULL, NULL, acc);
  s->flags |= SET_HIDDEN | SET_NULL_OK;

  s = set_add(&acc->set, "friendship_mode", "on", set_eval_bool, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  acc->flags |= ACC_FLAG_AWAY_MESSAGE;
  acc->flags |= ACC_FLAG_STATUS_MESSAGE;

  discord_help_init();
}

static void discord_do_login(struct im_connection *ic)
{
  if (set_getstr(&ic->acc->set,"token_cache")) {
    discord_http_get_gateway(ic, set_getstr(&ic->acc->set,"token_cache"));
  } else {
    discord_http_login(ic->acc);
  }
}

static void discord_login(account_t *acc)
{
  struct im_connection *ic = imcb_new(acc);

  discord_data *dd = g_new0(discord_data, 1);
  dd->keepalive_interval = DEFAULT_KEEPALIVE_INTERVAL;
  ic->proto_data = dd;

  guchar nonce_bytes[16];
  random_bytes(nonce_bytes, sizeof(nonce_bytes));
  dd->nonce = g_base64_encode(nonce_bytes, sizeof(nonce_bytes));

  discord_do_login(ic);
}

static void discord_logout(struct im_connection *ic)
{
  discord_data *dd = ic->proto_data;

  discord_ws_cleanup(dd);

  free_discord_data(dd);
  g_slist_free(ic->chatlist);
}

void discord_soft_reconnect(struct im_connection *ic)
{
  discord_data *dd = ic->proto_data;

  imcb_log(ic, "Performing soft-reconnect");
  discord_ws_cleanup(dd);
  dd->reconnecting = TRUE;
  discord_do_login(ic);
}

static void discord_chat_msg(struct groupchat *gc, char *msg, int flags)
{
  channel_info *cinfo = gc->data;

  discord_http_send_msg(gc->ic, cinfo->id, msg);
}

static void discord_chat_list(struct im_connection *ic, const char *server)
{
  imcb_chat_list_finish(ic);
}

static struct groupchat *discord_chat_join(struct im_connection *ic,
                                           const char *room,
                                           const char *nick,
                                           const char *password,
                                           set_t **sets)

{
  return discord_chat_do_join(ic, room, FALSE);
}

struct groupchat *discord_chat_do_join(struct im_connection *ic,
                                       const char *room,
                                       gboolean is_auto_join)
{
  discord_data *dd = ic->proto_data;
  struct groupchat *gc = NULL;
  server_info *sinfo = NULL;
  channel_info *cinfo = get_channel(dd, room, NULL, SEARCH_FNAME);

  if (cinfo != NULL && cinfo->type == CHANNEL_TEXT) {
    sinfo = cinfo->to.channel.sinfo;
    gc = imcb_chat_new(ic, cinfo->to.channel.name);

    if (is_auto_join) {
      imcb_chat_name_hint(gc, room);
    }

    if (cinfo->to.channel.bci->topic != NULL) {
      imcb_chat_topic(gc, "root", cinfo->to.channel.bci->topic, 0);
    }

    for (GSList *ul = sinfo->users; ul; ul = g_slist_next(ul)) {
      user_info *uinfo = ul->data;
      if (uinfo->flags & BEE_USER_ONLINE) {
        imcb_chat_add_buddy(gc, uinfo->user->handle);
      }
    }
    imcb_chat_add_buddy(gc, dd->uname);

    cinfo->to.channel.gc = gc;
  } else if (cinfo != NULL && cinfo->type == CHANNEL_GROUP_PRIVATE) {
    gc = imcb_chat_new(ic, cinfo->to.group.name);

    if (is_auto_join) {
      imcb_chat_name_hint(gc, room);
    }

    for (GSList *ul = cinfo->to.group.users; ul; ul = g_slist_next(ul)) {
      user_info *uinfo = ul->data;
      imcb_chat_add_buddy(gc, uinfo->user->handle);
    }
    imcb_chat_add_buddy(gc, dd->uname);

    cinfo->to.group.gc = gc;
  } else {
    return NULL;
  }
  gc->data = cinfo;

  if (set_getbool(&ic->acc->set, "fetch_pinned")) {
    discord_http_get_pinned(ic, cinfo->id);
  }

  if (set_getint(&ic->acc->set, "max_backlog") > 0 &&
      cinfo->last_msg > cinfo->last_read) {
    discord_http_get_backlog(ic, cinfo->id);
  }

  return gc;
}

static void discord_chat_leave(struct groupchat *gc)
{
  channel_info *cinfo = gc->data;
  imcb_chat_free(cinfo->to.channel.gc);
  cinfo->to.channel.gc = NULL;
}

static int discord_buddy_msg(struct im_connection *ic, char *to, char *msg,
                             int flags)
{
  discord_data *dd = ic->proto_data;

  if (g_strcmp0(to, DISCORD_MFA_HANDLE) == 0) {
    discord_http_mfa_auth(ic, msg);
    return 0;
  }

  for (GSList *cl = dd->pchannels; cl; cl = g_slist_next(cl)) {
    channel_info *cinfo = cl->data;
    if (cinfo->type == CHANNEL_PRIVATE &&
        g_strcmp0(cinfo->to.handle.name, to) == 0) {
      discord_http_send_msg(ic, cinfo->id, msg);
      return 0;
    }
  }

  // If we are here we didn't find an appropriate channel, create it
  discord_http_create_and_send_msg(ic, to, msg);

  return 0;
}

gboolean discord_is_self(struct im_connection *ic, const char *who)
{
  discord_data *dd = ic->proto_data;
  return !g_strcmp0(dd->uname, who);
}

static GList *discord_away_states(struct im_connection *ic)
{
    static GList *m = NULL;

    m = g_list_prepend(m, "invisible");
    m = g_list_prepend(m, "dnd");
    m = g_list_prepend(m, "idle");
    m = g_list_prepend(m, "online");

    return m;
}

static void discord_set_away(struct im_connection *ic, char *state,
                             char *message)
{
  discord_data *dd = ic->proto_data;

  discord_ws_set_status(dd, state, message);
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
    .chat_list = discord_chat_list,
    .chat_join = discord_chat_join,
    .chat_leave = discord_chat_leave,
    .buddy_msg = discord_buddy_msg,
    .handle_cmp = g_strcmp0,
    .handle_is_self = discord_is_self,
    .away_states = discord_away_states,
    .set_away = discord_set_away
  };
  dpp = g_memdup(&pp, sizeof pp);
  register_protocol(dpp);
}

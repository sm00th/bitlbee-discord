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
#include "discord.h"
#include "discord-http.h"
#include "discord-util.h"
#include "discord-websockets.h"
#include "help.h"

#ifdef BITLBEE_ABI_VERSION_CODE
struct plugin_info *init_plugin_info(void)
{
  static struct plugin_info info = {
    BITLBEE_ABI_VERSION_CODE,
    "bitlbee-discord",
    "0.3.1",
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

  s = set_add(&acc->set, "max_backlog", "50", set_eval_int, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  s = set_add(&acc->set, "never_offline", "off", set_eval_bool, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  s = set_add(&acc->set, "server_prefix_len", "3", set_eval_int, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  s = set_add(&acc->set, "token_cache", NULL, NULL, acc);
  s->flags |= SET_HIDDEN | SET_NULL_OK;

  acc->flags |= ACC_FLAG_AWAY_MESSAGE;
  acc->flags |= ACC_FLAG_STATUS_MESSAGE;

  // \002 is ^B which is used by IRC to toggle bold
  help_add_mem(&global.help, "discord",
	       "You need to configure discord channels you would like to join/autojoin. To do that, "
	       "use bitlbee's \002chat list\002 functionality (\002help chat list\002 and \002help chat add\002):\n"
	       "\002<trac3r>\002 chat list discord\n"
	       "This will show you the list of available channel with indexes that can be used for adding channels.\n"
	       "\002<trac3r>\002 chat add discord !1 #mydiscordchannel\n"
	       "\002<trac3r>\002 chan #mydiscordchannel set auto_join true\n"
	       "\002<trac3r>\002 /join #mydiscordchannel\n"
	       "If you set auto_join to true, next time you reconnect there will be no need to join the channel manually.\n"
	       "See \002help discord options\002 for more.");

  help_add_mem(&global.help, "discord options",
	       "Various options are available through \002account set\002. See \002help account set\002 for more info. "
	       "For more help on the the options themselves, use \002help discord <option>\002.\n"
	       "\002host\002 (default: \"discordapp.com\")\n"
	       "\002voice_status_notify\002 (default: no)\n"
	       "\002edit_prefix\002 (default: \"EDIT: \")\n"
	       "\002urlinfo_handle\002 (default: \"urlinfo\")\n"
	       "\002max_backlog\002 (default: 50)\n"
	       "\002send_acks\002 (default: yes)\n"
	       "\002mention_suffix\002 (default: \":\")\n"
	       "\002mention_ignorecase\002 (default: off)\n"
	       "\002incoming_me_translation\002 (default: on)\n"
	       "\002never_offline\002 (default: off)\n"
	       "\002server_prefix_len\002 (default: 3)\n"
	       "\002fetch_pinned\002 (default: off)\n");

  help_add_mem(&global.help, "discord host",
	       "host (type: string; default: \"discordapp.com\")\n"
	       "Discord server hostname. Just in case discord changes the hostname or there "
	       "are some alternatives with compatible API.");

  help_add_mem(&global.help, "discord voice_status_notify",
	       "voice_status_notify (type: boolean; default: no)\n"
	       "This enables text notifications in your control channel about users "
	       "changing/leaving voice channels. Can be noisy on big servers.");

  help_add_mem(&global.help, "discord edit_prefix",
	       "edit_prefix (type: string; default: \"EDIT: \")\n"
	       "A string that will be prefixed to an edited message to distinguish those "
	       "from normal ones.");

  help_add_mem(&global.help, "discord urlinfo_handle",
	       "urlinfo_handle (type: string; default: \"urlinfo\")\n"
	       "User handle that will be used to post url expansion info such as title and "
	       "description in groupchats.");

  help_add_mem(&global.help, "discord max_backlog",
	       "max_backlog (type: integer; default: 50)\n"
	       "Maximum number of backlog messages per channel to fetch on connection. "
	       "Unlike twitter implementation in bitlbee this won't dump seen messages. "
	       "Setting this to 0 or negative values disables backlog fetching.");

  help_add_mem(&global.help, "discord send_acks",
	       "send_acks (type: boolean; default: yes)\n"
	       "By default bitlbee-discord will send an \"ack\" for every message received, "
	       "thus marking everything as \"read\" on mobile/webapp. Setting this to false "
	       "will disable all acks from bitlbee-discord.");

  help_add_mem(&global.help, "discord mention_suffix",
	       "mention_suffix (type: string; default: \":\")\n"
	       "Suffix used in a regex to look for username mentions to automatically "
	       "convert your usual irc-style \"nick:\" mentions to discord's \"<@id>\" format. "
	       "So if you type \"nick: hello\" in bitlbee, it will be displayed as "
	       "\"@nick hello\" in discord. This can be multicharacter and you can even do OR "
	       "logic here because it is actually used as a part of glib regex. That is "
	       "setting this to \"[:,]\" will match both \"nick:\" and \"nick,\". But beware "
	       "overcomplicating this may lead to bitlbee-discord spending a lot of time "
	       "parsing your outgoing messages. Setting this to \"\" will disable this "
	       "function.");

  help_add_mem(&global.help, "discord mention_ignorecase",
	       "mention_ignorecase (type: boolean; default: off)\n"
	       "Ignore case when looking for outgoing mentions. This also affects channel "
	       "mentions.");

  help_add_mem(&global.help, "discord incoming_me_translation",
	       "incoming_me_translation (type: boolean; default: on)\n"
	       "This option controls whether bitlbee-discord will translate incoming "
	       "messages that are fully italicized (that is enclosed in '*' characters) to "
	       "'/me' messages.");

  help_add_mem(&global.help, "discord never_offline",
	       "never_offline (type: boolean; default: off)\n"
	       "Contacts from this account will never appear as offline and will be marked "
	       "away instead.");

  help_add_mem(&global.help, "discord server_prefix_len",
	       "server_prefix_len (type: int; default: 3)\n"
	       "Prefix channel names with this many characters of server name. If set to 0 "
	       "nothing will be prefixed. If set to anything lower than 0 - full server "
	       "name will be prefixed. Assuming we have a channel \"general\" on \"beecord\" "
	       "server here is what channel name you are going to get with different "
	       "settings:\n"
	       " -1 - #beecord.general\n"
	       "  0 - #general\n"
	       "  3 - #bee.general");

  help_add_mem(&global.help, "discord fetch_pinned",
	       "fetch_pinned (type: boolean; default: off)\n"
	       "Fetch pinned messages on channel join.");
}

static void discord_login(account_t *acc)
{
  struct im_connection *ic = imcb_new(acc);

  discord_data *dd = g_new0(discord_data, 1);
  dd->keepalive_interval = DEFAULT_KEEPALIVE_INTERVAL;
  ic->proto_data = dd;

  if (set_getstr(&ic->acc->set,"token_cache")) {
    discord_http_get_gateway(ic, set_getstr(&ic->acc->set,"token_cache"));
  } else {
    discord_http_login(acc);
  }
}

static void discord_logout(struct im_connection *ic)
{
  discord_data *dd = ic->proto_data;

  discord_ws_cleanup(dd);

  free_discord_data(dd);
  g_slist_free(ic->chatlist);
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
  discord_data *dd = ic->proto_data;
  struct groupchat *gc = NULL;
  server_info *sinfo = NULL;
  channel_info *cinfo = get_channel(dd, room, NULL, SEARCH_FNAME);

  if (cinfo == NULL || cinfo->type != CHANNEL_TEXT) {
    return NULL;
  }

  sinfo = cinfo->to.channel.sinfo;
  gc = imcb_chat_new(ic, cinfo->to.channel.name);
  if (cinfo->to.channel.bci->topic != NULL) {
    imcb_chat_topic(gc, "root", cinfo->to.channel.bci->topic, 0);
  }

  for (GSList *ul = sinfo->users; ul; ul = g_slist_next(ul)) {
    user_info *uinfo = ul->data;
    if (uinfo->user->flags & BEE_USER_ONLINE) {
      imcb_chat_add_buddy(gc, uinfo->user->handle);
    }
  }
  imcb_chat_add_buddy(gc, dd->uname);

  cinfo->to.channel.gc = gc;
  gc->data = cinfo;

  if (set_getbool(&ic->acc->set, "fetch_pinned")) {
    discord_http_get_pinned(ic, cinfo->id);
  }

  if (set_getint(&ic->acc->set, "max_backlog") > 0 &&
      cinfo->last_msg > cinfo->last_read) {
    cinfo->last_msg = cinfo->last_read;
    discord_http_get_backlog(ic, cinfo->id);
  }

  return gc;
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

static gboolean discord_is_self(struct im_connection *ic, const char *who)
{
  discord_data *dd = ic->proto_data;
  return !g_strcmp0(dd->uname, who);
}

static GList *discord_away_states(struct im_connection *ic)
{
    static GList *m = NULL;

    m = g_list_append(m, "Idle");

    return m;
}

static void discord_set_away(struct im_connection *ic, char *state,
                             char *message)
{
  discord_data *dd = ic->proto_data;

  discord_ws_set_status(dd, state != NULL, message);
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
    .buddy_msg = discord_buddy_msg,
    .handle_cmp = g_strcmp0,
    .handle_is_self = discord_is_self,
    .away_states = discord_away_states,
    .set_away = discord_set_away
  };
  dpp = g_memdup(&pp, sizeof pp);
  register_protocol(dpp);
}

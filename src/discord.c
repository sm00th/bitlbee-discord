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

  s = set_add(&acc->set, "max_backlog", "50", set_eval_int, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  s = set_add(&acc->set, "never_offline", "off", set_eval_bool, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  s = set_add(&acc->set, "server_prefix_len", "0", set_eval_int, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  acc->flags |= ACC_FLAG_AWAY_MESSAGE;
  acc->flags |= ACC_FLAG_STATUS_MESSAGE;
}

static void discord_login(account_t *acc)
{
  struct im_connection *ic = imcb_new(acc);

  discord_data *dd = g_new0(discord_data, 1);
  dd->keepalive_interval = DEFAULT_KEEPALIVE_INTERVAL;
  ic->proto_data = dd;

  discord_http_login(acc);
}

static void discord_logout(struct im_connection *ic)
{
  discord_data *dd = ic->proto_data;

  discord_ws_cleanup(dd);

  free_discord_data(dd);
}

static void discord_chat_msg(struct groupchat *gc, char *msg, int flags)
{
  channel_info *cinfo = gc->data;

  discord_http_send_msg(gc->ic, cinfo->id, msg);
}

static int discord_buddy_msg(struct im_connection *ic, char *to, char *msg,
                             int flags)
{
  discord_data *dd = ic->proto_data;

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
    .buddy_msg = discord_buddy_msg,
    .handle_cmp = g_strcmp0,
    .handle_is_self = discord_is_self,
    .away_states = discord_away_states,
    .set_away = discord_set_away
  };
  dpp = g_memdup(&pp, sizeof pp);
  register_protocol(dpp);
}

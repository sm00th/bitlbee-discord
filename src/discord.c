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
#include "discord.h"
#include "discord-http.h"
#include "discord-util.h"
#include "discord-websockets.h"

static void discord_init(account_t *acc)
{
  set_t *s;

  s = set_add(&acc->set, "host", DISCORD_HOST, NULL, acc);
  s->flags |= ACC_SET_OFFLINE_ONLY;

  s = set_add(&acc->set, "voice_status_notify", "off", set_eval_bool, acc);
  s = set_add(&acc->set, "edit_prefix", "EDIT: ", NULL, acc);
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

  return 1;
}

static gboolean discord_is_self(struct im_connection *ic, const char *who)
{
  discord_data *dd = ic->proto_data;
  return !g_strcmp0(dd->uname, who);
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

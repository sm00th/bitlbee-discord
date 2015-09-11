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

#define DISCORD_URL "http://discordapp.com/api"
#define DISCORD_HOST "discordapp.com"

static void discord_init(account_t *acct) {
  set_t *s;

  g_print("%s\n", __func__);
  s = set_add(&acct->set, "token", NULL, NULL, acct);
  s->flags = SET_NULL_OK | SET_HIDDEN | SET_PASSWORD;

  s = set_add(&acct->set, "uid", NULL, NULL, acct);
  s->flags = SET_NULL_OK | SET_HIDDEN;

  set_add(&acct->set, "show_unread", "true", set_eval_bool, acct);
}

static void discord_login(account_t *acc) {
  /*
   * POST request
   * > { "email" : "xxx@xxx.xxx", "password" : "xxx" }
   * < token
   */
  GString *request = g_string_new("");
  GString *jlogin = g_string_new("");

  g_print("%s\n", __func__);
  g_string_printf(request, "{\"email\":\"%s\",\"password\",\"%s\"}",
                  "login",
                  "password");

  g_string_printf(request, "POST api/auth/login HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "User-Agent: Bitlbee-Discord\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: %zd\r\n\r\n"
                  "%s",
                  DISCORD_HOST,
                  jlogin->len,
                  jlogin->str);

  (void) http_dorequest(DISCORD_HOST, 80, 1, request->str, NULL, NULL);

  g_string_free(request, TRUE);
}

G_MODULE_EXPORT void init_plugin(void)
{
  struct prpl *dpp;

  static const struct prpl pp = {
    .name = "discord",
    .init = discord_init,
    .login = discord_login,
    /*.logout = fb_logout,
    .buddy_msg = fb_buddy_msg,
    .send_typing = fb_send_typing,
    .add_buddy = fb_add_buddy,
    .remove_buddy = fb_remove_buddy,
    .chat_invite = fb_chat_invite,
    .chat_leave = fb_chat_leave,
    .chat_msg = fb_chat_msg,
    .chat_join = fb_chat_join,
    .chat_topic = fb_chat_topic,*/
    .handle_cmp = g_strcmp0
  };
  g_print("%s\n", __func__);
  dpp = g_memdup(&pp, sizeof pp);
  register_protocol(dpp);
}

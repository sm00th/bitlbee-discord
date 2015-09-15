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

#define DISCORD_URL "http://discordapp.com/api"
#define DISCORD_HOST "discordapp.com"

struct discord_data {
  char *token;
  char *id;
};

static void discord_init(account_t *acct) {
  //set_t *s;

  g_print("%s\n", __func__);
  //s = set_add(&acct->set, "token", NULL, NULL, acct);
  //s->flags = SET_NULL_OK | SET_HIDDEN | SET_PASSWORD;

  //s = set_add(&acct->set, "uid", NULL, NULL, acct);
  //s->flags = SET_NULL_OK | SET_HIDDEN;

  //set_add(&acct->set, "show_unread", "true", set_eval_bool, acct);
}

static void discord_logout(struct im_connection *ic) {
  struct discord_data *dd = ic->proto_data;

  g_print("%s\n", __func__);
  if (dd->token != NULL) {
    g_free(dd->token);
  }

  if (dd->id != NULL) {
    g_free(dd->id);
  }

  g_free(dd);
}

static void discord_me_cb(struct http_request *req) {
  struct im_connection *ic = req->data;
  g_print("============================\nstatus=%d\n", req->status_code);
  g_print("\nrh=%s\nrb=%s\n", req->reply_headers, req->reply_body);

  if (req->status_code == 200) {
    json_value *js = json_parse(req->reply_body, req->body_size);
    if (!js || js->type != json_object) {
      imcb_error(ic, "Failed to parse json reply.");
      imc_logout(ic, TRUE);
    }
    struct discord_data *dd = ic->proto_data;
    dd->id = json_o_strdup(js, "id");
    g_print("ID: %s\n", dd->id);
  } else {
    imcb_error(ic, "Failed to get info about self.");
    imc_logout(ic, TRUE);
  }
}

static void discord_login_cb(struct http_request *req) {
  struct im_connection *ic = req->data;
  g_print("============================\nstatus=%d\n", req->status_code);
  g_print("\nrh=%s\nrb=%s\n", req->reply_headers, req->reply_body);

  json_value *js = json_parse(req->reply_body, req->body_size);
  if (!js || js->type != json_object) {
    imcb_error(ic, "Failed to parse json reply.");
    imc_logout(ic, TRUE);
  }
  if (req->status_code == 200) {
    struct discord_data *dd = ic->proto_data;
    dd->token = json_o_strdup(js, "token");
    g_print("TOKEN: %s\n", dd->token);

    // TODO: Remove this debug crap
    GString *request = g_string_new("");
    g_string_printf(request, "GET /api/users/@me HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: Bitlbee-Discord\r\n"
                    "Content-Type: application/json\r\n"
                    "authorization: %s\r\n\r\n",
                    DISCORD_HOST,
                    dd->token);

    g_print("Sending req:\nxxxxxxxxxx\n%s\nxxxxxxxxxx\n", request->str);
    (void) http_dorequest(DISCORD_HOST, 80, 0, request->str, discord_me_cb,
                          ic);
  } else {
    JSON_O_FOREACH(js, k, v){
      if (v->type != json_array) {
        continue;
      }

      int i;
      GString *err = g_string_new("");
      g_string_printf(err, "%s:", k);
      for (i = 0; i < v->u.array.length; i++) {
        if(v->u.array.values[i]->type == json_string) {
          g_string_append_printf(err, " %s",
                                 v->u.array.values[i]->u.string.ptr);
        }
      }
      imcb_error(ic, err->str);
      g_string_free(err, TRUE);
      imc_logout(ic, FALSE);
    }
  }
}

static void discord_login(account_t *acc) {
  struct im_connection *ic = imcb_new(acc);
  GString *request = g_string_new("");
  GString *jlogin = g_string_new("");

  ic->proto_data = g_new0(struct discord_data, 1);
  g_print("%s\n", __func__);
  g_string_printf(jlogin, "{\"email\":\"%s\",\"password\":\"%s\"}",
                  acc->user,
                  acc->pass);

  g_string_printf(request, "POST /api/auth/login HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "User-Agent: Bitlbee-Discord\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: %zd\r\n\r\n"
                  "%s",
                  DISCORD_HOST,
                  jlogin->len,
                  jlogin->str);

  g_print("Sending req:\nxxxxxxxxxx\n%s\nxxxxxxxxxx\n", request->str);
  (void) http_dorequest(DISCORD_HOST, 80, 0, request->str, discord_login_cb,
                       acc->ic);

  g_string_free(request, TRUE);
}

G_MODULE_EXPORT void init_plugin(void)
{
  struct prpl *dpp;

  static const struct prpl pp = {
    .name = "discord",
    .init = discord_init,
    .login = discord_login,
    .logout = discord_logout,
    /*.buddy_msg = fb_buddy_msg,
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

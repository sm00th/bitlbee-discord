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
#include <bitlbee/http_client.h>
#include <bitlbee/json.h>
#include <bitlbee/json_util.h>

#include "discord.h"
#include "discord-http.h"
#include "discord-websockets.h"

static void discord_http_get(struct im_connection *ic, const char *api_path,
                             http_input_function cb_func, gpointer data)
{
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

static void discord_http_gateway_cb(struct http_request *req)
{
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

    const char *gw = json_o_str(js, "url");
    char *tmp;
    if ((tmp = g_strstr_len(gw, MIN(strlen(gw), 6), "://"))) {
      dd->gateway = g_strdup(tmp + 3);
    } else {
      dd->gateway = g_strdup(gw);
    }

    if (discord_ws_init(ic, dd) < 0) {
      imcb_error(ic, "Failed to create websockets context.");
      imc_logout(ic, TRUE);
      json_value_free(js);
      return;
    }
    dd->state = WS_CONNECTING;

    json_value_free(js);
  } else {
    imcb_error(ic, "Failed to get info about self.");
    imc_logout(ic, TRUE);
  }
}

static void discord_http_login_cb(struct http_request *req)
{
  struct im_connection *ic = req->data;

  if (req->status_code == 200) {
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

      discord_http_get(ic, "gateway", discord_http_gateway_cb, ic);
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
      }
    }
    json_value_free(js);
  } else {
    imcb_error(ic, "Failed to login: %d.", req->status_code);
    imc_logout(ic, TRUE);
  }
}

static void discord_http_send_msg_cb(struct http_request *req)
{
  struct im_connection *ic = req->data;
  if (req->status_code != 200) {
    imcb_error(ic, "Failed to send message (%d).", req->status_code);
  }
}

void discord_http_send_msg(struct im_connection *ic, char *id, char *msg)
{
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
                                   request->str, discord_http_send_msg_cb, ic);

  g_string_free(content, TRUE);
  g_string_free(request, TRUE);
}

void discord_http_login(account_t *acc)
{
  GString *request = g_string_new("");
  GString *jlogin = g_string_new("");

  g_string_printf(jlogin, "{\"email\":\"%s\",\"password\":\"%s\"}",
                  acc->user,
                  acc->pass);

  g_string_printf(request, "POST /api/auth/login HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "User-Agent: Bitlbee-Discord\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: %zd\r\n\r\n"
                  "%s",
                  set_getstr(&acc->set, "host"),
                  jlogin->len,
                  jlogin->str);

  (void) http_dorequest(set_getstr(&acc->set, "host"), 80, 0,
                                   request->str, discord_http_login_cb,
                                   acc->ic);

  g_string_free(jlogin, TRUE);
  g_string_free(request, TRUE);
}

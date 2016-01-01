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
#include "discord-handlers.h"
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
      imc_logout(ic, TRUE);
    }
  }
  json_value_free(js);
}

static void discord_http_noop_cb(struct http_request *req)
{
  return;
}

static void discord_http_send_msg_cb(struct http_request *req)
{
  struct im_connection *ic = req->data;
  if (req->status_code != 200) {
    imcb_error(ic, "Failed to send message (%d).", req->status_code);
  }
}

static void discord_http_backlog_cb(struct http_request *req)
{
  struct im_connection *ic = req->data;
  if (req->status_code != 200) {
    imcb_error(ic, "Failed to get backlog (%d).", req->status_code);
  } else {
    json_value *messages = json_parse(req->reply_body, req->body_size);
    if (!messages || messages->type != json_array) {
      imcb_error(ic, "Failed to parse json reply for backlog.");
      imc_logout(ic, TRUE);
      json_value_free(messages);
      return;
    }

    for (int midx = messages->u.array.length - 1; midx >= 0; midx--) {
      json_value *minfo = messages->u.array.values[midx];
      discord_handle_message(ic, minfo, ACTION_CREATE);
    }

    json_value_free(messages);
  }
}

void discord_http_get_backlog(struct im_connection *ic, const char *channel_id)
{
  GString *api = g_string_new("");

  g_string_printf(api, "channels/%s/messages?limit=%d", channel_id,
                  set_getint(&ic->acc->set, "max_backlog"));

  discord_http_get(ic, api->str, discord_http_backlog_cb, ic);

  g_string_free(api, TRUE);
}

static gboolean discord_escape_string(const GMatchInfo *match,
                                      GString *result,
                                      gpointer user_data)
{
  guint32 *matches = user_data;
  gint pos = 0;

  if (g_match_info_fetch_pos(match, 0, &pos, NULL)) {
    gchar *r = g_strdup_printf("\\%s", g_match_info_fetch(match, 0));
    result = g_string_insert(result, pos + (*matches)++, r);
    g_free(r);
  }
  return FALSE;
}

void discord_http_send_msg(struct im_connection *ic, const char *id,
                           const char *msg)
{
  discord_data *dd = ic->proto_data;
  GString *request = g_string_new("");
  GString *content = g_string_new("");
  guint32 matches = 0;
  GRegex *regex = g_regex_new("[\"]", 0, 0, NULL);
  gchar *emsg = g_regex_replace_eval(regex, msg, -1, 0, 0,
                                     discord_escape_string, &matches, NULL);

  g_string_printf(content, "{\"content\":\"%s\"}", emsg);
  g_regex_unref(regex);
  g_free(emsg);
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

void discord_http_send_ack(struct im_connection *ic, const char *channel_id,
                           const char *message_id)
{
  if (set_getbool(&ic->acc->set, "send_acks") == FALSE) {
    return;
  }

  discord_data *dd = ic->proto_data;
  GString *request = g_string_new("");

  g_string_printf(request, "POST /api/channels/%s/messages/%s/ack HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "User-Agent: Bitlbee-Discord\r\n"
                  "Authorization: %s\r\n"
                  "Content-Length: 0\r\n\r\n",
                  channel_id, message_id,
                  set_getstr(&ic->acc->set, "host"),
                  dd->token);

  (void) http_dorequest(set_getstr(&ic->acc->set, "host"), 80, 0,
                                   request->str, discord_http_noop_cb,
                                   NULL);

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

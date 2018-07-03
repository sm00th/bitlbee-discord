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
#include <config.h>
#include <http_client.h>
#include <json.h>
#include <json_util.h>

#include "discord.h"
#include "discord-http.h"
#include "discord-handlers.h"
#include "discord-websockets.h"
#include "discord-util.h"

typedef struct _casm_data {
  struct im_connection *ic;
  char *msg;
} casm_data;

typedef struct _mstr_data {
  struct im_connection *ic;
  char *sid;
} mstr_data;

typedef struct _retry_req {
  char *request;
  struct im_connection *ic;
  http_input_function func;
  gpointer data;
  gint evid;
} retry_req;

static void _discord_http_get(struct im_connection *ic, char *request,
                             http_input_function cb_func, gpointer data)
{
  discord_data *dd = ic->proto_data;
  struct http_request *req;

  req = http_dorequest(set_getstr(&ic->acc->set, "host"), 443, 1,
                       request, cb_func, data);

  dd->pending_reqs = g_slist_prepend(dd->pending_reqs, req);
}

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

  discord_debug(">>> (%s) %s %lu", dd->uname, __func__, request->len);
  _discord_http_get(ic, request->str, cb_func, data);
  g_string_free(request, TRUE);
}

static gboolean discord_http_retry(retry_req *rreq, gint fd,
                                   b_input_condition cond)
{
  struct im_connection *ic = rreq->ic;
  discord_data *dd = ic->proto_data;

  _discord_http_get(ic, rreq->request, rreq->func, rreq->data);

  dd->pending_events = g_slist_remove(dd->pending_events,
                                     GINT_TO_POINTER(rreq->evid));
  g_free(rreq->request);
  g_free(rreq);

  return FALSE;
}

static int discord_http_check_retry(struct http_request *req)
{
  struct im_connection *ic = req->data;
  discord_data *dd = ic->proto_data;

  if (req->status_code == 429) {
    json_value *js = json_parse(req->reply_body, req->body_size);
    if (!js || js->type != json_object) {
      imcb_error(ic, "Error while parsing ratelimit message");
      json_value_free(js);
      return 0;
    }

    json_value *retry = json_o_get(js, "retry_after");
    guint32 timeout = (retry && retry->type == json_integer) ? retry->u.integer : 0;
    retry_req *rreq = g_new0(retry_req, 1);
    rreq->request = g_strdup(req->request);
    rreq->ic = ic;
    rreq->func = req->func;
    rreq->data = req->data;

    gint evid = b_timeout_add(timeout, (b_event_handler)discord_http_retry,
                              rreq);
    rreq->evid = evid;

    dd->pending_events = g_slist_prepend(dd->pending_events,
                                         GINT_TO_POINTER(evid));
    discord_debug("(%s) %s [%d] retry scheduled in %u", dd->uname, __func__,
                  evid, timeout);

    json_value_free(js);
    return 1;
  }
  return 0;
}

static void discord_http_gateway_cb(struct http_request *req)
{
  struct im_connection *ic = req->data;
  discord_data *dd = ic->proto_data;

  discord_debug("<<< (%s) %s [%d] %d\n%s\n", dd->uname, __func__,
                req->status_code, req->body_size, req->reply_body);

  dd->pending_reqs = g_slist_remove(dd->pending_reqs, req);

  if (req->status_code == 200) {
    json_value *js = json_parse(req->reply_body, req->body_size);
    if (!js || js->type != json_object) {
      imcb_error(ic, "Failed to parse json reply (%s)", __func__);
      imc_logout(ic, TRUE);
      json_value_free(js);
      return;
    }
    discord_data *dd = ic->proto_data;

    const char *gw = json_o_str(js, "url");
    GMatchInfo *match = NULL;
    GRegex *gwregex = g_regex_new("^(wss?://)?([^/]+)(/.*)?$", 0, 0, NULL);

    g_regex_match(gwregex, gw, 0, &match);

    if (match == NULL) {
      imcb_error(ic, "Failed to get gateway (%s).", gw);
      json_value_free(js);
      g_regex_unref(gwregex);
      imc_logout(ic, TRUE);
      return;
    }

    dd->gateway = g_new0(gw_data, 1);

    gchar *wss = g_match_info_fetch(match, 1);
    if (g_strcmp0(wss, "wss://") == 0) {
      dd->gateway->wss = 1;
    } else {
      dd->gateway->wss = 0;
    }
    g_free(wss);

    dd->gateway->addr = g_match_info_fetch(match, 2);
    dd->gateway->path = g_match_info_fetch(match, 3);

    if (dd->gateway->path == NULL) {
      dd->gateway->path = g_strdup("/?encoding=json&v=6");
    }

    g_match_info_free(match);
    g_regex_unref(gwregex);

    if (discord_ws_init(ic, dd) < 0) {
      imcb_error(ic, "Failed to create websockets context.");
      imc_logout(ic, TRUE);
      json_value_free(js);
      return;
    }
    dd->state = WS_CONNECTING;

    json_value_free(js);
  } else {
    if (discord_http_check_retry(req) == 0) {
      imcb_error(ic, "Failed to get info about self.");
      imc_logout(ic, TRUE);
    }
  }
}

void discord_http_get_gateway(struct im_connection *ic, const char *token)
{
  discord_data *dd = ic->proto_data;

  dd->token = g_strdup(token);
  set_setstr(&ic->acc->set, "token_cache", dd->token);
  discord_http_get(ic, "gateway", discord_http_gateway_cb, ic);
}

static void discord_http_mfa_cb(struct http_request *req)
{
  struct im_connection *ic = req->data;
  discord_data *dd = ic->proto_data;

  discord_debug("<<< (%s) %s [%d] %d\n%s\n", dd->uname, __func__,
                req->status_code, req->body_size, req->reply_body);
  dd->pending_reqs = g_slist_remove(dd->pending_reqs, req);

  json_value *js = json_parse(req->reply_body, req->body_size);
  if (!js || js->type != json_object) {
    imcb_error(ic, "Failed to parse json reply (%s)", __func__);
    imc_logout(ic, TRUE);
    json_value_free(js);
    return;
  }

  imcb_remove_buddy(ic, DISCORD_MFA_HANDLE, NULL);
  if (req->status_code == 200) {
    discord_data *dd = ic->proto_data;

    g_free(dd->token);
    discord_http_get_gateway(ic, json_o_str(js, "token"));
  } else {
    if (discord_http_check_retry(req) == 0) {
      imcb_error(ic, "MFA Error: %s", (char*)json_o_str(js, "message"));
      imc_logout(ic, TRUE);
    }
  }
  json_value_free(js);
}

static void discord_http_login_cb(struct http_request *req)
{
  struct im_connection *ic = req->data;
  discord_data *dd = ic->proto_data;

  discord_debug("<<< (%s) %s [%d] %d\n%s\n", dd->uname, __func__,
                req->status_code, req->body_size, req->reply_body);
  dd->pending_reqs = g_slist_remove(dd->pending_reqs, req);

  json_value *js = json_parse(req->reply_body, req->body_size);
  if (!js || js->type != json_object) {
    imcb_error(ic, "Failed to parse json reply (%s)", __func__);
    imc_logout(ic, TRUE);
    json_value_free(js);
    return;
  }

  if (req->status_code == 200) {
    discord_data *dd = ic->proto_data;
    json_value *mfa = json_o_get(js, "mfa");

    if (mfa != NULL && mfa->type == json_boolean && mfa->u.boolean == TRUE) {
      dd->token = json_o_strdup(js, "ticket");
      imcb_log(ic, "Starting MFA authentication");
      imcb_add_buddy(ic, DISCORD_MFA_HANDLE, NULL);
      imcb_buddy_msg(ic, DISCORD_MFA_HANDLE, "Two-factor auth is enabled. "
                     "Please respond to this message with your token.", 0, 0);
    } else {
      discord_http_get_gateway(ic, json_o_str(js, "token"));
    }
  } else {
    if (discord_http_check_retry(req) == 0) {
      char *errmsg = (char*)json_o_str(js, "message");

      if (errmsg == NULL) {
        json_value *em = NULL;
        json_value *email = json_o_get(js, "email");
        json_value *password = json_o_get(js, "password");
        json_value *captcha_key = json_o_get(js, "captcha_key");

        if (email != NULL && email->type == json_array) {
          em = email->u.array.values[0];
        } else if (password != NULL && password->type == json_array) {
          em = password->u.array.values[0];
        } else if (captcha_key != NULL && captcha_key->type == json_array) {
          em = captcha_key->u.array.values[0];
        }

        if (em != NULL && em->type == json_string) {
          errmsg = em->u.string.ptr;
        }
      }

      imcb_error(ic, "Login error: %s", errmsg);
      imc_logout(ic, TRUE);
    }
  }
  json_value_free(js);
}

static void discord_http_noop_cb(struct http_request *req)
{
  discord_data *dd = req->data;
  dd->pending_reqs = g_slist_remove(dd->pending_reqs, req);
  return;
}

static void discord_http_send_msg_cb(struct http_request *req)
{
  struct im_connection *ic = req->data;
  discord_data *dd = ic->proto_data;

  dd->pending_reqs = g_slist_remove(dd->pending_reqs, req);

  discord_debug("<<< (%s) %s [%d] %d\n%s\n", dd->uname, __func__,
                req->status_code, req->body_size, req->reply_body);

  if (req->status_code != 200) {
    if (discord_http_check_retry(req) == 0) {
      imcb_error(ic, "Failed to send message (%d).", req->status_code);
    }
  }
}

static void discord_http_backlog_cb(struct http_request *req)
{
  struct im_connection *ic = req->data;
  discord_data *dd = ic->proto_data;

  dd->pending_reqs = g_slist_remove(dd->pending_reqs, req);

  discord_debug("<<< (%s) %s [%d] %d\n%s\n", dd->uname, __func__,
                req->status_code, req->body_size, req->reply_body);

  if (req->status_code != 200) {
    if (discord_http_check_retry(req) == 0) {
      imcb_error(ic, "Failed to get backlog (%d).", req->status_code);
    }
  } else {
    json_value *messages = json_parse(req->reply_body, req->body_size);
    if (!messages || messages->type != json_array) {
      imcb_error(ic, "Failed to parse json reply (%s)", __func__);
      imc_logout(ic, TRUE);
      json_value_free(messages);
      return;
    }

    for (int midx = messages->u.array.length - 1; midx >= 0; midx--) {
      json_value *minfo = messages->u.array.values[midx];
      discord_handle_message(ic, minfo, ACTION_CREATE, TRUE);
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

static void discord_http_pinned_cb(struct http_request *req)
{
  struct im_connection *ic = req->data;
  discord_data *dd = ic->proto_data;

  dd->pending_reqs = g_slist_remove(dd->pending_reqs, req);

  discord_debug("<<< (%s) %s [%d] %d\n%s\n", dd->uname, __func__,
                req->status_code, req->body_size, req->reply_body);

  if (req->status_code != 200) {
    if (discord_http_check_retry(req) == 0) {
      imcb_error(ic, "Failed to get pinned messages (%d).", req->status_code);
    }
  } else {
    json_value *messages = json_parse(req->reply_body, req->body_size);
    if (!messages || messages->type != json_array) {
      imcb_error(ic, "Failed to parse json reply (%s)", __func__);
      imc_logout(ic, TRUE);
      json_value_free(messages);
      return;
    }

    for (int midx = messages->u.array.length - 1; midx >= 0; midx--) {
      json_value *minfo = messages->u.array.values[midx];
      discord_handle_message(ic, minfo, ACTION_CREATE, TRUE);
    }

    json_value_free(messages);
  }
}

void discord_http_get_pinned(struct im_connection *ic, const char *channel_id)
{
  GString *api = g_string_new("");

  g_string_printf(api, "channels/%s/pins", channel_id);

  discord_http_get(ic, api->str, discord_http_pinned_cb, ic);

  g_string_free(api, TRUE);
}

static gboolean discord_mentions_string(const GMatchInfo *match,
                                        GString *result,
                                        gpointer user_data)
{
  mstr_data *md = (mstr_data *)user_data;
  struct im_connection *ic = md->ic;
  discord_data *dd = ic->proto_data;
  gchar *name = g_match_info_fetch(match, 1);

  search_t stype = SEARCH_IRC_USER_NAME;
  if (set_getbool(&ic->acc->set, "mention_ignorecase") == TRUE) {
    stype = SEARCH_IRC_USER_NAME_IGNORECASE;
  }

  user_info *uinfo = get_user(dd, name, md->sid, stype);
  g_free(name);

  if (uinfo != NULL) {
    gchar *id = g_strdup_printf("<@%" G_GUINT64_FORMAT ">", uinfo->id);
    result = g_string_append(result, id);
    g_free(id);
  } else {
    gchar *fmatch = g_match_info_fetch(match, 0);
    result = g_string_append(result, fmatch);
    g_free(fmatch);
  }

  return FALSE;
}

static gboolean discord_channel_string(const GMatchInfo *match,
                                       GString *result,
                                       gpointer user_data)
{
  mstr_data *md = (mstr_data *)user_data;
  struct im_connection *ic = md->ic;
  discord_data *dd = ic->proto_data;

  gchar *name = g_match_info_fetch(match, 1);

  search_t stype = SEARCH_NAME;
  if (set_getbool(&ic->acc->set, "mention_ignorecase") == TRUE) {
    stype = SEARCH_NAME_IGNORECASE;
  }

  channel_info *cinfo = get_channel(dd, name, md->sid, stype);
  g_free(name);

  if (cinfo != NULL) {
    gchar *id = g_strdup_printf("<#%s>", cinfo->id);
    result = g_string_append(result, id);
    g_free(id);
  } else {
    gchar *fmatch = g_match_info_fetch(match, 0);
    result = g_string_append(result, fmatch);
    g_free(fmatch);
  }

  return FALSE;
}

void discord_http_send_msg(struct im_connection *ic, const char *id,
                           const char *msg)
{
  discord_data *dd = ic->proto_data;
  GString *request = g_string_new("");
  GString *content = g_string_new("");
  channel_info *cinfo = get_channel(dd, id, NULL, SEARCH_ID);
  mstr_data *md = g_new0(mstr_data, 1);

  md->ic = ic;
  if (cinfo != NULL && cinfo->type == CHANNEL_TEXT) {
    md->sid = cinfo->to.channel.sinfo->id;
  }

  gchar *nmsg = NULL;
  gchar *emsg = discord_escape_string(msg);

  if (strlen(set_getstr(&ic->acc->set,"mention_suffix")) > 0) {
    gchar *hlrstr = g_strdup_printf("(\\S+)%s", set_getstr(&ic->acc->set,
                                                "mention_suffix"));
    GRegex *hlregex = g_regex_new(hlrstr, 0, 0, NULL);

    g_free(hlrstr);
    nmsg = g_regex_replace_eval(hlregex, emsg, -1, 0, 0,
                                discord_mentions_string, md, NULL);
    g_free(emsg);
    emsg = nmsg;
    g_regex_unref(hlregex);
  }

  GRegex *hlregex = g_regex_new("@(\\S+)", 0, 0, NULL);

  nmsg = g_regex_replace_eval(hlregex, emsg, -1, 0, 0,
                              discord_mentions_string, md, NULL);
  g_free(emsg);
  emsg = nmsg;
  g_regex_unref(hlregex);

  hlregex = g_regex_new("#(\\S+)", 0, 0, NULL);
  nmsg = g_regex_replace_eval(hlregex, emsg, -1, 0, 0,
                              discord_channel_string, md, NULL);
  g_free(emsg);
  emsg = nmsg;
  g_regex_unref(hlregex);
  g_free(md);

  if (g_str_has_prefix(emsg, "/me ")) {
    nmsg = g_strdup_printf("_%s_", emsg + 4);
    g_free(emsg);
    emsg = nmsg;
  }

  g_string_printf(content, "{\"content\":\"%s\", \"nonce\":\"%s\"}",
                  emsg, dd->nonce);
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

  discord_debug(">>> (%s) %s %lu", dd->uname, __func__, request->len);

  _discord_http_get(ic, request->str, discord_http_send_msg_cb, ic);

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
                  "Content-Type: application/json\r\n"
                  "Authorization: %s\r\n"
                  "Content-Length: 2\r\n\r\n"
                  "{}",
                  channel_id, message_id,
                  set_getstr(&ic->acc->set, "host"),
                  dd->token);

  discord_debug(">>> (%s) %s %lu", dd->uname, __func__, request->len);

  _discord_http_get(ic, request->str, discord_http_noop_cb, dd);

  g_string_free(request, TRUE);
}

void discord_http_mfa_auth(struct im_connection *ic, const char *msg)
{
  GString *request = g_string_new("");
  GString *auth = g_string_new("");
  discord_data *dd = ic->proto_data;

  g_string_printf(auth, "{\"code\":\"%s\",\"ticket\":\"%s\"}",
                  msg,
                  dd->token);

  g_string_printf(request, "POST /api/auth/mfa/totp HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "User-Agent: Bitlbee-Discord\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: %zd\r\n\r\n"
                  "%s",
                  set_getstr(&ic->acc->set, "host"),
                  auth->len,
                  auth->str);

  discord_debug(">>> (%s) %s %lu", dd->uname, __func__, request->len);

  _discord_http_get(ic, request->str, discord_http_mfa_cb, ic);

  g_string_free(auth, TRUE);
  g_string_free(request, TRUE);
}

void discord_http_login(account_t *acc)
{
  GString *request = g_string_new("");
  GString *jlogin = g_string_new("");
  gchar *epass = discord_escape_string(acc->pass);
  discord_data *dd = acc->ic->proto_data;

  g_string_printf(jlogin, "{\"email\":\"%s\",\"password\":\"%s\"}",
                  acc->user,
                  epass);

  g_string_printf(request, "POST /api/auth/login HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "User-Agent: Bitlbee-Discord\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: %zd\r\n\r\n"
                  "%s",
                  set_getstr(&acc->set, "host"),
                  jlogin->len,
                  jlogin->str);

  discord_debug(">>> (%s) %s %lu", dd->uname, __func__, request->len);

  _discord_http_get(acc->ic, request->str, discord_http_login_cb, acc->ic);

  g_free(epass);
  g_string_free(jlogin, TRUE);
  g_string_free(request, TRUE);
}

static void discord_http_casm_cb(struct http_request *req)
{
  casm_data *cd = req->data;
  struct im_connection *ic = cd->ic;
  discord_data *dd = ic->proto_data;
  dd->pending_reqs = g_slist_remove(dd->pending_reqs, req);
  if (req->status_code != 200) {
    if (discord_http_check_retry(req) == 0) {
      imcb_error(ic, "Failed to create private channel (%d).",
                 req->status_code);
    }
    goto out;
  }

  json_value *channel = json_parse(req->reply_body, req->body_size);
  if (!channel || channel->type != json_object) {
    imcb_error(ic, "Failed to create private channel.");
    goto jout;
  }

  discord_handle_channel(ic, channel, NULL, ACTION_CREATE);
  discord_http_send_msg(ic, json_o_str(channel, "id"), cd->msg);

jout:
  json_value_free(channel);

out:
  g_free(cd->msg);
  g_free(cd);
}

void discord_http_create_and_send_msg(struct im_connection *ic,
                                      const char *handle, const char *msg)
{
  discord_data *dd = ic->proto_data;
  user_info *uinfo = get_user(dd, handle, NULL, SEARCH_IRC_USER_NAME);

  if (uinfo == NULL) {
    imcb_error(ic, "Failed to create channel for unknown user: '%s'.",
               handle);
    return;
  }

  GString *request = g_string_new("");
  GString *content = g_string_new("");

  g_string_printf(content, "{\"recipient_id\":\"%" G_GUINT64_FORMAT "\"}", uinfo->id);
  g_string_printf(request, "POST /api/users/%" G_GUINT64_FORMAT "/channels HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "User-Agent: Bitlbee-Discord\r\n"
                  "authorization: %s\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: %zd\r\n\r\n"
                  "%s",
                  dd->id,
                  set_getstr(&ic->acc->set, "host"),
                  dd->token,
                  content->len,
                  content->str);

  casm_data *cd = g_new0(casm_data, 1);
  cd->ic = ic;
  cd->msg = g_strdup(msg);

  discord_debug(">>> (%s) %s %lu", dd->uname, __func__, request->len);

  _discord_http_get(ic, request->str, discord_http_casm_cb, cd);

  g_string_free(content, TRUE);
  g_string_free(request, TRUE);
}

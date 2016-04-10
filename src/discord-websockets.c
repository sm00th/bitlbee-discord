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
#include <libwebsockets.h>

#include "discord-websockets.h"
#include "discord-handlers.h"

static int discord_ws_send_payload(struct lws *wsi, const char *pload,
                                   size_t psize)
{
  int ret = 0;
  unsigned char *buf = g_malloc0(LWS_SEND_BUFFER_PRE_PADDING + \
                                 psize + LWS_SEND_BUFFER_POST_PADDING);
  strncpy((char*)&buf[LWS_SEND_BUFFER_PRE_PADDING], pload, psize);
  ret = lws_write(wsi, &buf[LWS_SEND_BUFFER_PRE_PADDING], psize,
                           LWS_WRITE_TEXT);
  g_free(buf);
  return ret;
}

gboolean discord_ws_keepalive_loop(gpointer data, gint fd,
                                   b_input_condition cond)
{
  struct im_connection *ic = data;
  discord_data *dd = ic->proto_data;

  if (dd->state == WS_READY) {
    lws_callback_on_writable(dd->lws);
  }
  return TRUE;
}

static gboolean discord_ws_service_loop(gpointer data, gint fd,
                                        b_input_condition cond)
{
  struct im_connection *ic = data;

  discord_data *dd = ic->proto_data;

  lws_service(dd->lwsctx, 0);

  if (dd->state == WS_CLOSING) {
    imc_logout(ic, TRUE);
  }

  return TRUE;
}

static int
discord_ws_callback(struct lws *wsi,
                    enum lws_callback_reasons reason,
                    void *user, void *in, size_t len)
{
  struct im_connection *ic = NULL;
  discord_data *dd = NULL;

  if (wsi == NULL) {
    return 0;
  }

  struct lws_context *wsctx = lws_get_context(wsi);
  if (wsctx != NULL) {
    ic = lws_context_user(wsctx);
    dd = ic->proto_data;
  }

  switch(reason) {
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
      dd->state = WS_CONNECTED;
      lws_callback_on_writable(wsi);
      break;
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
      imcb_error(ic, "Websocket connection error");
      if (in != NULL) {
        imcb_error(ic, in);
      }
      b_event_remove(dd->keepalive_loop_id);
      dd->keepalive_loop_id = 0;
      dd->state = WS_CLOSING;
      break;
    case LWS_CALLBACK_CLIENT_WRITEABLE:
      if (dd->state == WS_CONNECTED) {
        GString *buf = g_string_new("");
        g_string_printf(buf, "{\"d\":{\"v\":3,\"token\":\"%s\",\"properties\":{\"$referring_domain\":\"\",\"$browser\":\"bitlbee-discord\",\"$device\":\"bitlbee\",\"$referrer\":\"\",\"$os\":\"linux\"}},\"op\":2}", dd->token);
        discord_ws_send_payload(wsi, buf->str, buf->len);
        g_string_free(buf, TRUE);
      } else if (dd->state == WS_READY) {
        GString *buf = g_string_new("");

        g_string_printf(buf, "{\"op\":1,\"d\":%tu}", time(NULL));
        discord_ws_send_payload(dd->lws, buf->str, buf->len);
        g_string_free(buf, TRUE);
      } else {
        g_print("%s: Unhandled writable callback\n", __func__);
      }
      break;
    case LWS_CALLBACK_CLIENT_RECEIVE:
      {
        size_t rpload = lws_remaining_packet_payload(wsi);
        if (dd->ws_buf == NULL) {
          dd->ws_buf = g_string_new("");
        }
        dd->ws_buf = g_string_append(dd->ws_buf, in);
        if (rpload == 0) {
          discord_parse_message(ic);
          g_string_free(dd->ws_buf, TRUE);
          dd->ws_buf = NULL;
        }
        break;
      }
    case LWS_CALLBACK_CLOSED:
      b_event_remove(dd->keepalive_loop_id);
      dd->keepalive_loop_id = 0;
      dd->state = WS_CLOSING;
      lws_cancel_service(dd->lwsctx);
      break;
    case LWS_CALLBACK_ADD_POLL_FD:
      {
        struct lws_pollargs *pargs = in;
        dd->main_loop_id = b_input_add(pargs->fd, B_EV_IO_READ,
                                       discord_ws_service_loop, ic);
        break;
      }
    case LWS_CALLBACK_DEL_POLL_FD:
      b_event_remove(dd->main_loop_id);
      break;
    case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
      {
        struct lws_pollargs *pargs = in;
        int flags = 0;
        b_event_remove(dd->main_loop_id);
        if (pargs->events & POLLIN) {
          flags |= B_EV_IO_READ;
        }
        if (pargs->events & POLLOUT) {
          flags |= B_EV_IO_WRITE;
        }
        dd->main_loop_id = b_input_add(pargs->fd, flags,
                                       discord_ws_service_loop, ic);
        break;
      }
    case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
    case LWS_CALLBACK_GET_THREAD_ID:
    case LWS_CALLBACK_LOCK_POLL:
    case LWS_CALLBACK_UNLOCK_POLL:
    case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:
    case LWS_CALLBACK_PROTOCOL_INIT:
    case LWS_CALLBACK_PROTOCOL_DESTROY:
    case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
    case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
    case LWS_CALLBACK_WSI_CREATE:
    case LWS_CALLBACK_WSI_DESTROY:
      // Ignoring these, this block should be removed when defult is set to
      // stay silent.
      break;
    default:
      g_print("%s: unknown rsn=%d\n", __func__, reason);
      break;
  }
  return 0;
}

static struct lws_protocols protocols[] =
{
  { "http-only,chat", discord_ws_callback, 0, 0, 0, NULL },
  { NULL, NULL, 0, 0, 0, NULL } /* end */
};

int discord_ws_init(struct im_connection *ic, discord_data *dd)
{
  struct lws_context_creation_info info;

  memset(&info, 0, sizeof(info));

  info.port = CONTEXT_PORT_NO_LISTEN;
  info.protocols = protocols;
#ifndef LWS_NO_EXTENSIONS
  info.extensions = lws_get_internal_extensions();
#else
  info.extensions = NULL;
#endif
  info.gid = -1;
  info.uid = -1;
  info.user = ic;

  lws_set_log_level(0, NULL);

  dd->lwsctx = lws_create_context(&info);
  if (dd->lwsctx == NULL) {
    return -1;
  }

  dd->lws = lws_client_connect(dd->lwsctx, dd->gateway->addr,
                                        dd->gateway->wss ? 443 : 80,
                                        dd->gateway->wss,
                                        dd->gateway->path, dd->gateway->addr,
                                        "discordapp.com",
                                        protocols[0].name, -1);
  return 0;
}

void discord_ws_cleanup(discord_data *dd)
{
  if (dd->keepalive_loop_id > 0) {
    b_event_remove(dd->keepalive_loop_id);
    dd->keepalive_loop_id = 0;
  }
  if (dd->lwsctx != NULL) {
    lws_context_destroy(dd->lwsctx);
  }
}

void discord_ws_set_status(discord_data *dd, gboolean idle, gchar *message)
{
  GString *buf = g_string_new("");
  if (idle == TRUE) {
    g_string_printf(buf, "{\"op\":3,\"d\":{\"idle_since\":%tu,\"game\":{\"name\":\"%s\"}}}", time(NULL), message);
  } else if (message != NULL) {
    g_string_printf(buf, "{\"op\":3,\"d\":{\"idle_since\":null,\"game\":{\"name\":\"%s\"}}}", message);
  } else {
    g_string_printf(buf, "{\"op\":3,\"d\":{\"idle_since\":null,\"game\":{\"name\":null}}}");
  }
  discord_ws_send_payload(dd->lws, buf->str, buf->len);
  g_string_free(buf, TRUE);
}

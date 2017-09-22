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
#include <config.h>
#include <ssl_client.h>
#include <events.h>

#include "discord-websockets.h"
#include "discord-handlers.h"
#include "discord-util.h"
#include "discord.h"

static gchar *discord_ws_mask(guchar key[4], const char *pload,
                              guint64 psize)
{
  gchar *ret = g_malloc0(psize);

  for (guint64 i = 0; i < psize; i++) {
    ret[i] = pload[i] ^ key[i % 4];
  }

  return ret;
}

static int discord_ws_send_payload(discord_data *dd, const char *pload,
                                   guint64 psize)
{
  gchar *buf;
  guint64 hlen = 6;
  size_t ret = 0;
  guchar mkey[4];
  gchar *mpload;

  discord_debug(">>> (%s) %s %"G_GUINT64_FORMAT"\n%s\n", dd->uname, __func__, psize, pload);

  random_bytes(mkey, sizeof(mkey));
  mpload = discord_ws_mask(mkey, pload, psize);

  if (psize > 125) {
    if (psize > G_MAXUINT16) {
      hlen += 8;
    } else {
      hlen += 2;
    }
  }

  buf = g_malloc0(hlen + psize);

  buf[0] = 0x81; // Text frame
  if (psize < 126) {
    buf[1] = (gchar)(psize | 0x80);
  } else if (psize > G_MAXUINT16) {
    guint64 esize = GUINT64_TO_BE(psize);
    buf[1] = (gchar)(127 | 0x80);
    memcpy(buf + 2, &esize, sizeof(esize));
  } else {
    guint16 esize = GUINT16_TO_BE(psize);
    buf[1] = (gchar)(126 | 0x80);
    memcpy(buf + 2, &esize, sizeof(esize));
  }

  memcpy(buf + hlen - sizeof(mkey), &mkey, sizeof(mkey));
  memcpy(buf + hlen, mpload, psize);
  g_free(mpload);

  ret = ssl_write(dd->ssl, buf, hlen + psize);

  g_free(buf);
  return ret;
}

void discord_ws_sync_server(discord_data *dd, const char *id)
{
  GString *buf = g_string_new("");
  g_string_printf(buf, "{\"op\":%d,\"d\":[\"%s\"]}", OPCODE_REQUEST_SYNC, id);
  discord_ws_send_payload(dd, buf->str, buf->len);
  g_string_free(buf, TRUE);
}

static gboolean discord_ws_writable(gpointer data, int source,
                                    b_input_condition cond)
{
  discord_data *dd = (discord_data*)data;
  if (dd->state == WS_CONNECTED) {
    GString *buf = g_string_new("");
    g_string_printf(buf, "{\"d\":{\"token\":\"%s\",\"properties\":{\"$referring_domain\":\"\",\"$browser\":\"bitlbee-discord\",\"$device\":\"bitlbee\",\"$referrer\":\"\",\"$os\":\"linux\"},\"compress\":false,\"large_threshold\":250,\"synced_guilds\":[]},\"op\":%d}", dd->token, OPCODE_IDENTIFY);

    discord_ws_send_payload(dd, buf->str, buf->len);
    g_string_free(buf, TRUE);
  } else if (dd->state == WS_READY) {
    GString *buf = g_string_new("");

    if (dd->seq == 0) {
      g_string_printf(buf, "{\"op\":%d,\"d\":null}", OPCODE_HEARTBEAT);
    } else {
      g_string_printf(buf, "{\"op\":%d,\"d\":%"G_GUINT64_FORMAT"}", OPCODE_HEARTBEAT,
                      dd->seq);
    }
    discord_ws_send_payload(dd, buf->str, buf->len);
    g_string_free(buf, TRUE);
  } else {
    g_print("%s: Unhandled writable callback\n", __func__);
  }

  dd->wsid = 0;
  return FALSE;
}

static void discord_ws_callback_on_writable(discord_data *dd)
{
  dd->wsid = b_input_add(dd->sslfd, B_EV_IO_WRITE, discord_ws_writable, dd);
}


gboolean discord_ws_keepalive_loop(gpointer data, gint fd,
                                   b_input_condition cond)
{
  struct im_connection *ic = data;
  discord_data *dd = ic->proto_data;

  if (dd->state == WS_READY) {
    discord_ws_callback_on_writable(dd);
  }
  return TRUE;
}

static gboolean discord_ws_in_cb(gpointer data, int source,
                                 b_input_condition cond)
{
  struct im_connection *ic = (struct im_connection *)data;
  discord_data *dd = ic->proto_data;

  if (dd->state == WS_CONNECTING) {
    gchar buf[4096] = "";
    ssl_read(dd->ssl, buf, sizeof(buf));
    if (g_strrstr_len(buf, 25, "101 Switching") != NULL && \
        g_str_has_suffix(buf, "\r\n\r\n")) {
      dd->state = WS_CONNECTED;
      discord_ws_callback_on_writable(dd);
    } else {
      imcb_error(ic, "Failed to switch to websocket mode");
      imc_logout(ic, TRUE);
      return FALSE;
    }
  } else {
    gchar buf = 0 ;
    guint64 len = 0;
    gboolean mask = FALSE;
    guchar mkey[4] = {0};
    gpointer rdata = NULL;
    guint64 read = 0;

    if (ssl_read(dd->ssl, &buf, 1) < 1) {
      imcb_error(ic, "Failed to read data.");
      imc_logout(ic, TRUE);
      return FALSE;
    }

    if ((buf & 0xf0) != 0x80) {
      imcb_error(ic, "Unexpected websockets header [0x%x], exiting", buf);
      imc_logout(ic, TRUE);
      return FALSE;
    }

    if ((buf & 0x0f) == 8) {
      imcb_log(ic, "Remote host is closing websocket connection");
      if (dd->state == WS_CONNECTED) {
        imcb_log(ic, "Token expired, cleaning up");
        set_setstr(&ic->acc->set, "token_cache", NULL);
      }
      imc_logout(ic, TRUE);
      return FALSE;
    }

    if (ssl_read(dd->ssl, &buf, 1) < 1) {
      imcb_error(ic, "Failed to read data.");
      imc_logout(ic, TRUE);
      return FALSE;
    }
    len = buf & 0x7f;
    mask = (buf & 0x80) != 0;

    if (len == 126) {
      guint16 lbuf;
      if (ssl_read(dd->ssl, (gchar*)&lbuf, 2) < 2) {
        imcb_error(ic, "Failed to read data.");
        imc_logout(ic, TRUE);
        return FALSE;
      }
      len = GUINT16_FROM_BE(lbuf);
    } else if (len == 127) {
      guint64 lbuf;
      if (ssl_read(dd->ssl, (gchar*)&lbuf, 8) < 8) {
        imcb_error(ic, "Failed to read data.");
        imc_logout(ic, TRUE);
        return FALSE;
      }
      len = GUINT64_FROM_BE(lbuf);
    }

    if (mask) {
      if (ssl_read(dd->ssl, (gchar*)mkey, 4) < 4) {
        imcb_error(ic, "Failed to read data.");
        imc_logout(ic, TRUE);
        return FALSE;
      }
    }

    rdata = g_malloc0(len + 1);
    while (read < len) {
      int ret = ssl_read(dd->ssl, rdata + read, len - read);
      read += ret;
      if (ret == 0) {
        break;
      }
    }

    if (read != len) {
        imcb_error(ic, "Failed to read data.");
        imc_logout(ic, TRUE);
    }

    if (mask) {
      gchar *mdata = discord_ws_mask(mkey, rdata, len);
      discord_parse_message(ic, mdata, len);
      g_free(mdata);
    } else {
      discord_parse_message(ic, rdata, len);
    }
    g_free(rdata);
  }
  if (ssl_pending(dd->ssl)) {
    /* OpenSSL empties the TCP buffers completely but may keep some
       data in its internal buffers. select() won't see that, but
       ssl_pending() does. */
    return discord_ws_in_cb(data, source, cond);
  } else {
    return TRUE;
  }
}

static gboolean discord_ws_connected_cb(gpointer data, int retcode,
                                        void *source, b_input_condition cond)
{
  struct im_connection *ic = (struct im_connection *)data;
  discord_data *dd = ic->proto_data;
  gchar *bkey;
  GString *req;
  guchar key[16];

  if (source == NULL) {
    dd->ssl = NULL;
    imcb_error(ic, "Failed to establish connection.");
    imc_logout(ic, TRUE);
    return FALSE;
  }

  random_bytes(key, sizeof(key));

  bkey = g_base64_encode(key, 16);

  req = g_string_new("");
  g_string_printf(req, "GET %s HTTP/1.1\r\n"
                       "Host: %s\r\n"
                       "Connection: keep-alive, Upgrade\r\n"
                       "Upgrade: websocket\r\n"
                       "Origin: %s\r\n"
                       "Pragma: no-cache\r\n"
                       "Cache-Control: no-cache\r\n"
                       "Sec-WebSocket-Version: 13\r\n"
                       "Sec-WebSocket-Key: %s\r\n"
                       "\r\n", dd->gateway->path, dd->gateway->addr,
                       DISCORD_HOST, bkey);

  g_free(bkey);

  dd->sslfd = ssl_getfd(source);
  dd->inpa = b_input_add(dd->sslfd, B_EV_IO_READ, discord_ws_in_cb, ic);
  ssl_write(dd->ssl, req->str, req->len);
  g_string_free(req, TRUE);
  return FALSE;
}

int discord_ws_init(struct im_connection *ic, discord_data *dd)
{
  dd->ssl = ssl_connect(dd->gateway->addr, 443, TRUE,
                        discord_ws_connected_cb, ic);

  if (dd->ssl == NULL) {
    return -1;
  }

  return 0;
}

void discord_ws_cleanup(discord_data *dd)
{
  if (dd->keepalive_loop_id > 0) {
    b_event_remove(dd->keepalive_loop_id);
    dd->keepalive_loop_id = 0;
  }

  if (dd->wsid > 0) {
    b_event_remove(dd->wsid);
    dd->wsid = 0;
  }

  if (dd->inpa > 0) {
    b_event_remove(dd->inpa);
    dd->inpa = 0;
  }

  if (dd->ssl != NULL) {
    ssl_disconnect(dd->ssl);
    dd->ssl = NULL;
  }
}

void discord_ws_set_status(discord_data *dd, gboolean idle, gchar *message)
{
  GString *buf = g_string_new("");
  gchar *msg = NULL;

  if (message != NULL) {
    msg = discord_escape_string(message);
  }

  if (idle == TRUE) {
    g_string_printf(buf, "{\"op\":%d,\"d\":{\"idle_since\":%tu,\"game\":{\"name\":\"%s\"}}}", OPCODE_STATUS_UPDATE, time(NULL), msg);
  } else if (message != NULL) {
    g_string_printf(buf, "{\"op\":%d,\"d\":{\"idle_since\":null,\"game\":{\"name\":\"%s\"}}}", OPCODE_STATUS_UPDATE, msg);
  } else {
    g_string_printf(buf, "{\"op\":%d,\"d\":{\"idle_since\":null,\"game\":{\"name\":null}}}", OPCODE_STATUS_UPDATE);
  }
  discord_ws_send_payload(dd, buf->str, buf->len);
  g_string_free(buf, TRUE);
  g_free(msg);
}

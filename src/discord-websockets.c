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

#define DISCORD_STATUS_TIMEOUT 500

typedef struct {
  struct im_connection *ic;
  gchar *status;
  gchar *msg;
} status_data;

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

static gboolean discord_ws_heartbeat_timeout(gpointer data, gint fd,
                                             b_input_condition cond)
{
  struct im_connection *ic = data;
  imcb_log(ic, "Heartbeat timed out, reconnecting...");
  discord_soft_reconnect(ic);
  return FALSE;
}

static gboolean discord_ws_writable(gpointer data, int source,
                                    b_input_condition cond)
{
  struct im_connection *ic = data;
  discord_data *dd = ic->proto_data;
  if (dd->state == WS_CONNECTED) {
    GString *buf = g_string_new("");
    if (dd->reconnecting == TRUE) {
      g_string_printf(buf, "{\"d\":{\"token\":\"%s\",\"session_id\":\"%s\",\"seq\":%"G_GUINT64_FORMAT"},\"op\":%d}", dd->token, dd->session_id, dd->seq, OPCODE_RESUME);
    } else {
      g_string_printf(buf, "{\"d\":{\"token\":\"%s\",\"properties\":{\"$referring_domain\":\"\",\"$browser\":\"bitlbee-discord\",\"$device\":\"bitlbee\",\"$referrer\":\"\",\"$os\":\"linux\"},\"compress\":false,\"large_threshold\":250,\"synced_guilds\":[]},\"op\":%d}", dd->token, OPCODE_IDENTIFY);
    }

    discord_ws_send_payload(dd, buf->str, buf->len);
    g_string_free(buf, TRUE);
  } else {
    imcb_error(ic, "Unhandled writable callback.");
  }

  dd->wsid = 0;
  return FALSE;
}

static void discord_ws_callback_on_writable(struct im_connection *ic)
{
  discord_data *dd = ic->proto_data;
  dd->wsid = b_input_add(dd->sslfd, B_EV_IO_WRITE, discord_ws_writable, ic);
}

gboolean discord_ws_keepalive_loop(gpointer data, gint fd,
                                   b_input_condition cond)
{
  struct im_connection *ic = data;
  discord_data *dd = ic->proto_data;

  if (dd->state > WS_CONNECTED && dd->state < WS_CLOSING) {
    GString *buf = g_string_new("");

    if (dd->seq == 0) {
      g_string_printf(buf, "{\"op\":%d,\"d\":null}", OPCODE_HEARTBEAT);
    } else {
      g_string_printf(buf, "{\"op\":%d,\"d\":%"G_GUINT64_FORMAT"}", OPCODE_HEARTBEAT,
                      dd->seq);
    }
    discord_ws_send_payload(dd, buf->str, buf->len);
    dd->heartbeat_timeout_id = b_timeout_add((dd->keepalive_interval - 100),
                                             discord_ws_heartbeat_timeout, ic);
    g_string_free(buf, TRUE);
  } else {
    discord_debug("=== (%s) %s tried to send keepalive in a wrong state: %d\n",
        dd->uname, __func__, dd->state);
  }
  return TRUE;
}

static void discord_ws_reconnect(struct im_connection *ic)
{
  discord_data *dd = ic->proto_data;

  if (dd->state == WS_READY) {
    discord_soft_reconnect(ic);
  } else {
    imc_logout(ic, TRUE);
  }
}

static gboolean discord_ws_in_cb(gpointer data, int source,
                                 b_input_condition cond)
{
  struct im_connection *ic = (struct im_connection *)data;
  discord_data *dd = ic->proto_data;

  if (dd->state == WS_CONNECTING) {
    gchar buf[4096] = "";
    if (ssl_read(dd->ssl, buf, sizeof(buf)) < 1) {
      imcb_error(ic, "Failed to do ssl_read while switching to websocket mode");
      imc_logout(ic, TRUE);
      return FALSE;
    }
    if (g_strrstr_len(buf, 25, "101 Switching") != NULL && \
        g_str_has_suffix(buf, "\r\n\r\n")) {
      dd->state = WS_CONNECTED;
      discord_ws_callback_on_writable(ic);
    } else {
      discord_debug("<<< (%s) %s switching failure. buf:\n%s\n", dd->uname, __func__, buf);
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
    gboolean disconnected;

    if (ssl_read(dd->ssl, &buf, 1) < 1) {
      imcb_error(ic, "Failed to read ws header.");
      discord_ws_reconnect(ic);
      return FALSE;
    }

    if ((buf & 0xf0) != 0x80) {
      imcb_error(ic, "Unexpected websockets header [0x%x], exiting", buf);
      discord_ws_reconnect(ic);
      return FALSE;
    }

    if ((buf & 0x0f) == 8) {
      imcb_log(ic, "Remote host is closing websocket connection");
      if (dd->state == WS_CONNECTED) {
        imcb_log(ic, "Token expired, cleaning up");
        set_setstr(&ic->acc->set, "token_cache", NULL);
        imc_logout(ic, TRUE);
      } else {
        discord_ws_reconnect(ic);
      }
      return FALSE;
    }

    if (ssl_read(dd->ssl, &buf, 1) < 1) {
      imcb_error(ic, "Failed to read first length byte.");
      discord_ws_reconnect(ic);
      return FALSE;
    }
    len = buf & 0x7f;
    mask = (buf & 0x80) != 0;

    if (len == 126) {
      guint16 lbuf;
      if (ssl_read(dd->ssl, (gchar*)&lbuf, 2) < 2) {
        imcb_error(ic, "Failed to read the rest of length (small).");
        discord_ws_reconnect(ic);
        return FALSE;
      }
      len = GUINT16_FROM_BE(lbuf);
    } else if (len == 127) {
      guint64 lbuf;
      if (ssl_read(dd->ssl, (gchar*)&lbuf, 8) < 8) {
        imcb_error(ic, "Failed to read the rest of length (big).");
        discord_ws_reconnect(ic);
        return FALSE;
      }
      len = GUINT64_FROM_BE(lbuf);
    }

    if (mask) {
      if (ssl_read(dd->ssl, (gchar*)mkey, 4) < 4) {
        imcb_error(ic, "Failed to read ws data.");
        discord_ws_reconnect(ic);
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
        imcb_error(ic, "Short-read on ws data.");
        discord_ws_reconnect(ic);
        g_free(rdata);
        return FALSE;
    }

    if (mask) {
      gchar *mdata = discord_ws_mask(mkey, rdata, len);
      disconnected = discord_parse_message(ic, mdata, len);
      g_free(mdata);
    } else {
      disconnected = discord_parse_message(ic, rdata, len);
    }
    g_free(rdata);
    if (disconnected)
      return FALSE;
  }
  if (ssl_pending(dd->ssl)) {
    /* The SSL library empties the TCP buffers completely but may keep some
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

static void discord_ws_remove_event(gint *event)
{
  if (*event > 0) {
    b_event_remove(*event);
    *event = 0;
  }
}

void discord_ws_cleanup(discord_data *dd)
{
  discord_ws_remove_event(&dd->keepalive_loop_id);
  discord_ws_remove_event(&dd->heartbeat_timeout_id);
  discord_ws_remove_event(&dd->status_timeout_id);
  discord_ws_remove_event(&dd->wsid);
  discord_ws_remove_event(&dd->inpa);

  if (dd->ssl != NULL) {
    ssl_disconnect(dd->ssl);
    dd->ssl = NULL;
  }
}

static gboolean discord_ws_status_postponed(status_data *sd, gint fd,
                                            b_input_condition cond)
{
  discord_data *dd = sd->ic->proto_data;
  if (dd->state != WS_READY) {
    return TRUE;
  }

  discord_ws_set_status(sd->ic, sd->status, sd->msg);

  g_free(sd->msg);
  g_free(sd->status);
  g_free(sd);
  dd->status_timeout_id = 0;

  return FALSE;
}

void discord_ws_set_status(struct im_connection *ic, gchar *status,
    gchar *message)
{
  discord_data *dd = ic->proto_data;
  GString *buf = g_string_new("");
  gchar *msg = NULL;
  gchar *stat = NULL;

  if (dd->state != WS_READY) {
    if (dd->status_timeout_id == 0) {
      status_data *sdata = g_new0(status_data, 1);
      sdata->ic = ic;
      sdata->status = g_strdup(status);
      sdata->msg = g_strdup(message);
      dd->status_timeout_id = b_timeout_add(DISCORD_STATUS_TIMEOUT,
        (b_event_handler)discord_ws_status_postponed, sdata);
    }
    return;
  }

  if (message != NULL) {
    msg = discord_escape_string(message);
  }
  if (status != NULL) {
    stat = discord_escape_string(status);
  }

  if (status != NULL) {
    if (message != NULL) { // game and away
      g_string_printf(buf, "{\"op\":%d,\"d\":{\"since\":%llu,\"game\":{\"name\":\"%s\",\"type\":0},\"afk\":true,\"status\":\"%s\"}}", OPCODE_STATUS_UPDATE, ((unsigned long long)time(NULL))*1000, msg, stat);
    } else { // away
      g_string_printf(buf, "{\"op\":%d,\"d\":{\"since\":%llu,\"game\":null,\"afk\":true,\"status\":\"%s\"}}", OPCODE_STATUS_UPDATE, ((unsigned long long)time(NULL))*1000, stat);
    }
  } else {
    char *afk;
    if (set_getbool(&ic->acc->set, "always_afk")) {
      afk = "true";
    } else {
      afk = "false";
    }
    if (message != NULL) { // game
      g_string_printf(buf, "{\"op\":%d,\"d\":{\"since\":null,\"game\":{\"name\":\"%s\",\"type\":0},\"afk\":%s,\"status\":\"online\"}}", OPCODE_STATUS_UPDATE, msg, afk);
    } else { // default
      g_string_printf(buf, "{\"op\":%d,\"d\":{\"since\":null,\"game\":null,\"afk\":%s,\"status\":\"online\"}}", OPCODE_STATUS_UPDATE, afk);
    }
  }

  discord_ws_send_payload(dd, buf->str, buf->len);
  g_string_free(buf, TRUE);
  g_free(msg);
  g_free(stat);
}

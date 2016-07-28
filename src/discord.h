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
#ifndef __DISCORD_H
#define __DISCORD_H

#include <bitlbee/bitlbee.h>

#define DISCORD_HOST "discordapp.com"
#define DEFAULT_KEEPALIVE_INTERVAL 30000
#define DISCORD_MFA_HANDLE "discord_mfa"

typedef enum {
  WS_IDLE,
  WS_CONNECTING,
  WS_CONNECTED,
  WS_READY,
  WS_CLOSING,
} ws_state;

typedef enum {
  CHANNEL_TEXT,
  CHANNEL_VOICE,
  CHANNEL_PRIVATE
} channel_type;

typedef struct _gw_data {
  int wss;
  gchar *addr;
  gchar *path;
} gw_data;

typedef struct _discord_data {
  char     *token;
  char     *id;
  char     *uname;
  gw_data  *gateway;
  GSList   *servers;
  GSList   *pchannels;
  gint     main_loop_id;
  GString  *ws_buf;
  ws_state state;
  gint     keepalive_interval;
  gint     keepalive_loop_id;
  void     *ssl;
  int      sslfd;
  int      inpa;
} discord_data;

typedef struct _server_info {
  char                 *name;
  char                 *id;
  GSList               *users;
  GSList               *channels;
  struct im_connection *ic;
} server_info;

typedef struct _channel_info {
  char                 *id;
  guint64              last_msg;
  union {
    struct {
      struct groupchat     *gc;
      server_info          *sinfo;
    } channel;
    struct {
      char                 *name;
      struct im_connection *ic;
    } handle;
  } to;
  channel_type         type;
} channel_info;

typedef struct _user_info {
  char                 *id;
  char                 *name;
  channel_info         *voice_channel;
  bee_user_t           *user;
} user_info;

#endif //__DISCORD_H

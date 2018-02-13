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

#include <bitlbee.h>

#define DISCORD_HOST "discordapp.com"
#define DEFAULT_KEEPALIVE_INTERVAL 30000
#define DISCORD_MFA_HANDLE "discord_mfa"

typedef enum {
  WS_IDLE,
  WS_CONNECTING,
  WS_CONNECTED,
  WS_ALMOST_READY,
  WS_READY,
  WS_CLOSING,
} ws_state;

typedef enum {
  CHANNEL_TEXT,
  CHANNEL_PRIVATE,
  CHANNEL_VOICE,
  CHANNEL_GROUP_PRIVATE
} channel_type;

typedef enum {
  RELATIONSHIP_NONE,
  RELATIONSHIP_FRIENDS,
  RELATIONSHIP_UNKNOWN,
  RELATIONSHIP_REQUEST_RECEIVED,
  RELATIONSHIP_REQUEST_SENT
} relationship_type;

typedef struct _gw_data {
  int wss;
  gchar *addr;
  gchar *path;
} gw_data;

typedef struct _discord_data {
  char     *token;
  char     *id;
  char     *session_id;
  char     *uname;
  char     *nonce;
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
  guint    wsid;
  guint64  seq;
  guint    pending_sync;
  GSList   *pending_reqs;
  GSList   *pending_events;
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
  guint64              last_read;
  union {
    struct {
      struct groupchat     *gc;
      char                 *name;
      bee_chat_info_t      *bci;
      server_info          *sinfo;
    } channel;
    struct {
      char                 *name;
      struct im_connection *ic;
    } handle;
    struct {
      struct groupchat     *gc;
      char                 *name;
      bee_chat_info_t      *bci;
      GSList               *users;
      struct im_connection *ic;
    } group;
  } to;
  channel_type         type;
  GSList *pinned;
} channel_info;

typedef struct _user_info {
  char                 *id;
  char                 *name;
  channel_info         *voice_channel;
  bee_user_t           *user;
  guint32               flags;
} user_info;

gboolean discord_is_self(struct im_connection *ic, const char *who);

struct groupchat *discord_chat_do_join(struct im_connection *ic,
                                       const char *name,
                                       gboolean is_auto_join);

#endif //__DISCORD_H

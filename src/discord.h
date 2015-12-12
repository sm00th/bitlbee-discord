#ifndef __DISCORD_H
#define __DISCORD_H

#include <bitlbee/bitlbee.h>

#define DISCORD_HOST "discordapp.com"
#define DEFAULT_KEEPALIVE_INTERVAL 30000

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

typedef struct _discord_data {
  char     *token;
  char     *id;
  char     *uname;
  char     *gateway;
  struct libwebsocket_context *lwsctx;
  struct libwebsocket *lws;
  GSList   *servers;
  GSList   *pchannels;
  gint     main_loop_id;
  GString  *ws_buf;
  ws_state state;
  gint     keepalive_interval;
  gint     keepalive_loop_id;
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

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
#include "discord.h"

typedef enum {
  OPCODE_DISPATCH,
  OPCODE_HEARTBEAT,
  OPCODE_IDENTIFY,
  OPCODE_STATUS_UPDATE,
  OPCODE_VOICE_UPDATE,
  OPCODE_VOICE_PING,
  OPCODE_RESUME,
  OPCODE_RECONNECT,
  OPCODE_REQUEST_MEMBERS,
  OPCODE_INVALID_SESSION,
  OPCODE_HELLO,
  OPCODE_HEARTBEAT_ACK,
  OPCODE_REQUEST_SYNC,
  OPCODE_REQUEST_SYNC_PRIVATE_GROUP,
  OPCODE_REQUEST_SYNC_CHANNEL
} discord_opcode;

gboolean discord_ws_keepalive_loop(gpointer data, gint fd,
                                   b_input_condition cond);

int discord_ws_init(struct im_connection *ic, discord_data *dd);
void discord_ws_cleanup(discord_data *dd);
void discord_ws_set_status(struct im_connection *ic, gchar *status,
    gchar *message);
void discord_ws_sync_server(discord_data *dd, const char *id);
void discord_ws_sync_channel(discord_data *dd, const char *guild_id,
                             const char *channel_id, unsigned int members);
void discord_ws_sync_private_group(discord_data *dd, const char *channel_id);

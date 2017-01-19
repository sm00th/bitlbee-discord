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
#include <stdlib.h>
#include <glib.h>

typedef enum {
  SEARCH_UNKNOWN,
  SEARCH_ID,
  SEARCH_NAME,
  SEARCH_NAME_IGNORECASE,
  SEARCH_FNAME,
  SEARCH_IRC_USER_NAME,
  SEARCH_IRC_USER_NAME_IGNORECASE
} search_t;

channel_info *get_channel(discord_data *dd, const char *channel_id,
                          const char *server_id, search_t type);
user_info *get_user(discord_data *dd, const char *uname,
                    const char *server_id, search_t type);
server_info *get_server_by_id(discord_data *dd, const char *server_id);

void free_channel_info(channel_info *cinfo);
void free_discord_data(discord_data *dd);
void free_server_info(server_info *sinfo);
void free_user_info(user_info *uinfo);
void free_gw_data(gw_data *gw);
char *discord_canonize_name(const char *name);
char *discord_escape_string(const char *msg);
void discord_debug(char *format, ...);

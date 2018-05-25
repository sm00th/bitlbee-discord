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
#include <json.h>

typedef enum {
  ACTION_CREATE,
  ACTION_DELETE,
  ACTION_UPDATE
} handler_action;

void discord_handle_message(struct im_connection *ic, json_value *minfo,
                            handler_action action, gboolean use_tstamp);
void discord_handle_channel(struct im_connection *ic, json_value *cinfo,
                            const char *server_id, handler_action action);
/* Returns TRUE if it called iwc_logout() */
gboolean discord_parse_message(struct im_connection *ic, gchar *buf, guint64 size);

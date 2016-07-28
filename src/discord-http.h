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
#include <bitlbee/bitlbee.h>

void discord_http_send_msg(struct im_connection *ic, const char *id,
                           const char *msg);
void discord_http_create_and_send_msg(struct im_connection *ic,
                                      const char *handle, const char *msg);
void discord_http_send_ack(struct im_connection *ic, const char *channel_id,
                           const char *message_id);
void discord_http_get_backlog(struct im_connection *ic,
                              const char *channel_id);
void discord_http_login(account_t *acc);
void discord_http_mfa_auth(struct im_connection *ic, const char *msg);

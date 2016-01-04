# Copyright 2016 Artem Savkov <artem.savkov@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

libdir = $(plugindir)
lib_LTLIBRARIES = discord.la

discord_la_CFLAGS  = \
	$(BITLBEE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(LIBWEBSOCKETS_CFLAGS) \
	-Wall

discord_la_LDFLAGS = \
	-module \
	-avoid-version \
	$(GLIB_LIBS) \
	$(LIBWEBSOCKETS_LIBS)

discord_la_SOURCES = \
	discord.c \
	discord.h \
	discord-handlers.c \
	discord-handlers.h \
	discord-http.c \
	discord-http.h \
	discord-util.c \
	discord-util.h \
	discord-websockets.c \
	discord-websockets.h

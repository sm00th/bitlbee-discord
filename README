Discord protocol plugin for bitlbee.

License
-------
bitlbee-discord plugin is distributed under GPLv2 license.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

Build dependencies
------------------
- bitlbee and headers >= 3.5
  If using distribution version of bitlbee you will need to install the dev
  package, usually bitlbee-dev or bitlbee-devel. If bitlbee was built from
  source don't forget to do `make install-dev`.

- glib2 and headers => 2.32
  The library itself is usually installed as a dependency of bitlbee, headers
  need to be installed separately. In Debian, the package containing them is
  libglib2.0-dev.

- autotools (if building from git)
  A bit of an overkill, but autotools is the build system of choice now, sorry.


Building and Installing
-----------------------
If building from git you will first need to generate autotools configuration
script and related files by executing the following command:

  $ ./autogen.sh

After that (or when building from a tarball) you can build as usual:

  $ ./configure
  $ make
  $ sudo make install

If your bitlbee's plugindir is in non-standard location you can specify it by
calling ./configure with --with-plugindir=/path/to/plugindir option.

You can also use the dockerfile from contrib/docker to build a docker container
containing bitlbee + bitlbee-discord. Use this command to run the container:

  $ docker run -d -v /bitlbee/config:/var/lib/bitlbee -p 6667:6667 --name bitlbee <image>

Usage
-----
Plugin adds 'discord' protocol to bitlbee, add your account as usual:

  > account add discord <email> <password>
  > account discord on

On your first login you might need to authorize bitlbee's ip address
(discord will send you an email with a link) or get a captcha-request. In
latter case you will have to manually set discord login-token to log in:

  > account off discord
  > acc discord set token_cache xxxxxxxx

To get your token you'll have to login with your browser and locate it in
"local storage"

Chrome: Developer Tools -> Application -> Local Storage -> https://discordapp.com -> token
Firefox: Web Developer -> Storage Inspector -> Local Storage -> http://discordapp.com -> token

For more info on captcha issue and any progress on making it less painful see
https://github.com/sm00th/bitlbee-discord/issues/118

You also need to configure discord channels you would like to join/autojoin. To
do that use bitlbee's 'chat list' functionality (`help chat list` and `help
chat add`):
  > chat list discord

This will show you the list of available channel with indexes that can be used
for adding channels.

  > chat add discord !1 #mydiscordchannel
  > chan #mydiscordchannel set auto_join true
  > /join #mydiscordchannel

If you set auto_join to true, next time you reconnect there will be no need to
join the channel manually.

Options
-------
This section describes options available through "account set" bitlbee command
(for help on usage of this command see "help account set").

  - host (type: string; default: "discordapp.com")
    Discord server hostname. Just in case discord changes the hostname or there
    are some alternatives with compatible API.

  - voice_status_notify (type: boolean; default: no)
    This enables text notifications in your control channel about users
    changing/leaving voice channels. Can be noisy on big servers.

  - edit_prefix (type: string; default: "EDIT: ")
    A string that will be prefixed to an edited message to distinguish those
    from normal ones.

  - urlinfo_handle (type: string; default: "urlinfo")
    User handle that will be used to post url expansion info such as title and
    description in groupchats.

  - max_backlog (type: integer; default: 50)
    Maximum number of backlog messages per channel to fetch on connection.
    Unlike twitter implementation in bitlbee this won't dump seen messages.
    Setting this to 0 or negative values disables backlog fetching.

  - send_acks (type: boolean; default: yes)
    By default bitlbee-discord will send an "ack" for every message received,
    thus marking everything as "read" on mobile/webapp. Setting this to false
    will disable all acks from bitlbee-discord.

  - mention_suffix (type: string; default: ":")
    Suffix used in a regex to look for username mentions to automatically
    convert your usual irc-style "nick:" mentions to discord's "<@id>" format.
    So if you type "nick: hello" in bitlbee, it will be displayed as
    "@nick hello" in discord. This can be multicharacter and you can even do OR
    logic here because it is actually used as a part of glib regex. That is
    setting this to "[:,]" will match both "nick:" and "nick,". But beware
    overcomplicating this may lead to bitlbee-discord spending a lot of time
    parsing your outgoing messages. Setting this to "" will disable this
    function.

  - mention_ignorecase (type: boolean; default: off)
    Ignore case when looking for outgoing mentions. This also affects channel
    mentions.

  - incoming_me_translation (type: boolean; default: on)
    This option controls whether bitlbee-discord will translate incoming
    messages that are fully italicized (that is enclosed in '*' characters) to
    '/me' messages.

  - never_offline (type: boolean; default: off)
    Contacts from this account will never appear as offline and will be marked
    away instead.

  - server_prefix_len (type: int; default: 3)
    Prefix channel names with this many characters of server name. If set to 0
    nothing will be prefixed. If set to anything lower than 0 - full server
    name will be prefixed. Assuming we have a channel "general" on "beecord"
    server here is what channel name you are going to get with different
    settings:
      -1 - #beecord.general
       0 - #general
       3 - #bee.general

  - fetch_pinned (type: boolean; default: off)
    Fetch pinned messages on channel join.

  - friendship_mode (type: boolean; default: on)
    With this option enabled, online/offline status is determined by the
    friendship relationship with a user in addition to their actual away
    status, and other users are added to channels.

  - always_afk (type: boolean; default: off)
    When enabled bitlbee-discord would always report client's status as afk.
    This feature is not properly documented in official docs, but it presumably
    can force push notifications to other clients when bitlbee is connected.

  - emoji_urls (type: boolean; default: on)
    Controls whether bitlbee-discord would display an url to emoji image next
    to it's text alias.

  - auto_join (type: boolean; default: off)
    Automatically join all of the server's channels so you don't have to add
    them manually (no "chat add" needed).

  - auto_join_exclude (type: string; default: "")
    Comma-separated list of channel patterns to exclude when auto-joining
    channels. * matches any text, ? matches a single character.  For instance,
    "Foo.*,Bar.A" will exclude all channels from server "Foo" and channel "A"
    from server "Bar".

Debugging
---------
You can enable extra debug output for bitlbee-discord, by setting BITLBEE_DEBUG
environment variable. This will enable bitlbee-discord to print all traffic it
exchanges with discord servers to stdout and there is a lot of it. To get it
on your screen run bitlbee by hand in foreground mode:
  $ BITLBEE_DEBUG=1 bitlbee -nvD
then connect with an irc client as you usually do.

WARNING: there IS sensitive information in this debug output, such as auth
tokens, your plaintext password and, obviously, your incoming and outgoing
messages. Be sure to remove any information you are not willing to share before
posting it anywhere.

If you are experiencing crashes please refer to this page for information on
how to get a meaningful backtrace: https://wiki.bitlbee.org/DebuggingCrashes

Bugs
----
Please report bugs at github: https://github.com/sm00th/bitlbee-discord/issues
For questions, bitlbee-discord breakage demonstrations and chitchat you can
join the following discord server: https://discord.gg/0lUXEAZXmvW3ovUC or ping
trac3r on irc.oftc.net/#bitlbee (irc is preferable).

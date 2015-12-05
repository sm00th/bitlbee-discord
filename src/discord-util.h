#include "discord.h"

gint cmp_chan_id(const channel_info *cinfo, const char *chan_id);
gint cmp_user_id(const user_info *uinfo, const char *user_id);

channel_info *get_channel_by_id(discord_data *dd, const char *channel_id,
                                const char *server_id);
server_info *get_server_by_id(discord_data *dd, const char *server_id);

void free_channel_info(channel_info *cinfo);
void free_discord_data(discord_data *dd);
void free_server_info(server_info *sinfo);
void free_user_info(user_info *uinfo);

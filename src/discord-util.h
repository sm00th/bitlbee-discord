#include "discord.h"

channel_info *get_channel_by_id(discord_data *dd, const char *channel_id,
                                const char *server_id);
user_info *get_user_by_id(discord_data *dd, const char *user_id,
                          const char *server_id);
server_info *get_server_by_id(discord_data *dd, const char *server_id);

void free_channel_info(channel_info *cinfo);
void free_discord_data(discord_data *dd);
void free_server_info(server_info *sinfo);
void free_user_info(user_info *uinfo);

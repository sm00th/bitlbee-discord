#include "discord.h"

gboolean discord_ws_keepalive_loop(gpointer data, gint fd,
                                   b_input_condition cond);

int discord_ws_init(struct im_connection *ic, discord_data *dd);
void discord_ws_cleanup(discord_data *dd);

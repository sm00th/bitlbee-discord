#include "discord.h"

typedef enum {
  ACTION_CREATE,
  ACTION_DELETE,
  ACTION_UPDATE
} handler_action;

void discord_parse_message(struct im_connection *ic);

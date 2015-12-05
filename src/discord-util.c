#include "discord-util.h"

void free_user_info(user_info *uinfo)
{
  g_free(uinfo->name);
  g_free(uinfo->id);
  g_free(uinfo);
}

void free_channel_info(channel_info *cinfo)
{
  g_free(cinfo->id);
  cinfo->id = NULL;

  if (cinfo->is_private) {
    g_free(cinfo->to.user.handle);
  } else {
    imcb_chat_free(cinfo->to.channel.gc);
  }

  g_free(cinfo);
}

void free_server_info(server_info *sinfo)
{
  g_free(sinfo->name);
  g_free(sinfo->id);

  g_slist_free_full(sinfo->channels, (GDestroyNotify)free_channel_info);
  g_slist_free_full(sinfo->users, (GDestroyNotify)free_user_info);

  g_free(sinfo);
}

void free_discord_data(discord_data *dd)
{
  g_slist_free_full(dd->pchannels, (GDestroyNotify)free_channel_info);
  g_slist_free_full(dd->servers, (GDestroyNotify)free_server_info);

  g_free(dd->gateway);
  g_free(dd->token);
  g_free(dd->uname);
  g_free(dd->id);

  g_free(dd);
}

gint cmp_chan_id(const channel_info *cinfo, const char *chan_id)
{
  return g_strcmp0(cinfo->id, chan_id);
}

gint cmp_user_id(const user_info *uinfo, const char *user_id)
{
  return g_strcmp0(uinfo->id, user_id);
}

static gint cmp_server_id(const server_info *sinfo, const char *server_id)
{
  return g_strcmp0(sinfo->id, server_id);
}

server_info *get_server_by_id(discord_data *dd, const char *server_id)
{
  GSList *sl = g_slist_find_custom(dd->servers, server_id,
                                   (GCompareFunc)cmp_server_id);

  return sl == NULL ?  NULL : sl->data;
}

channel_info *get_channel_by_id(discord_data *dd, const char *channel_id,
                                const char *server_id)
{
  GSList *cl = g_slist_find_custom(dd->pchannels, channel_id,
                                   (GCompareFunc)cmp_chan_id);

  if (cl == NULL && server_id != NULL) {
    server_info *sinfo = get_server_by_id(dd, server_id);
    cl = g_slist_find_custom(sinfo->channels, channel_id,
                             (GCompareFunc)cmp_chan_id);
  }

  return cl == NULL ?  NULL : cl->data;
}


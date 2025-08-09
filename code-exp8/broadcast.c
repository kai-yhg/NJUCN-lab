#include "base.h"
#include <stdio.h>

extern ustack_t *instance;

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	// TODO: broadcast packet
	// fprintf(stdout, "TODO: broadcast packet.\n");
	iface_info_t *tmp;
	list_for_each_entry(tmp, &instance->iface_list, list)
	{
		if (tmp != iface)
			iface_send_packet(tmp, packet, len);
	}
}

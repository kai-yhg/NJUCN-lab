#include "mospf_database.h"
#include "ip.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct list_head mospf_db;

void init_mospf_db()
{
	init_list_head(&mospf_db);
}

void print_lsdb()
{
	printf("LSDB:\n路由器网段  子网网段   子网掩码    子网编号    序号\n");
	printf("--------------------------------------\n");
	mospf_db_entry_t *lsas;
	list_for_each_entry(lsas, &mospf_db, list)
	{
		for (int i = 0; i < lsas->nadv; ++i)
		{
			printf(IP_FMT "\t" IP_FMT "\t" IP_FMT "\t" IP_FMT "\t%d\n", HOST_IP_FMT_STR(lsas->rid), HOST_IP_FMT_STR(lsas->array[i].network), HOST_IP_FMT_STR(lsas->array[i].mask), HOST_IP_FMT_STR(lsas->array[i].rid), lsas->seq);
		}
		printf("--------------------------------------\n");
	}
}

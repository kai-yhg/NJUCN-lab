#ifndef __CHECKSUM_H__
#define __CHECKSUM_H__

#include "types.h"

// calculate the checksum of the given buf, providing sum
// as the initial value
static inline u16 checksum(u16 *buf, int nbytes, u32 sum) // 计算 Internet Checksum,传入数据缓冲区地址，数据长度和初始和
{
	for (int i = 0; i < nbytes / 2; i++)
		sum += buf[i];

	if (nbytes % 2)
		sum += ((u8 *)buf)[nbytes - 1];

	while (sum >> 16)
		sum = (sum >> 16) + (sum & 0xffff);

	return (u16)~sum;
}

#endif

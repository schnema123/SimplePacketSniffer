#pragma once

#include <pcap.h>

#include "error.h"

typedef struct
{
    pcap_t *pcap_handle;
} PacketSnifferInfo;


Error_t packet_sniffer_init(PacketSnifferInfo *info);
Error_t packet_sniffer_start(PacketSnifferInfo *info);
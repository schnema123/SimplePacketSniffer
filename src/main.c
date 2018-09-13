#include "packet_sniffer.h"

int main(int argc, char **argv) 
{
    PacketSnifferInfo ps_info;
    packet_sniffer_init(&ps_info);
    packet_sniffer_start(&ps_info);
}
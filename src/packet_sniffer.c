#include <pcap/pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <assert.h>

#include "packet_sniffer.h"
#include "error.h"

typedef struct
{
    uint8_t mac_dest[6];
    uint8_t mac_src[6];
    uint16_t type;
} EthernetPacket;

typedef struct
{
    uint8_t flags[4];
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t ip_src[16];
    uint8_t ip_dest[16];
} Ipv6Packet;

typedef struct
{
    /*  First 4 bits a version
        Second 4 bits are IHL */
    uint8_t version_ihl;

    /* In this case these fields are not so important */
    uint8_t padding[8];

    uint8_t protocol;
} Ipv4Packet;

static_assert(
    offsetof(Ipv4Packet, protocol) == 9, 
    "IPv4 packet declaration not correct.");

typedef struct
{
    uint16_t port_src;
    uint16_t port_dest;

    uint32_t sequence_number;
    uint32_t ackn_number;

    /*  data_offset is the first 3 bits of this uint8_t!
        It is multiplied by 32 bits to give total tcp header length */
    uint8_t data_offset;
} TcpPacket;

uint16_t change_endianess(uint16_t val)
{
    uint16_t tmp = 0;
    tmp |= (val & 0x00FF) << 8;
    tmp |= (val & 0xFF00) >> 8;
    return tmp;
}

void handle_tcp(const uint8_t *buffer, uint32_t buffer_size) 
{
    TcpPacket *tcp_packet = (TcpPacket *) buffer;

    uint8_t data_offset = tcp_packet->data_offset >> 4;
    uint32_t tcp_header_size = data_offset * 4;
    if (buffer_size <= tcp_header_size) {
        printf("TCP packet has no payload.\n");
        return;
    }

    const uint8_t *payload = buffer + tcp_header_size;
    uint32_t payload_size = buffer_size - tcp_header_size;

    printf( "      port_src %d\n" \
            "      port_dest %d\n" \
            "      payload_size %d\n", 
        change_endianess(tcp_packet->port_src), 
        change_endianess(tcp_packet->port_dest),
        payload_size);

    fwrite(payload, 1, payload_size, stdout);
    printf("\n");
}

void handle_ipv6(const uint8_t *buffer, uint32_t buffer_size) 
{
    Ipv6Packet *ipv6_packet = (Ipv6Packet *) buffer;
    switch (ipv6_packet->next_header)
    {
    case 0x06:
        printf("    Packet is tcp. Handling\n");

        size_t ipv6_header_size = sizeof(Ipv6Packet);
        handle_tcp( buffer + ipv6_header_size, 
                    buffer_size - ipv6_header_size);

        break;
    default:
        printf("    Next header %#x is not handled\n", ipv6_packet->next_header);
        break;
    }
}

void handle_ipv4(const uint8_t *buffer, uint32_t buffer_size) 
{
    Ipv4Packet *ipv4_packet = (Ipv4Packet *) buffer;

    uint8_t version = (ipv4_packet->version_ihl & 0xF0) >> 4;
    uint8_t ihl = ipv4_packet->version_ihl & 0x0F;

    assert(version == 4);

    switch (ipv4_packet->protocol)
    {
    case 0x06:
        printf("    Packet is tcp. Handling\n");

        size_t ipv4_header_size = ihl * 4;
        handle_tcp( buffer + ipv4_header_size, 
                    buffer_size - ipv4_header_size);

        break;
    default:
        printf("    Protocol %#x is not handled\n", ipv4_packet->protocol);
        break;
    }
}

void pcap_callback(
    uint8_t *user, 
    const struct pcap_pkthdr *header, 
    const uint8_t *buffer) 
{
    printf( "Captured packet:\n" \
            "  caplen %d\n" \
            "  len %d\n",
            header->caplen, header->len);

    if (header->caplen < header->len) {
        printf("[!] caplen < len!"); /* Increase buffer size */
    }

    EthernetPacket *eth_packet = (EthernetPacket *) buffer;

    uint16_t packet_type_little_endian = change_endianess(eth_packet->type);
    switch (packet_type_little_endian)
    {
    case 0x86DD:
    {
        printf("  Packet is ipv6. Handling\n");

        size_t ethernet_header_size = sizeof(EthernetPacket);
        handle_ipv6(buffer + ethernet_header_size, 
                    header->caplen - ethernet_header_size);

        break;
    }
    case 0x800:
    {
        printf("  Packet is ipv4. Handling\n");

        size_t ethernet_header_size = sizeof(EthernetPacket);
        handle_ipv4(buffer + ethernet_header_size, 
                    header->caplen - ethernet_header_size);

        break;
    }
    default:
        printf("  Packet with type %#x not handled\n", packet_type_little_endian);
        break;
    }
}

Error_t packet_sniffer_init(PacketSnifferInfo *info)
{
    /* Get device to sniff on */
    char err_msg[PCAP_ERRBUF_SIZE];
    char *device = pcap_lookupdev(err_msg);

    info->pcap_handle = pcap_create(device, err_msg);
    if (info->pcap_handle == NULL) {
        return ERROR_PCAP;
    }

    pcap_set_promisc(info->pcap_handle, 1);
    pcap_set_timeout(info->pcap_handle, 1000);
    /* May need to set buffer size */

    if (pcap_activate(info->pcap_handle) != 0) {
        pcap_perror(info->pcap_handle, "pcap");
        return ERROR_PCAP;
    }

    /* Check if interface provides ethernet headers */
    if (pcap_datalink(info->pcap_handle) != DLT_EN10MB) {
        return ERROR_PCAP;
    }

    return ERROR_OK;
}

Error_t packet_sniffer_start(PacketSnifferInfo *info)
{
    if (pcap_loop(info->pcap_handle, -1, &pcap_callback, NULL) != 0) {
        return ERROR_PCAP;
    }

    return ERROR_OK;
}
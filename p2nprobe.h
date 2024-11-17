#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <cstdint>

typedef struct Flow
{
    uint32_t src;
    uint32_t dst;
    uint32_t x1;
    uint16_t x2;
    uint16_t x3;
    uint32_t n_of_packets;
    uint32_t bytes;
    uint32_t first_packet_sysuptime;
    uint32_t last_packet_sysuptime;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t pad;
    uint8_t flags;
    uint8_t protocol = 6;
    uint8_t x4;
    uint16_t x5;
    uint16_t x6;
    uint8_t x7;
    uint8_t x8;
    uint16_t pad2;
} Flow;

typedef struct packet_header
{
    uint16_t v = htons(5);
    uint16_t count = 0;
    uint32_t system_uptime;
    uint32_t seconds;
    uint32_t nanoseconds;
    uint32_t sequence_number; // Flows aleady sent
    uint8_t engine = 0;
    uint8_t engine_id = 0;
    uint16_t samplingInterval; // Empty
} packet_eader;
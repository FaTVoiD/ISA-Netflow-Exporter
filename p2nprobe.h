// Brno University of Technology - Faculty of Information Technology
//                  Author: Michal Belovec
//                   Login: xbelov04
//                    Date: 18.11.2024

#include <pcap.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <string.h>
#include <cstdint>
#include <iostream>
#include <stdbool.h>

#define MAX_BUFFER_SIZE sizeof(packet_header) + 30 * sizeof(flow_t)

using namespace std;

typedef struct flow_t
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
} flow_t;

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
} packet_header;

typedef struct flow_time
{
    struct timeval flow_first_pkt_time;
    struct timeval flow_last_pkt_time;
} flow_time;

typedef struct dynamic_flow_array
{
    flow_t *array = NULL;
    flow_time *time_array = NULL;
    int index = 0;
    long int size = 32;
} *flow_array;
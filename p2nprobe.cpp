#include "p2nprobe.h"

int check_timeout_arg(char *arg);
void array_init(flow_array buffer);
void array_add(flow_array buffer);
void array_delete(flow_array buffer, flow_t flow);
int array_find(flow_array buffer, flow_t find_flow);
int check_flow_equality(flow_t f1, flow_t f2);
void analyze_ip(const u_char *packet, flow_array buffer, flow_t current_flow);
uint32_t compute_time_diff(struct timeval t1, struct timeval t2);

struct timeval program_start_time;
struct timeval program_run_time;
struct timeval current_time;

int main(int argc, char *argv[])
{
    gettimeofday(&program_start_time, NULL);

    int a_arg_index = -1;
    int a_value;
    int i_arg_index = -1;
    int i_value;
    char *file;
    if (argc > 7)
    {
        cout << "ERROR: incorrect arguments! Try \"./p2nprobe --help\"!\n";
        return -1;
    }

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-a") == 0)
        {
            // Found -a the next arg should be the active timeout value
            i++;
            if (i < argc)
            {
                a_arg_index = i;
                if (check_timeout_arg(argv[i]))
                {
                    cout << "Wrong active timeout value!\n";
                    return -1;
                }
            }
            else
            { // Ran out of arguments
                cout << "ERROR: incorrect arguments! Try \"--help\"!\n";
                return -1;
            }
        }
        else if (strcmp(argv[i], "-i") == 0)
        {
            // Found -i the next arg should be the inactive timeout value
            i++;
            if (i < argc)
            {
                i_arg_index = i;
                if (check_timeout_arg(argv[i]))
                {
                    cout << "Wrong inactive timeout value!\n";
                    return -1;
                }
            }
            else
            { // Ran out of arguments
                fprintf(stderr, "ERROR: incorrect arguments! Try \"--help\"!\n");
                return -1;
            }
        }
        // else if ()
        //{
        //}
        else if (strcmp(argv[1], "--help") == 0)
        {
            fprintf(stderr, "Correct usage is as follows: ./p2nprobe <host>:<port> <pcap_file_path> [-a <active_timeout> -i <inactive_timeout>]\nArguments might be in any order.\n");
            return 0;
        }
        else
        { // Found an argument that doesnt match any allowed arguments
            fprintf(stderr, "ERROR: incorrect arguments! Try \"--help\"!\n");
            return -1;
        }
    }

    if (a_arg_index == -1)
    {
        a_value = 60;
    }
    else
    {
        a_value = atoi(argv[a_arg_index]);
    }
    if (i_arg_index == -1)
    {
        i_value = 60;
    }
    else
    {
        i_value = atoi(argv[i_arg_index]);
    }

    struct pcap_pkthdr pcap_header;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

    // Open file
    pcap_t *pcap_handle = pcap_open_offline(file, pcap_error_buffer);
    if (pcap_handle == NULL)
    {
        cout << "Can't open specified PCAP file!\n";
        return -1;
    }

    struct bpf_program filter;
    if (pcap_compile(pcap_handle, &filter, "tcp", 0, 0) == -1)
    {
        cout << "Function call pcap_compile() unsuccessful!\n";
        return -1;
    }

    if (pcap_setfilter(pcap_handle, &filter) == -1)
    {
        cout << "Function call pcap_setfilter() unsuccessful!\n";
        return -1;
    }

    flow_array buffer;
    array_init(buffer);

    struct ether_header *eth_header;
    const u_char *packet;
    flow_t current_flow;
    struct timeval packet_timestamp;
    while ((packet = pcap_next(pcap_handle, &pcap_header)) != NULL)
    {
        eth_header = (struct ether_header *)packet;
        packet_timestamp = pcap_header.ts;
        switch (ntohs(eth_header->ether_type))
        {
        case ETHERTYPE_IP:
            // Getting data from ethernet header
            current_flow.n_of_packets = pcap_header.len - 14;
            current_flow.first_packet_sysuptime = compute_time_diff(packet_timestamp, program_start_time);
            current_flow.last_packet_sysuptime = compute_time_diff(packet_timestamp, program_start_time);
            analyze_ip(packet, buffer, current_flow, packet_timestamp);
            break;
        default:
            continue;
        }
    }
    pcap_close(pcap_handle);
    return 0;
}

int check_timeout_arg(char *arg)
{
    for (int i = 0; i < strlen(arg); i++)
    {
        if (arg[i] > '0' && arg[i] < '9')
        {
            continue;
        }
        else
        {
            return 1;
        }
    }
    return 0;
}

void array_init(flow_array buffer)
{
    buffer->array = (flow_t *)malloc(buffer->size * sizeof(flow_t));
    if (buffer->array == NULL)
    {
        printf("Array initialization unsuccessful!");
        exit(-1);
    }

    buffer->time_array = (flow_time *)malloc(buffer->size * sizeof(flow_time));
    if (buffer->time_array == NULL)
    {
        printf("Time array initialization unsuccessful!");
        exit(-1);
    }
}

void array_add(flow_array buffer, flow_t add_flow, struct timeval packet_time)
{
    int found = array_find(buffer, add_flow);
    // Flow found in array
    if (found != -1)
    {
        buffer->array[found].n_of_packets++;
        buffer->array[found].bytes += add_flow.bytes;
        buffer->array[found].flags |= add_flow.flags;
        buffer->array[found].last_packet_sysuptime = add_flow.last_packet_sysuptime;
        buffer->time_array[found].flow_last_pkt_time = packet_time;
        return;
    }

    // Flow not found in array
    buffer->array[buffer->index] = add_flow;
    buffer->time_array[buffer->index].flow_first_pkt_time = packet_time;
    buffer->time_array[buffer->index].flow_last_pkt_time = packet_time;
    buffer->index++;
    // Check for array fullness
    if (buffer->index == buffer->size)
    {
        buffer->size = 2 * buffer->size;
        buffer->array = (flow_t *)realloc(buffer->array, buffer->size * sizeof(flow_t));
        if (buffer->array == NULL)
        {
            printf("Array realloc unsuccessful!");
            exit(-1);
        }

        buffer->time_array = (flow_time *)realloc(buffer->time_array, buffer->size * sizeof(flow_time));
        if (buffer->array == NULL)
        {
            printf("Time array realloc unsuccessful!");
            exit(-1);
        }
    }
}

void array_delete(flow_array buffer, flow_t delete_flow)
{
    flow_t empty_flow;
    struct timeval empty_time;
    for (int i = 0; i < buffer->index; i++)
    {
        if (check_flow_equality(buffer->array[i], delete_flow))
        {
            for (int j = i; j < buffer->index; j++)
            {
                if (j + 1 < buffer->index)
                {
                    buffer->array[j] = buffer->array[j + 1];
                    buffer->time_array[j] = buffer->time_array[j + 1];
                }
                else
                {
                    buffer->array[j] = empty_flow;
                    buffer->time_array[j].flow_first_pkt_time = empty_time;
                    buffer->time_array[j].flow_last_pkt_time = empty_time;
                }
            }
            buffer->index--;
            return;
        }
    }
}

int array_find(flow_array buffer, flow_t find_flow)
{
    for (int i = 0; i < buffer->index; i++)
    {
        if (check_flow_equality(buffer->array[i], find_flow))
        {
            return i;
        }
    }
    return -1;
}

int check_flow_equality(flow_t f1, flow_t f2)
{
    if (f1.src == f2.src && f1.dst == f2.dst && f1.src_port == f2.src_port && f1.dst_port == f2.dst_port)
    {
        return 1;
    }
    return 0;
}

void analyze_ip(const u_char *packet, flow_array buffer, flow_t current_flow, struct timeval packet_timestamp)
{
    struct ip *ip_header = (struct ip)packet + 14;
    // Getting data from IP header
    current_flow.src = ip_header.ip_src.s_addr;
    current_flow.dst = ip_header.ip_dst.s_addr;
    // Getting data from TCP header
    struct tcphdr *tcp_header = (const struct tcphdr *)packet + 14 + ip_header->ip_hl * 4;
    current_flow.src_port = tcp_header->th_sport;
    current_flow.dst_port = tcp_header->th_dport;
    current_flow.flags = tcp_header->th_flags;

    array_add(buffer, current_flow, packet_timestamp);
}

uint32_t compute_time_diff(struct timeval t1, struct timeval t2)
{
    uint32_t result = ((uint32_t)t1.tv_sec * 1000 + (uint32_t)t1.tv_usec / 1000) - ((uint32_t)t2.tv_sec * 1000 + (uint32_t)t2.tv_usec / 1000);
    return result;
}
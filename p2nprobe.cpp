// Brno University of Technology - Faculty of Information Technology
//                  Author: Michal Belovec
//                   Login: xbelov04
//                    Date: 18.11.2024

#include "p2nprobe.h"

int check_timeout_arg(char *arg);
void array_init(flow_array buffer);
void array_add(flow_array buffer, flow_t *add_flow);
void array_delete(flow_array buffer, flow_t delete_flow);
int array_find(flow_array buffer, flow_t find_flow);
void array_destroy(flow_array buffer);
int check_flow_equality(flow_t f1, flow_t f2);
void analyze_ip(const u_char *packet, flow_array buffer, flow_t *current_flow);
uint32_t compute_time_diff(struct timeval t1, struct timeval t2);
void send_to_collector();
void check_for_timeout(flow_array buffer, uint32_t active_timeout, uint32_t inactive_timeout);

// Time values used in program
struct timeval program_start_time;
struct timeval current_time;
struct timeval last_packet_time;

// Variables used for sending data
uint32_t flows_sent = 0;
uint8_t expired_flows_buffer[MAX_BUFFER_SIZE];
uint16_t flows_in_buffer = 0;
packet_header send_header;

// Variables needed to send data to collector
int sockfd;
int serverlen;
struct sockaddr_in serveraddr;
struct hostent *server;

int main(int argc, char *argv[])
{
    // Get program start time
    gettimeofday(&program_start_time, NULL);

    // Integers to stoje argument indexes and timeout values
    int a_arg_index = -1;
    int a_value;
    int i_arg_index = -1;
    int i_value;

    // Variables for storing argument values
    char *file, *host, *port;

    // Booleans to check if file and host/port arguments were specified
    bool file_found = false;
    bool host_port_found = false;

    // Loop for processing arguments
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
                cout << "ERROR: incorrect arguments! Try \"--help\"!\n";
                return -1;
            }
        }
        else if (strcmp(argv[1], "--help") == 0)
        {
            cout << "Correct usage is as follows: ./p2nprobe <host>:<port> <pcap_file_path> [-a <active_timeout> -i <inactive_timeout>]\nArguments might be in any order.\nArguments with '<>' are mandatory, while with '[]' are optional.\n";
            return 0;
        }
        else if (string(argv[i]).find(":") != string::npos)
        {
            // Found ':'
            if (host_port_found == false)
            {
                // Inspired by: https://www.geeksforgeeks.org/how-to-split-a-string-in-cc-python-and-java/
                //----------------------------------------------------------------------------------------
                host = strtok(argv[i], ":"); // IP address or domain of the collector
                port = strtok(NULL, ":");    // port of the collector
                host_port_found = true;
                //----------------------------------------------------------------------------------------
            }
            else
            {
                cout << "Multiple hostnames/ports defined!\n";
                return -1;
            }
        }
        else if (string(argv[i]).find(".pcap") != string::npos)
        {
            // Found '.pcap'
            if (file_found == false)
            {
                file = argv[i];
                file_found = true;
            }
            else
            {
                cout << "Multiple files defined!\n";
                return -1;
            }
        }
        else
        {
            cout << "ERROR: incorrect arguments! Try \"--help\"!\n";
            return -1;
        }
    }

    int portnum;
    // Checking for mandatory arguments
    if (!host_port_found || !file_found)
    {
        if (!host_port_found)
        {
            cout << "Hostname and port not specified!\n";
            return -1;
        }
        else
        {
            cout << "PCAP file path not specified!\n";
            return -1;
        }
    }
    else
    {
        portnum = atoi(port);
        if (portnum <= 0 || portnum > 65535)
        {
            cout << "Invalid port number specified!\n";
            return -1;
        }
    }

    // Inspired by: https://www.cs.cmu.edu/afs/cs/academic/class/15213-f99/www/class26/udpclient.c
    //--------------------------------------------------------------------------------------------
    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        cout << "Function call socket() failed!\n";
        return -1;
    }

    // Get IP adress from hostname
    if ((server = gethostbyname(host)) == NULL)
    {
        cout << "Function call gethostbyname() failed!\n";
        return -1;
    }

    // Set required variables for sending packets to collector
    bzero((char *)&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portnum);
    serverlen = sizeof(serveraddr);
    //--------------------------------------------------------------------------------------------

    // Checking if timout values were specified in arguments
    if (a_arg_index == -1)
    {
        a_value = 60;
    }
    else
    {
        a_value = atoi(argv[a_arg_index]);
        if (a_value <= 0)
        {
            cout << "Incorrect timeout value!\n";
            return -1;
        }
    }
    if (i_arg_index == -1)
    {
        i_value = 60;
    }
    else
    {
        i_value = atoi(argv[i_arg_index]);
        if (i_value <= 0)
        {
            cout << "Incorrect timeout value!\n";
            return -1;
        }
    }

    struct pcap_pkthdr pcap_header;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

    // Inspired by: https://moodle.vut.cz/course/view.php?id=280945
    // Author: (c) Petr Matousek, 2020
    //------------------------------------------------------------------------------------------------------
    // Open .pcap file
    pcap_t *pcap_handle = pcap_open_offline(file, pcap_error_buffer);
    if (pcap_handle == NULL)
    {
        cout << "Can't open specified PCAP file!\n";
        return -1;
    }

    // Install "tcp" filter so we can ignore the other packets
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

    // Create dynamic array for storing active flows
    flow_array active_flows_buffer = (flow_array)malloc(sizeof(struct dynamic_flow_array));
    if (active_flows_buffer == NULL)
    {
        cout << "Failed to allocate memory for buffer!";
        return -1;
    }
    array_init(active_flows_buffer);

    struct ether_header *eth_header;
    const u_char *packet;
    flow_t current_flow;

    // Loop for reading packets from the file
    while ((packet = pcap_next(pcap_handle, &pcap_header)) != NULL)
    {
        // Retype packet to read from ethernet header
        eth_header = (struct ether_header *)packet;

        // Update last packet time
        last_packet_time = pcap_header.ts;

        // Check stored flows for timeout
        check_for_timeout(active_flows_buffer, (uint32_t)a_value * 1000, (uint32_t)i_value * 1000);
        switch (ntohs(eth_header->ether_type))
        {
        case ETHERTYPE_IP:
            // Getting data from ethernet header
            current_flow.n_of_packets = 1;
            current_flow.bytes = pcap_header.len - 14;
            current_flow.first_packet_sysuptime = compute_time_diff(last_packet_time, program_start_time);
            current_flow.last_packet_sysuptime = compute_time_diff(last_packet_time, program_start_time);
            analyze_ip(packet + 14, active_flows_buffer, &current_flow);
            break;
        default:
            continue;
        }
    }
    //------------------------------------------------------------------------------------------------------
    array_destroy(active_flows_buffer);
    pcap_close(pcap_handle);
    close(sockfd);
    return 0;
}

/* Checks if characters in timeout argument are only numbers.
 */
int check_timeout_arg(char *arg)
{
    for (int i = 0; i < (int)strlen(arg); i++)
    {
        if (arg[i] >= '0' && arg[i] <= '9')
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

/**
 * @brief Initializing buffer, allocating memory for arrays.
 *
 * @param buffer Buffer to be initialized.
 */
void array_init(flow_array buffer)
{
    // Allocate memory for flow array
    buffer->array = (flow_t *)malloc(buffer->size * sizeof(flow_t));
    if (buffer->array == NULL)
    {
        printf("Array initialization unsuccessful!");
        exit(-1);
    }
    // Allocate memory for flow time array
    buffer->time_array = (flow_time *)malloc(buffer->size * sizeof(flow_time));
    if (buffer->time_array == NULL)
    {
        printf("Time array initialization unsuccessful!");
        exit(-1);
    }
}

/**
 * @brief Stores flow data from add_flow into the buffer.
 *
 * @param buffer Buffer containing active flows.
 * @param add_flow Flow to be stored in the buffer.
 */
void array_add(flow_array buffer, flow_t *add_flow)
{
    // Try finding flow in buffer
    int found = array_find(buffer, (*add_flow));
    // Flow found in array, update values of existing flow
    if (found != -1)
    {
        buffer->array[found].n_of_packets++;
        buffer->array[found].bytes += add_flow->bytes;
        buffer->array[found].flags |= add_flow->flags;
        buffer->array[found].last_packet_sysuptime = add_flow->last_packet_sysuptime;
        buffer->time_array[found].flow_last_pkt_time = last_packet_time;
        return;
    }
    // Flow not found in array, create new flow
    buffer->array[buffer->index] = (*add_flow);
    buffer->time_array[buffer->index].flow_first_pkt_time = last_packet_time;
    buffer->time_array[buffer->index].flow_last_pkt_time = last_packet_time;
    buffer->index++;
    // Check for array fullness
    if (buffer->index == buffer->size)
    {
        // If full, allocate more space
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

/**
 * @brief Deletes Flow from buffer specified in delete_flow.
 *
 * @param buffer Buffer containing stored flows.
 * @param delete_flow Flow to be deleted.
 */
void array_delete(flow_array buffer, flow_t delete_flow)
{
    flow_t empty_flow;
    struct timeval empty_time;
    // Loop through stored flows
    for (int i = 0; i < buffer->index; i++)
    {
        // Check if the flow is the on to be deleted
        if (check_flow_equality(buffer->array[i], delete_flow))
        {
            // Edit flow data to network bit order
            buffer->array[i].n_of_packets = htonl(buffer->array[i].n_of_packets);
            buffer->array[i].bytes = htonl(buffer->array[i].bytes);
            buffer->array[i].first_packet_sysuptime = htonl(buffer->array[i].first_packet_sysuptime);
            buffer->array[i].last_packet_sysuptime = htonl(buffer->array[i].last_packet_sysuptime);

            // Copy into expider flows buffer
            memcpy(expired_flows_buffer + sizeof(packet_header) + flows_in_buffer * sizeof(flow_t), &(buffer->array[i]), sizeof(flow_t));
            flows_in_buffer++;

            // Shift buffer
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

            if (flows_in_buffer == 30)
            {
                send_to_collector();
            }
            return;
        }
    }
}

/* @brief array_find() tries to find flow in the active flows buffer. If found returns the index of the flow in the buffer.
 *
 * @param buffer Buffer containing active flows.
 * @param find_flow Flow which we are trying to find.
 */
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

/* @brief array_destroy() empties the active flows buffer, exports the flows and frees the allocated memory.
 *
 * @param buffer Buffer containing active flows which did not time out.
 */
void array_destroy(flow_array buffer)
{
    flow_t empty_flow;
    struct timeval empty_time;
    while (buffer->index != 0)
    {

        // Edit flow data to network bit order
        buffer->array[0].n_of_packets = htonl(buffer->array[0].n_of_packets);
        buffer->array[0].bytes = htonl(buffer->array[0].bytes);
        buffer->array[0].first_packet_sysuptime = htonl(buffer->array[0].first_packet_sysuptime);
        buffer->array[0].last_packet_sysuptime = htonl(buffer->array[0].last_packet_sysuptime);

        // Copy into expider flows buffer
        memcpy(expired_flows_buffer + sizeof(packet_header) + flows_in_buffer * sizeof(flow_t), &(buffer->array[0]), sizeof(flow_t));
        flows_in_buffer++;

        // Shift buffer
        for (int j = 0; j < buffer->index; j++)
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

        if (flows_in_buffer == 30)
        {
            send_to_collector();
        }
    }
    // Send last flows
    if (flows_in_buffer != 0)
    {
        send_to_collector();
    }
    free(buffer->array);
    free(buffer->time_array);
    free(buffer);
}

/* @brief Compares two flows based on their key attributes (src_ip:src_port - dst_ip:dst_port).
 *
 */
int check_flow_equality(flow_t f1, flow_t f2)
{
    if (f1.src == f2.src && f1.dst == f2.dst && f1.src_port == f2.src_port && f1.dst_port == f2.dst_port)
    {
        return 1;
    }
    return 0;
}

/* @brief analyze_ip() extracts data from IP and TCP headers and saves them into the newly created flow.
 *
 * @param packet The packet that is being currently processed.
 * @param buffer Buffer containing currently active flows.
 * @param current_flow Newly created flow with previosly extracted data from ethernet header.
 */
void analyze_ip(const u_char *packet, flow_array buffer, flow_t *current_flow)
{
    struct ip *ip_header = (struct ip *)packet;
    // Getting data from IP header
    current_flow->src = ip_header->ip_src.s_addr;
    current_flow->dst = ip_header->ip_dst.s_addr;
    // Getting data from TCP header
    packet = packet + ip_header->ip_hl * 4;
    const struct tcphdr *tcp_header = (const struct tcphdr *)packet;
    current_flow->src_port = tcp_header->th_sport;
    current_flow->dst_port = tcp_header->th_dport;
    current_flow->flags = tcp_header->th_flags;
    array_add(buffer, current_flow);
}

/* @brief compute_time_diff() computes the time difference between two timeval type variables.
 * @return Time difference converted to uint32_t.
 */
uint32_t compute_time_diff(struct timeval t1, struct timeval t2)
{
    uint32_t result = ((uint32_t)t1.tv_sec * 1000 + (uint32_t)t1.tv_usec / 1000) - ((uint32_t)t2.tv_sec * 1000 + (uint32_t)t2.tv_usec / 1000);
    return result;
}

/**
 * @brief Sends expired flows to the collector.
 *
 */
void send_to_collector()
{
    // Update current time used in the packet header
    gettimeofday(&current_time, NULL);
    send_header.system_uptime = htonl(compute_time_diff(current_time, program_start_time));
    send_header.seconds = htonl(current_time.tv_sec);
    // Converting microseconds to nanoseconds by multiplying with 1000
    send_header.nanoseconds = htonl(current_time.tv_usec * 1000);
    send_header.count = htons(flows_in_buffer);
    send_header.sequence_number = htonl(flows_sent);

    // Update sent flows counter
    flows_sent += flows_in_buffer;

    // Copy header data into buffer
    memcpy(expired_flows_buffer, &send_header, sizeof(packet_header));

    // Send packet to collector
    if (sendto(sockfd, expired_flows_buffer, sizeof(packet_header) + flows_in_buffer * sizeof(flow_t), 0, (struct sockaddr *)&serveraddr, serverlen) < 0)
    {
        printf("Failed to send data to collector!\n");
        exit(-1);
    }

    // Reset buffer
    flows_in_buffer = 0;
    bzero(expired_flows_buffer, sizeof(expired_flows_buffer));
}

/**
 * @brief Iterates through flows stored in buffer and checks active and inactive timeout values.
 *
 * @param buffer Buffer containing flows being checked for timeouts.
 * @param active_timeout Active timeout value in seconds.
 * @param inactive_timeout Inactive timeout value in seconds.
 */
void check_for_timeout(flow_array buffer, uint32_t active_timeout, uint32_t inactive_timeout)
{
    uint32_t last_packet_time_converted = (uint32_t)last_packet_time.tv_sec * 1000 + (uint32_t)last_packet_time.tv_usec / 1000;
    uint32_t flow_time_converted;
    for (int i = 0; i < buffer->index; i++)
    {
        // Active timeout check
        flow_time_converted = (uint32_t)buffer->time_array[i].flow_first_pkt_time.tv_sec * 1000 + (uint32_t)buffer->time_array[i].flow_first_pkt_time.tv_usec / 1000;
        if (active_timeout <= last_packet_time_converted - flow_time_converted)
        {
            array_delete(buffer, buffer->array[i]);
            continue;
        }

        // Inactive timeout check
        flow_time_converted = (uint32_t)buffer->time_array[i].flow_last_pkt_time.tv_sec * 1000 + (uint32_t)buffer->time_array[i].flow_last_pkt_time.tv_usec / 1000;
        if (inactive_timeout <= last_packet_time_converted - flow_time_converted)
        {
            array_delete(buffer, buffer->array[i]);
        }
    }
}
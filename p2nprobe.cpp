#include "p2nprobe.h"

int check_timeout_arg(char *arg);

void array_init(flow_array buffer);
void array_add(flow_array buffer);
void array_delete(flow_array buffer, flow_t flow);
int check_flow_equality(flow_t f1, flow_t f2);

int main(int argc, char *argv[])
{
    int a_arg_index = -1;
    int a_value;
    int i_arg_index = -1;
    int i_value;
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
        else if ()
        {
        }
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

    const u_char *packet;
    while ((packet = pcap_next(pcap_handle, &pcap_header)) != NULL)
    {
    }

    pcap_close(pcap_handle);
    return 0;
}

int check_timeout_arg(char *arg)
{
    for (int i = 0; i < strlen(arg); i++)
    {
        if (arg[i] > "0" && arg[i] < "9")
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
    buffer->array = (flow_t)malloc(buffer->size * sizeof(struct flow_t));
    if (buffer->array == NULL)
    {
        printf("Array initialization unsuccessful!");
        exit(-1);
    }
}

void array_add(flow_array buffer, flow_t add_flow)
{
    buffer->array[index] = add_flow;
    index++;

    // Check for array fullness
    if (index == size)
    {
        size = 2 * size;
        buffer->array = (flow_t)realloc(buffer->array, buffer->size * sizeof(struct flow_t));
        if (buffer->array == NULL)
        {
            printf("Array realloc unsuccessful!");
            exit(-1);
        }
    }
}

void array_delete(flow_array buffer, flow_t delete_flow)
{
    flow_t empty_flow;
    for (int i = 0; i < buffer->index; i++)
    {
        if (check_flow_equality(buffer->array[i], delete_flow))
        {
            for (int j = i; j < buffer->index; j++)
            {
                if (j + 1 < buffer->index)
                {
                    buffer->array[j] = buffer->array[j + 1];
                }
                else
                {
                    buffer->array[j] = empty_flow;
                }
            }
            buffer->index--;
            return;
        }
    }
}

int check_flow_equality(flow_t f1, flow_t f2)
{
    if (f1.src == f2.src && f1.dst == f2.dst && f1.src_port == f2.src_port && f1.dst_port == f2.dst_port)
    {
        return 1;
    }
    return 0;
}
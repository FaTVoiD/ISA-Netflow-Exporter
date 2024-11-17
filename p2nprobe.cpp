#include "p2nprobe.h"

int check_timeout_arg(char *arg);

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

    struct pcap_pkthdr header;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];

    // Open file
    pcap_t *handle = pcap_open_offline(file, pcap_error_buffer);
    if (handle == NULL)
    {
        cout << "Can't open specified PCAP file!\n";
        return -1;
    }

    const u_char *packet;
    while ((packet = pcap_next(handle, &header)) != NULL)
    {
    }

    pcap_close(handle);
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
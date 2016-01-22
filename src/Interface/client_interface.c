#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <math.h>

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        printf("Usage : '-g file_name' to get file\n \
       '-u file_name' to upload a file\n \
       '-l' to get the list of all files\n");
        return 1;
    }
    /* GetOpt */
    int list_flag = 0;
    char *get_value = NULL;
    char *upl_value = NULL;

    int index;
    int c;

    opterr = 0;

    while ((c = getopt (argc, argv, "lu:g:")) != -1)
        switch (c)
        {
            case 'g':
                get_value = optarg;
                break;
            case 'l':
                list_flag = 1;
                break;
            case 'u':
                upl_value = optarg;
                break;
            case '?':
                if (optopt == 'c')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr,
                            "Unknown option character `\\x%x'.\n",
                            optopt);
                return 1;
            default:
                abort ();
        }
    for (index = optind; index < argc; index++)
        printf ("Non-option argument %s\n", argv[index]);
    /* End GetOpt */


    int socket_desc;
    struct sockaddr_in server;
     
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
         
    /* Put the proxy address there */
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(4242);
 
    //Connect to remote server
    if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        puts("connect error");
        return 1;
    }
     
    puts("Connected\n");
     
    size_t message_length = 0;
    uint8_t *message;
    if (get_value != NULL)
    {
        /* Get a file */
        printf("Get file : %s\n", get_value);
        size_t filename_len = strlen(get_value);
        size_t static_size = 4;
        message_length = static_size + filename_len;
        message = malloc(message_length * sizeof (uint8_t));

        message[0] = 1; // Set version
        message[1] = 4; // Set message type

        message[2] = (uint8_t)(filename_len / 256);
        message[3] = filename_len - message[2];

        memcpy(message + static_size, get_value, filename_len);
        for (size_t i = 0; i < message_length; i++)
            printf("%d\n", message[i]);
    }
    else if (list_flag == 1)
    {
        /* List files */
        message_length = 2;
        message = malloc(message_length * sizeof(uint8_t));

        message[0] = 1;
        message[1] = 2;

        printf("List files\n");
    }
    else if (upl_value != NULL)
    {
        /* Upload a file */
        printf("Upload file : %s\n", upl_value);
        /* Reading content of file */
        FILE *fp;
        size_t file_size;
        char *buffer_file;
        int errnum;
        size_t static_size = 13;

        fp = fopen (upl_value, "rb");
        if (fp == NULL)
        {
            /* Handle error case */
            errnum = errno;
            printf("error code: %d\n", errnum);
            return 0;
        }

        fseek( fp , 0L , SEEK_END);
        file_size = ftell(fp);
        rewind(fp);

        /* Debug logs */
        printf("Size of uploaded file : %zu\n", file_size);
        /* End debug logs */


        buffer_file = calloc(1, file_size + 1);
        fread(buffer_file, file_size, 1 , fp);

        /* End reading content of file */

        message_length = file_size + static_size;
        message = malloc(message_length * sizeof (uint8_t));

        message[0] = 1; // Set version
        message[1] = 5; // Set message type
        message[2] = 0; // Set status code, it is 0 since fp != null
        message[3] = 0; // Digest not handled yet 

        
        /* Size of file on 64 bits */
        int power = 64 - 8;
        message[4] = file_size / pow(2, power);
        for (int i = 5; i < 11; i++) 
        {
            message[i] = (file_size - message[i - 1]) / pow(2, power);
            power -= 8;
        }
        message[11] = file_size - message[10];

        /* Copying file content to buffer which will be send in the socket */
        memcpy(message + static_size - 1, buffer_file, file_size); 

        /* Digest value set to 0. Not implemented yet. */
        message[file_size + static_size] = 0;

        /* Debug logs */
        printf("Buffer_file = %s\n", buffer_file);
        printf("Message length = %zu\n", message_length);
        for (size_t i = 0; i < file_size + static_size; i++)
            printf("%zu: %d\n", i, message[i]);
        /* End debug logs */

        fclose(fp);
        free(buffer_file);
    }

    if( send(socket_desc , message , message_length, 0) < 0)
    {
        puts("Send failed");
        return 1;
    }

    return 0;
}


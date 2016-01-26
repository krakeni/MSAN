#include <sys/socket.h>
#include <sys/types.h>
#include <inttypes.h>
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

#include "../include/lib.h"

#define DEBUG 1
#ifdef DEBUG
# define DEBUG_PRINT(x) printf x
#else
# define DEBUG_PRINT(x) do {} while (0)
#endif


char *FRONT_ADDRESS = "127.0.0.1";
int FRONT_PORT = 4242;

void option_help()
{
    printf("Usage : '-g file_name' to get file\n \
   '-u file_name' to upload a file\n \
   '-l' to get the list of all files\n");
}

int send_socket(int socket_desc, uint8_t *message, long long message_length)
{
    if( send(socket_desc , message , message_length, 0) < 0)
    {
        puts("Send failed");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
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

    if (argc == 1 || (argc > 1 && (get_value == NULL && upl_value == NULL && list_flag == 0)))
    {
        option_help();
        return 1;
    }

    /* End GetOpt */


    /* Socket */

    int socket_desc;
    struct sockaddr_in server;
     
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        DEBUG_PRINT(("Could not create socket"));
    }
         
    /* Put the proxy address there */
    server.sin_addr.s_addr = inet_addr(FRONT_ADDRESS);
    server.sin_family = AF_INET;
    server.sin_port = htons(FRONT_PORT);
 
    //Connect to remote server
    if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        puts("connect error");
        return 1;
    }
     
    puts("Connected\n");

    /* End Socket */
     
    long long  message_length = 0;
    if (get_value != NULL)
    {
        /* Get a file */
        DEBUG_PRINT(("Get file : %s\n", get_value));
        size_t filename_len = strlen(get_value);
        size_t static_message_size = 4;
        message_length = static_message_size + filename_len;
        uint8_t message[message_length];

        message[0] = 1; // Set version
        message[1] = 4; // Set message type

        message[2] = (uint8_t)(filename_len / 256);
        message[3] = filename_len - message[2];

        memcpy(message + static_message_size, get_value, filename_len);
        for (size_t i = 0; i < (size_t)message_length; i++)
            DEBUG_PRINT(("%d\n", message[i]));
        return send_socket(socket_desc, message, message_length);
    }
    else if (list_flag == 1)
    {
        /* List files */
        message_length = 2;
        uint8_t message[2];
        message[0] = 1;
        message[1] = 2;

        DEBUG_PRINT(("List files\n"));
        return send_socket(socket_desc, message, message_length);
    }
    else if (upl_value != NULL)
    {
        /* Upload a file */

        DEBUG_PRINT(("Upload file : %s\n", upl_value));
        /* Reading content of file */
        uint8_t version = 1;
        uint8_t msg_type = 9;
        uint8_t status_code = 0;
        rush_digest_type digest_type = rush_digest_type_sha256;
        long long content_len;
        char *content;
        char *digest_value;
        int errnum;
        FILE *fp;

        /* Size of the message without Content, digest value and filename which are variable */
        size_t static_message_size = 14;



        fp = fopen (upl_value, "rb");
        /* Handle errors when opening file */
        if (fp == NULL)
        {
            /* Handle error case */
            errnum = errno;
            if (errnum > 0)
            {
                fprintf(stderr, "Can't access the file.\n Errno : %d", errnum);
                return errnum;
            }
            fprintf(stderr, "Can't access the file");
            return 1;
        }

        fseek(fp , 0L , SEEK_END);
        content_len = ftell(fp);
        rewind(fp);

        DEBUG_PRINT(("Size of uploaded file : %llu\n", content_len));


        content = calloc(1, content_len + 1);
        fread(content, content_len, 1 , fp);
        fclose(fp);
        /* End reading content of file */

        size_t digest_len = rush_digest_type_to_size(digest_type) * 2;
        digest_value = malloc((int) digest_len * sizeof(char));
        int digest_value_pos_in_buffer = 12 + content_len;
        get_hash_sha256(upl_value, digest_value);

        /* Parse filename */

        char filename_final[255];

        char *filename = strtok(upl_value, "/");

        while (filename != NULL)
        {
            printf("%s\n", filename);
            strcpy(filename_final, filename);
            filename = strtok(NULL, "/");
        }
        
        /* Copying file content to buffer which will be send in the socket */

        uint16_t filename_len = strlen(filename_final);
        message_length = content_len + static_message_size + digest_len + filename_len;

        uint8_t message[message_length];

        message[0] = version; 
        message[1] = msg_type; 
        message[2] = status_code; 
        message[3] = digest_type; 

        /* Content length parse */
        /* Size of file on 64 bits */

        int power = 64 - 8;
        message[4] = (uint8_t) (content_len / pow(2, power));
        long long current_size = content_len;

        for (int i = 5; i < 11; i++) 
        {
            power -= 8;
            if (message[i - 1] == 0)
                message[i] = (content_len / pow(2, power));
            else
            {
                current_size = current_size - (message[i - 1] * pow(2, power + 8));
                message[i] = current_size/pow(2, power);
            }

        }

        message[11] = content_len - (message[10] * 256);

        /* Copying in buffer */
        memcpy(message + 12, content, content_len);

        memcpy(message + digest_value_pos_in_buffer, digest_value, digest_len);

        message[digest_value_pos_in_buffer + digest_len] = filename_len / 256;

        message[digest_value_pos_in_buffer + digest_len + 1] = filename_len - 
            (message[content_len + static_message_size] * 256);

        memcpy(message + digest_value_pos_in_buffer + digest_len + 2, filename_final, filename_len);

        DEBUG_PRINT(("Message length = %llu\n", message_length));
        for (int i = 0; i < message_length; i++)
            DEBUG_PRINT(("byte %d :  %"PRIu8"\n", i, message[i]));


        free(content);
        return send_socket(socket_desc, message, message_length);
    }
    return 0;
}


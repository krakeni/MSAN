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
     
    long long  message_length = 0;
//    uint8_t *message;
    if (get_value != NULL)
    {
        /* Get a file */
        printf("Get file : %s\n", get_value);
        size_t filename_len = strlen(get_value);
        size_t static_size = 4;
        message_length = static_size + filename_len;
        uint8_t message[message_length];

        message[0] = 1; // Set version
        message[1] = 4; // Set message type

        message[2] = (uint8_t)(filename_len / 256);
        message[3] = filename_len - message[2];

        memcpy(message + static_size, get_value, filename_len);
        for (size_t i = 0; i < (size_t)message_length; i++)
            printf("%d\n", message[i]);
        return send_socket(socket_desc, message, message_length);
    }
    else if (list_flag == 1)
    {
        /* List files */
        message_length = 2;
        uint8_t message[2];
        message[0] = 1;
        message[1] = 2;

        printf("List files\n");
        return send_socket(socket_desc, message, message_length);
    }
    else if (upl_value != NULL)
    {
        /* Upload a file */
        printf("Upload file : %s\n", upl_value);
        /* Reading content of file */
        FILE *fp;
        long long file_size;
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

        fseek(fp , 0L , SEEK_END);
        file_size = ftell(fp);
        rewind(fp);

        /* Debug logs */
        printf("Size of uploaded file : %llu\n", file_size);
        /* End debug logs */


        buffer_file = calloc(1, file_size + 1);
        fread(buffer_file, file_size, 1 , fp);
        /* End reading content of file */

        message_length = file_size + static_size;
       // message = malloc(message_length * sizeof (uint8_t));
        uint8_t message[message_length];

        message[0] = 1; // Set version
        message[1] = 5; // Set message type
        message[2] = 0; // Set status code, it is 0 since fp != null
<<<<<<< HEAD
        message[3] = 1; // Digest not handled yet

=======
        message[3] = 0; // Digest not handled yet 
        
>>>>>>> d24d7d3ce164e16596352658514d7a3704ee0e58
        /* Size of file on 64 bits */

        int power = 64 - 8;
        message[4] = file_size / pow(2, power);
        long long current_size = file_size;

        for (int i = 5; i < 11; i++) 
        {
            power -= 8;
            if (message[i - 1] == 0)
                message[i] = (file_size / pow(2, power));
            else
            {
                current_size = current_size - (message[i - 1] * pow(2, power + 8));
                message[i] = current_size/pow(2, power);
            }

        }

        message[11] = file_size - (message[10] * 256);
        
        /* Debug logs */
        printf("byte 4: %d\n", message[5]);
        printf("byte 5: %d\n", message[5]);
        printf("byte 6: %d\n", message[6]);
        printf("byte 7: %d\n", message[7]);
        printf("byte 8: %d\n", message[8]);
        printf("byte 9: %d\n", message[9]);
        printf("byte 10: %d\n", message[10]);
        printf("byte 11: %d\n", message[11]);

        printf("Message length = %llu\n", message_length);
        /* End debug logs */

        /* Copying file content to buffer which will be send in the socket */
        memcpy(message + static_size - 1, buffer_file, file_size); 

        /* Digest value set to 0. Not implemented yet. */
        //message[file_size + static_size - 1] = 99;
        //

        uint8_t digest_buffer[20];
        for (int i = 0; i < 20; i++)
            digest_buffer[i] = '1';

        memcpy(message + static_size + file_size - 1, digest_buffer, 20);

        /* Handling type 9 here */

        /* Add filename len */
        printf("TEST : %d\n", file_size + static_size - 1);
        message[file_size + static_size + file_size + 20] = filename_len / 256;
        message[file_size + static_size + 21] = filename_len - 
            (message[file_size + static_size] * 256);

        /* Copying file name */
        memcpy(message + static_size + file_size + 22, filename_final, filename_len);

        /* End handling type 9 */

        for (int i = 0; i < message_length; i++)
            printf("byte %d :  %"PRIu8"\n", i, message[i]);


        fclose(fp);
        free(buffer_file);
        return send_socket(socket_desc, message, message_length);
    }
    return 0;
}


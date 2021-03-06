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


char *FRONT_ADDRESS = "192.168.56.104";
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
  char *front_address = NULL;

  int index;
  int c;

  opterr = 0;

  while ((c = getopt (argc, argv, "lu:g:f:")) != -1)
    switch (c)
    {
      case 'g':
        get_value = optarg;
        break;
      case 'l':
        list_flag = 1;
        break;
      case 'u':
        printf("optarg: %s\n", optarg);
        upl_value = optarg;
//        return upload_file(optarg, FRONT_ADDRESS, 4242);
        break;
      case 'f':
        front_address = optarg;
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

  if (front_address != NULL && upl_value != NULL)
  {
    return upload_file(upl_value, front_address, 4242); 
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

  return 0;
}

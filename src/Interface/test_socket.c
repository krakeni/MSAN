#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

int main()
{
   int socket_desc;
    struct sockaddr_in server;
    uint8_t *message = malloc(100 * sizeof (uint8_t));
     
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
         
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons( 4242 );
 
    //Connect to remote server
    if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        puts("connect error");
        return 1;
    }
     
    puts("Connected\n");
     
    int MESSAGE_LENGTH = 6;
    //Send some data
    message[0] = 1;
    message[1] = 4;
    message[2] = 0;
    message[3] = 2;
    message[4] = 'm';
    message[5] = 'o';
    printf("SIZE : %d\n", MESSAGE_LENGTH);
    if( send(socket_desc , message , MESSAGE_LENGTH, 0) < 0)
    {
        puts("Send failed");
        return 1;
    }
    puts("Data Send\n");
     
    return 0;
}


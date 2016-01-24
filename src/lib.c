#include "../include/lib.h"

void send_mcast_msg(char *databuf, int datalen, uint16_t port, const char* mcast_group)
{
    struct in_addr Local_interface = (struct in_addr) { 0 };
    struct sockaddr_in mcast_sock = (struct sockaddr_in) { 0 };

    int msocket = socket(AF_INET, SOCK_DGRAM, 0);
    memset((char *) &mcast_sock, 0, sizeof(mcast_sock));
    mcast_sock.sin_family = AF_INET;
    mcast_sock.sin_addr.s_addr = inet_addr(mcast_group);
    mcast_sock.sin_port = htons(port);

    Local_interface.s_addr = inet_addr(LOCAL_IFACE);
    if(setsockopt(msocket, IPPROTO_IP, IP_MULTICAST_IF, (char *)&Local_interface, sizeof(Local_interface)) < 0)
    {
        perror("Setting local interface error");
        exit(1);
    }
    if(sendto(msocket, databuf, datalen, 0, (struct sockaddr*)&mcast_sock, sizeof(mcast_sock)) < 0)
    {
        perror("Sending datagram message error");
    }
    close(msocket);
}

void send_mcast_discover(uint16_t port, const char* mcast_group)
{
  char msg[2];
  msg[0] = 1;
  msg[1] = 8;
  send_mcast_msg(&msg, 2, port, mcast_group);
}

int send_ucast_msg(char *address, int port, int socket_desc, uint8_t *message, long long message_length)
{

    int socket_desc;
    struct sockaddr_in server;
     
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
         
    /* Put the proxy address there */
    server.sin_addr.s_addr = inet_addr(address);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
 
    //Connect to remote server
    if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        puts("connect error");
        return 1;
    }
     
    puts("Connected\n");
    if( send(socket_desc , message , message_length, 0) < 0)
    {
        puts("Send failed");
        return 1;
    }
    return 0;
}

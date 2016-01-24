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
  send_mcast_msg(&msg, 2, port, mcast_group);
}

/* Type 1 Params:
 * - port
 *   mcast_group
 *   path
 *   digest_type
 */
void send_mcast_adv_file_msg(uint16_t port, const char* mcast_group, const char* path,
			      const int digest_type)
{
    uint64_t message_length = 0;
    size_t static_size = 12;
    size_t digest_len = rush_digest_type_to_size(digest_type);

    message_length = static_size + name_len + digest_len;
    uint8_t message[message_length];

    message[0] = 1; // version
    message[1] = 1; // type

    printf("Version 1\n");
    printf("Type 1\n");

    const char delim[2] = "/";
    char* filename;
    char* token;
    filename = strtok(path, delim);

    while (token != NULL)
    {
	token = strtok(NULL, delim);
	if (token != NULL)
	    filename = token;
    }

    printf("Filename: %s\n", filename);
    uint16_t name_len = strlen(filename); 

    printf("Filename size: %zu\n", name_len);

    message[2] = name_len >> 8;
    message[3] = name_len;
    printf("%" PRIu8 "%" PRIu8 "\n", message[2], message[3]);
}

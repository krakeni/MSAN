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

/* Type 1 Params:
 * - port
 *   mcast_group
 *   path
 *   digest_type
 */
void send_mcast_adv_file_msg(uint16_t port, const char* mcast_group, char* path,
			      const int digest_type)
{
    uint64_t message_length = 0;
    // static_size = version_sz + type_sz + name_len_sz + content_len_sz + digest_type_sz;
    // static_size = 1 + 1 + 2 + 8 + 1;
    size_t static_size = 13;
    size_t digest_len = rush_digest_type_to_size(digest_type);
    digest_len = 0;

    const char delim[2] = "/";
    char* token = malloc(strlen(path));
    char* filename = NULL;

    if (token != NULL)
    {
	char* tmp = strdup(path);
	token = strtok(tmp, delim);
    }

    while (token != NULL)
    {
    	filename = token;
	token = strtok(NULL, delim);
	if (token != NULL)
	    filename = token;
    }

    printf("Version: 1\nType: 1\n");

    uint16_t name_len = strlen(filename); 

    printf("Filename size: %" PRIu16 "\n", name_len);

    FILE* file = fopen(path, "r");
    if (file != NULL)
    {
	fseek(file, 0, SEEK_END);
    }
    uint64_t content_len = ftell(file);

    printf("File length: %" PRIu64 "\n", content_len);
    printf("Digest type: %d\n", digest_type);
    printf("Filename: %s\n", filename);

    message_length = static_size + name_len + digest_len;
    printf("Message length: %" PRIu64 "\n", message_length);
    uint8_t message[message_length];

    message[0] = 1; // version
    message[1] = 1; // type
    message[2] = name_len >> 8;
    message[3] = name_len;
    
    int shift = 64;
    for (int i = 4; i < 12; i++)
    {
	shift -= 8;
	message[i] = content_len >> shift;
    }

    message[12] = digest_type;

    memcpy(message + static_size, filename, name_len);

    // Digest
    message[static_size + name_len] = 0;

    for (int i = 0; i < message_length; i++)
    {
	printf("message[%d] = %d\n", i, message[i]);
    }

    fclose(file);
    free(token);

int send_ucast_msg(char *address, int port, uint8_t *message, long long message_length)
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

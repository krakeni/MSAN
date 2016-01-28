#include "../include/handlers.h"
#include "../include/rush.h"

void* rush_bind_server_multicast_socket(int * const multicast_socket, int port, char *mcast_group)
{
    struct sockaddr_in localSock = (struct sockaddr_in) { 0 };
    struct ip_mreq group;

    *multicast_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (*multicast_socket < 0)
        perror("Opening datagram socket error");
    int reuse = 1;
    if(setsockopt(*multicast_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0)
        perror("Setting SO_REUSEADDR error");
    memset((char *) &localSock, 0, sizeof(localSock));
    localSock.sin_family = AF_INET;
    localSock.sin_port = htons(port);
    localSock.sin_addr.s_addr = INADDR_ANY;

    if(bind(*multicast_socket, (struct sockaddr*)&localSock, sizeof(localSock)))
        perror("Binding datagram socket error");

    group.imr_multiaddr.s_addr = inet_addr(mcast_group);
    group.imr_interface.s_addr = inet_addr(LOCAL_IFACE);
    if(setsockopt(*multicast_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group)) < 0)
        perror("Adding multicast group error");
    return NULL;
}

void* FE_request_file_content_mcast(/*int const conn_socket, */uint8_t buffer[1024])
{   
    printf("Message type 4 multicast\n");
    uint8_t *data = malloc(2 * sizeof(uint16_t));
    char *filename; 

    uint16_t filename_len;

    data = (uint8_t *)&filename_len;
    memcpy(data, &buffer[2], 2);
    filename = malloc(filename_len + 1);

    memcpy(filename, &buffer[4], filename_len);
    filename[filename_len] = '\0';

    printf("filename : %s\n filename_len : %"PRIu16"\n", filename, filename_len);

    //Send multicast request to frontend type 6
    //Backend advertises the disponibility of a file
    
    uint8_t *buffer_to_send = malloc(4 + filename_len);

    buffer_to_send[0] = 1;
    buffer_to_send[0] = 6;

    memcpy(&buffer_to_send[2], &filename_len, 2);
    memcpy(&buffer_to_send[4], &filename, filename_len);

    //FIXME
    //SEND MCAST TYPE 6 REQUEST TO FRONT 
    return NULL;
}

/* params
uint8_t buffer[1024]
*/
void* FE_advertising_disponibility(uint8_t buf[1024])
{
    printf("Message type 6 multicast\n");
    uint8_t *data = malloc(2 * sizeof(uint16_t));
//    char *filename; 

    uint16_t filename_len;

    data = (uint8_t *)&filename_len;
    memcpy(data, &buf[2], 2);
    return NULL;
}

void* alive_message_handle(void* args)
{
    thread_args* t_args = (thread_args*)args;
    char* address = t_args->address;
    uint8_t src_srv_type = t_args->src_srv_type;

    pthread_mutex_lock(&(be_table.mutex));
    char* temp;
    temp = malloc(strlen(address) + 1);
    strcpy(temp, address);		    
    struct namelist *temp_l = malloc(sizeof(struct namelist));
    temp_l->elt = temp;
    temp_l->next_elt = NULL;
    if (src_srv_type == SRV_TYPE_BACKEND)
    {
	printf("received alive from a %s\n", "BACK END");
	SGLIB_LIST_ADD(struct namelist, be_table.BE_alive, temp_l, next_elt);
    }
    else if (src_srv_type == SRV_TYPE_FRONTEND)
    {
	printf("received alive from a %s\n", "FRONT END");
	SGLIB_LIST_ADD(struct namelist, be_table.FE_alive, temp_l, next_elt);
    }
    pthread_mutex_unlock(&(be_table.mutex));
    return NULL;
}

/* params
uint8_t buffer[1024]
*/
void* BE_advertise_file_handle(uint8_t buffer[1024])
{
    uint8_t* data;
    size_t static_size = 13;

    uint16_t name_len = 0;
    data = (uint8_t *)&name_len;
    memcpy(data, &buffer[2], 2);
    printf("Name len: %" PRIu16 "\n", name_len);

    uint64_t content_len = 0;
    data =  (uint8_t *)&content_len;
    memcpy(data, &buffer[4], 8);
    printf("Content len: %" PRIu64 "\n", content_len);

    uint8_t digest_type = buffer[12];
    printf("Digest type: %" PRIu8 "\n", digest_type);

    char* name = malloc(name_len + 1);
    memcpy(name, &buffer[13], name_len);
    name[name_len] = '\0';
    printf("Name: %s\n", name);

    size_t digest_len = rush_digest_type_to_size(digest_type) * 2;
    char* digest = malloc(digest_len + 1);
    memcpy(digest, &buffer[static_size + name_len], digest_len);
    digest[digest_len] = '\0';
    printf("Digest: %s\n", digest);

    // Save digest in /tmp/hash/
    char* path = malloc(name_len + 11); // 11 = "/tmp/hash/
    strcpy(path, "/tmp/hash/"); // HASH_DIR
    strcat(path, name);

    FILE* file = fopen(path, "w+");

    if (file != NULL)
    {
	fwrite(digest, digest_len, 1, file);
	fclose(file);
	free(path);
    }
    else
    {
	fprintf(stderr,
		"Error on saving file.\n");
    }
    return NULL;
}

/* params
char* ipsrc
*/
void* discover_message_handle(void* args)
{
    thread_args* t_args = (thread_args*)args;
    uint8_t src_srv_type = t_args->src_srv_type;
    // TYPE == 8
    if (src_srv_type == SRV_TYPE_BACKEND)
    {
	printf("received discover from a %s\n", "BACK END");
	send_mcast_alive(BE_MCAST_PORT, SAN_GROUP, t_args->srv_type);
    }
    else if (src_srv_type == SRV_TYPE_FRONTEND)
    {
	printf("received discover from a %s\n", "FRONT END");
	send_mcast_alive(FE_MCAST_PORT, FRONTEND_GROUP, t_args->srv_type);
    }
    pthread_exit(NULL);
}


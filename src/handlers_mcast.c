#include "../include/handlers.h"
#include "../include/rush.h"

void rush_bind_server_multicast_socket(int * const multicast_socket, int port, char *mcast_group)
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
}

// static char *HASH_DIR = "test/";


/*
void BE_advertise_file_handle(int const conn_socket)
{
    printf("HERE I AM\n");
    int result = EINVAL;
    ssize_t got = 0;

    // TYPE == 1
    // name_len
    uint16_t name_len_net = 0;

    got = read(conn_socket,
            &name_len_net,
            sizeof name_len_net);

    if (got == sizeof name_len_net)
    {
	uint16_t const name_len = ntohs(name_len_net);
	printf("Name len: %" PRIu16 "\n", name_len);
	// content_len
	uint64_t content_len_net = 0;

	got = read(conn_socket,
		&content_len_net,
		sizeof content_len_net);

	if (got == sizeof content_len_net)
	{
	    uint32_t content_len_net_low = content_len_net;
	    uint32_t content_len_net_high = content_len_net >> 32;
	    uint32_t low_32 = ntohl(content_len_net_low);
	    uint32_t high_32 = ntohl(content_len_net_high);

	    uint64_t content_len = (high_32 << 32) + low_32;
	    printf("Content len: %" PRIu64 "\n", content_len);

	    // digest_type
	    uint8_t digest_type = 0;

	    got = read(conn_socket,
		    &digest_type,
		    sizeof digest_type);

	    printf("Digest type: %" PRIu8 "\n", digest_type);

	    if (got == sizeof digest_type)
	    {
		// name
		char* name = malloc(name_len + 1);

		if (name != NULL)
		{
		    got = read(conn_socket,
			    name,
			    name_len);

		    printf("Name: %s\n", name);

		    if (got == name_len)
		    {
			name[name_len] = '\0';

			// digest
			size_t digest_len = rush_digest_type_to_size(digest_type);
			char* digest = malloc(digest_len + 1);

			if (digest != NULL)
			{
			    got = read(conn_socket,
				    digest,
				    digest_len);

			    printf("Digest: %s\n", digest);

			    if (got == sizeof digest_len)
			    {
				digest[digest_len] = '\0';
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
			    }
			    else if (got == -1)
			    {
				result = errno;
				fprintf(stderr,
					"Error reading digest of advertise file message: %d\n",
					result);
			    }
			    else
			    {
				fprintf(stderr,
					"Not enough data available, skipping.\n");
			    }
			}
			else
			{
			    result = ENOMEM;
			    fprintf(stderr,
				    "Error allocating memory for digest of size %zu: %d\n",
				    digest_len,
				    result);
			}
			free(digest);
			digest = NULL;
		    }
		    else if (got == -1)
		    {
			result = errno;
			fprintf(stderr,
				"Error reading name of advertise file message: %d\n",
				result);
		    }
		    else
		    {
			fprintf(stderr,
				"Not enough data available, skipping.\n");
		    }
		    free(name);
		    name = NULL;
		}
		else
		{
		    result = ENOMEM;
		    fprintf(stderr,
			    "Error allocating memory for name of size %" PRIu16 ": %d\n",
			    name_len,
			    result);
		}
	    }
	    else if (got == -1)
	    {
		result = errno;
		fprintf(stderr,
			"Error reading digest type of advertise file message: %d\n",
			result);
	    }
	    else
	    {
		fprintf(stderr,
			"Not enough data available, skipping.\n");
	    }
	}
	else if (got == -1)
	{
	    result = errno;
	    fprintf(stderr,
		    "Error reading content length of advertise file message: %d\n",
		    result);
	}
	else
	{
	    fprintf(stderr,
		    "Not enough data available, skipping.\n");
	}
    }
    else if (got == -1)
    {
	result = errno;
	fprintf(stderr,
		"Error reading name length of advertise file message: %d\n",
		result);
    }
    else
    {
	fprintf(stderr,
		"Not enough data available, skipping.\n");
    }
}
*/

void FE_request_file_content_mcast(int const conn_socket, uint8_t buffer[1024])
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
}

void FE_advertising_disponibility(int const conn_socket, uint8_t buf[1024])
{
    printf("Message type 6 multicast\n");
    uint8_t *data = malloc(2 * sizeof(uint16_t));
    char *filename; 

    uint16_t filename_len;

    data = (uint8_t *)&filename_len;
    memcpy(data, &buf[2], 2);
}

/*
  Sur le FE pour gérer un message alive
 */
void FE_alive_message_handle(int const conn_socket, uint8_t buf[1024], char *address)
{
    printf("Sending unicast list all files message to the BACKEND with IP %s", address);
    uint8_t *message = malloc(2 * sizeof(uint8_t));
    message[0] = 1;
    message[1] = 2;

    send_ucast_msg(address, BE_PORT, message, 2);
}

void BE_advertise_file_handle(uint8_t buffer[1024])
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
}

void BE_alive_message_handle(char* ipsrc)
{
    // TYPE == 7
    // FIXME Bind port replication
    if (strcmp(ipsrc, "239.42.3.1") == 0)
    {
	send_mcast_request_list_all_files_msg(BE_REP_PORT, ipsrc);
    }
}

/*
  On utilise cette fonction pour gérer un discover sur un backend
 */
void BE_discover_message_handle(char* ipsrc, uint8_t srv_type)
{
    // TYPE == 8
    int port = 0;
    if (srv_type == SRV_TYPE_BACKEND)
    {
	printf("received discover from a %s\n", "BACK END");
	send_mcast_alive(BE_MCAST_PORT, ipsrc);
    }
    else if (srv_type == SRV_TYPE_FRONTEND)
    {
	printf("received discover from a %s\n", "FRONT END");
	send_mcast_alive(FE_MCAST_PORT, ipsrc);
    }
}


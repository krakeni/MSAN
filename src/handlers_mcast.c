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

static char *HASH_DIR = "test/";

/*
void 8to64()
{
    uint64_t rval;
    uint8_t *data = (uint8_t *)&rval;

    data[0] = *input >> 56;
    data[1] = *input >> 48;
    data[2] = *input >> 40;
    data[3] = *input >> 32;
    data[4] = *input >> 24;
    data[5] = *input >> 16;
    data[6] = *input >> 8;
    data[7] = *input >> 0;

}
*/

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

/*
void BE_advertise_file_handle_bis(uint8_t buffer[1024])
{
    int result = EINVAL;

    uint16_t name_len 
}
*/

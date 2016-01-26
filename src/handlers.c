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

void BE_advertise_file_handle(int const conn_socket)
{
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
				// FIXME
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
				    "Error allocatinf memory for digest of size %zu: %d\n",
				    digest_len,
				    result);
			}
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
		    "Erro rreading content length of advertise file message: %d\n",
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

void BE_FE_rqst_content_message(rush_backend_config const * const config,
	int const conn_socket)
{
    int result = EINVAL;
    ssize_t got = 0;
    assert(config != NULL);

    // TYPE == 4
    // UNICAST RQST CONTENT OF A FILE
    uint16_t name_len_net = 0;

    got = read(conn_socket,
	    &name_len_net,
	    sizeof name_len_net);

    if (got == sizeof name_len_net)
    {
	uint16_t const name_len = ntohs(name_len_net);
	char * name = malloc(name_len + 1);

	if (name != NULL)
	{
	    got = read(conn_socket,
		    name,
		    name_len);

	    if (got == name_len)
	    {
		name[name_len] = '\0';

		fprintf(stdout,
			"DEBUG: received request for file %s\n",
			name);

#warning FIXME: Some code has been deleted.

	    }
	    else if (got == -1)
	    {
		result = errno;
		fprintf(stderr,
			"Error reading name of get_file message: %d\n",
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
		    "Error allocating memory for name of size %"PRIu16": %d\n",
		    name_len,
		    result);
	}
    }
    else if (got == -1)
    {
	result = errno;
	fprintf(stderr,
		"Error reading name length of get_file message: %d\n",
		result);
    }
    else
    {
	fprintf(stderr,
		"Not enough data available, skipping.\n");
    }

}

void BE_FE_send_content_message(rush_backend_config const * const config,
        int const conn_socket)
{
    int result = EINVAL;
    ssize_t got = 0;
    assert(config != NULL);

    // TYPE == 5
    // UNICAST MSG SEND CONTENT OF A FILE
    // status must not be negative
    uint8_t status = 0;

    got = read(conn_socket,
            &status,
            sizeof status);

    printf("Status: %" PRIu8 "\n", status);

    if (got == sizeof status)
    {
        // digest_type
        uint8_t digest_type = rush_digest_type_none;

        got = read(conn_socket,
                &digest_type,
                sizeof digest_type);
        printf("Digest type: %" PRIu8 "\n", digest_type);

        if (got == sizeof digest_type)
        {
            // content_len
            long long content_len_net = 0;

            got = read(conn_socket,
                    &content_len_net,
                    sizeof content_len_net);
            printf("Content len net: %llu\n", content_len_net);
            printf("sizeof Content len net: %lu\n", sizeof content_len_net);
            printf("got: %zu\n", got);

            if (got == sizeof content_len_net)
            {
                uint32_t content_len_net_low = content_len_net;
                uint32_t content_len_net_high = content_len_net >> 32;
                uint32_t low_32 = ntohl(content_len_net_low);
                uint32_t high_32 = ntohl(content_len_net_high);

                uint64_t content_len = (high_32 << 32) + low_32;
                printf("Content len: %" PRIu64 "\n", content_len);
                if (content_len_net == 0 && digest_type != rush_digest_type_none)
                {
                    fprintf(stderr,
                            "Error in digest type of send_file message, should be None.\n");
                }
                else
                {
                    // Status code matches non-negative errno values.
                    // If the status code is non-zero, content length
                    // MUST to be set to zero.
                    if (status == 0)
                    {
                        char * content = malloc(content_len + 1);

                        if (content != NULL)
                        {
                            got = read(conn_socket,
                                    content,
                                    content_len);
                            printf("Content: %s\n", content);

                            if (got == (int)content_len)
                            {
                                content[content_len] = '\0';
                                uint8_t digest_len = 0;

                                switch (digest_type)
                                {
                                    case rush_digest_type_sha1:
                                        digest_len = RUSH_DIGEST_SHA1_SIZE;
                                        break;
                                    case rush_digest_type_sha256:
                                        digest_len = RUSH_DIGEST_SHA256_SIZE;
                                        break;
                                    case rush_digest_type_blake2b:
                                        digest_len = RUSH_DIGEST_BLAKE2B_SIZE;
                                        break;
                                    case rush_digest_type_none:
                                        digest_len = 0;
                                        break;
                                }

                                char * digest = malloc((digest_len + 1) * sizeof (uint8_t));

                                if (digest != NULL)
                                {
                                    got = read(conn_socket,
                                            digest,
                                            digest_len);
                                    printf("Digest len: %" PRIu8 "\n", digest_len);
                                    printf("Got: %zu\n", got);
                                    printf("Digest: %s\n", digest);

                                    if (got == digest_len)
                                    {
                                        digest[digest_len] = '\0';
                                        FILE * file = NULL;
                                        file = fopen("test.txt", "w+");

                                        if (file != NULL)
                                        {
                                            fwrite(content, content_len, 1, file);
                                        }
                                        fclose(file);
                                    }
                                    else if (got == -1)
                                    {
                                        result = errno;
                                        fprintf(stderr,
                                                "Error reading digest of send_file message: %d\n",
                                                result);
                                    }
                                    else
                                    {
                                        fprintf(stderr,
                                                "Not enough data available for digest, skipping.\n");
                                    }

                                    free(digest);
                                    digest = NULL;
                                }
                                else
                                {
                                    result = ENOMEM;
                                    fprintf(stderr,
                                            "Error allocating memory for digest of size %"PRIu16": %d\n",
                                            digest_len,
                                            result);
                                }
                            }
                            else if (got == -1)
                            {
                                result = errno;
                                fprintf(stderr,
                                        "Error reading content of send_file message: %d\n",
                                        result);
                            }
                            else
                            {
                                fprintf(stderr,
                                        "Not enough data available for content, skiping.\n");
                            }

                            free(content);
                            content = NULL;
                        }
                        else
                        {
                            result = ENOMEM;
                            fprintf(stderr,
                                    "Error rallocating memory for content of size %"PRIu64": %d\n",
                                    content_len,
                                    result);
                        }
                    }
                    else
                    {
                        if (content_len != 0)
                        {
                            fprintf(stderr,
                                    "Error in content length of send_file message, should be 0.\n");
                        }
                        else
                        {
                            fprintf(stderr,
                                    "Error in send_file message: %d\n",
                                    status);
                        }
                    }
                }
            }
            else if (got == -1)
            {
                result = errno;
                fprintf(stderr,
                        "Error reading content length of send_file message: %d\n",
                        result);
            }
            else
            {
                fprintf(stderr,
                        "Not enough data available for content len, skipping.\n");
            }
        }
        else if (got == -1)
        {
            result = errno;
            fprintf(stderr,
                    "Error reading digest type of send_file message: %d\n",
                    result);
        }
        else
        {
            fprintf(stderr,
                    "Not enough data available for digest type, skipping.\n");
        }
    }
    else if (got == -1)
    {
        result = errno;
        fprintf(stderr,
                "Error reading status code of send_file message: %d\n",
                result);
    }
    else
    {
        fprintf(stderr,
                "Not enough data available for status code, skipping.\n");
    }

}


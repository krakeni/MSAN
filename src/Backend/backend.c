
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../rush.h"

typedef struct
{
    char const * unicast_bind_addr_str;
    char const * unicast_bind_port_str;
    char const * watched_dir;
    size_t watched_dir_len;

} rush_backend_config;

static int rush_backend_watch_dir(char const * const dir,
        int * const inotify_fd,
        int * const dir_inotify_fd)
{
    int result = 0;

    if (dir != NULL &&
            inotify_fd != NULL &&
            dir_inotify_fd != NULL)
    {
        *inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);

        if (*inotify_fd >= 0)
        {
            *dir_inotify_fd = inotify_add_watch(*inotify_fd,
                    dir,
                    IN_CLOSE_WRITE | IN_MOVED_TO);

            if (*dir_inotify_fd < 0)
            {
                result = errno;
                fprintf(stderr,
                        "Error in inotify_add_watch(): %d\n",
                        result);
            }

            if (result != 0)
            {
                close(*inotify_fd);
                *inotify_fd = -1;
            }
        }
        else
        {
            result = errno;
            fprintf(stderr,
                    "Error in inotify_init1(): %d\n",
                    result);
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

static int rush_backend_handle_new_file(rush_backend_config const * const config,
        char const * const filename)
{
    int result = 0;
    assert(config != NULL);
    assert(config->watched_dir != NULL);
    assert(filename != NULL);
    size_t const filename_len = strlen(filename);

    if (filename_len > 0)
    {
        char * path = NULL;

        result = asprintf(&path,
                "%s%s%s",
                config->watched_dir,
                config->watched_dir[config->watched_dir_len - 1] == '/' ? "" : "/",
                filename);

        if (result > 0)
        {
#warning FIXME: Some code has been deleted.

            free(path);
            path = NULL;
        }
        else
        {
            result = errno;
            fprintf(stderr,
                    "Error allocating memory for path, filename length was %zu: %d\n",
                    filename_len,
                    result);
        }
    }

    return result;
}

static void rush_backend_handle_dir_event(rush_backend_config const * const config,
        int const inotify_fd)
{
    static size_t const buffer_size = sizeof(struct inotify_event) + NAME_MAX + 1;
    int result = 0;
    char buffer[buffer_size] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    bool finished = false;
    assert(config != NULL);
    assert(inotify_fd >= 0);

    do
    {
        ssize_t got = read(inotify_fd,
                buffer,
                buffer_size);

        if (got > 0)
        {
            for (char const * ptr = buffer;
                    ptr < (buffer + got);
                )
            {
                struct inotify_event const * event = (struct inotify_event const *) ptr;

                if (event->len > 0 &&
                        event->name != NULL)
                {
                    char const * const filename = event->name;

                    rush_backend_handle_new_file(config,
                            filename);
                }

                ptr += sizeof(struct inotify_event) + event->len;
            }
        }
        else if (got == 0)
        {
            finished = true;
        }
        else
        {
            result = errno;

            if (result != EAGAIN &&
                    result != EWOULDBLOCK)
            {
                fprintf(stderr,
                        "Error reading inotify event: %d\n",
                        result);
            }

            finished = true;
        }
    }
    while (finished == false);
}

static void BE_FE_send_content_message(rush_backend_config const * const config,
        int const conn_socket)
{
    int result = EINVAL;
    ssize_t got = 0;
    assert(config != NULL);

    // TYPE == 5
    // UNICAST MSG SEND CONTENT OF A FILE
    // status must not be negative
    uint8_t status = 0;
    uint64_t content_len = 0;
    char * content = NULL;

    got = read(conn_socket,
	    &status,
	    sizeof status);

    if (got == sizeof status)
    {
	// digest_type
	uint8_t digest_type = rush_digest_type_none;

	got = read(conn_socket,
		&digest_type,
		sizeof digest_type);

	if (got == sizeof digest_type)
	{
	    // content_len
	    uint64_t content_len_net = 0;

	    got = read(conn_socket,
		    &content_len_net,
		    sizeof content_len_net);

	    if (got == sizeof content_len_net)
	    {
		content_len = ntohs(content_len_net);
		if (content_len == 0 && digest_type != rush_digest_type_none)
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
			content = malloc(content_len + 1);

			if (content != NULL)
			{
			    got = read(conn_socket,
				    content,
				    content_len);

			    if (got == sizeof content_len)
			    {
				content[content_len] = '\0';
				uint8_t digest_len_net = 0;

				switch (digest_type)
				{
				    case rush_digest_type_sha1:
					digest_len_net = 20;
					break;
				    case rush_digest_type_sha256:
					digest_len_net = 32;
					break;
				    case rush_digest_type_blake2b:
					digest_len_net = 64;
					break;
				    case rush_digest_type_none:
					digest_len_net = 0;
					break;
				}

				uint8_t const digest_len = ntohs(digest_len_net);
				char * digest = malloc(digest_len + 1);

				if (digest != NULL)
				{
				    got = read(conn_socket,
					    digest,
					    digest_len);

				    if (got == digest_len)
				    {
					digest[digest_len] = '\0';
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
						"Not enough data available, skipping.\n");
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
					"Not enough data available, skiping.\n");
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
			"Not enough data available, skipping.\n");
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
		    "Not enough data available, skipping.\n");
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
		"Not enough data available, skipping.\n");
    }

    FILE * file = NULL;
    file = fopen("test.txt", "w+");

    if (file != NULL)
    {
	fwrite(content, content_len, 1, file);
    }
    fclose(file);
}

static int rush_backend_handle_new_connection(rush_backend_config const * const config,
        int const conn_socket)
{
    int result = EINVAL;
    uint8_t version = rush_message_version_none;
    ssize_t got = 0;
    assert(config != NULL);
    assert(conn_socket >= 0);

    got = read(conn_socket,
            &version,
            sizeof version);

    if (got == sizeof version)
    {
        if (version == rush_message_version_1)
        {
            uint8_t type = rush_message_type_none;

            got = read(conn_socket,
                    &type,
                    sizeof type);

            if (got == sizeof type)
            {
		if (type == rush_message_type_new_file)
		{
		    // TYPE == 1
		    // name_len
		    // content_len
		    // digest_type
		    // name
		    // digest
		    // FIXME
		}
		else if (type == rush_message_type_list_files)
                {
                    // TYPE == 2
                    // UNICAST RQST LIST OF FILES
                    // FIXME
                }
                else if (type == rush_message_type_get_file)
                {
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
                else if (type == rush_message_type_get_file_response)
                {
		    // TYPE == 5
		    BE_FE_send_content_message(config, conn_socket);
                }
                else if (type == rush_message_type_discover)
                {
                    // TYPE == 8
                }
                else
                {
                    fprintf(stderr,
                            "Discarding unexpected message of type %"PRIu8"\n",
                            type);
                }
            }
            else if (got == -1)
            {
                result = errno;
                fprintf(stderr,
                        "Error reading message type: %d\n",
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
            fprintf(stderr,
                    "Discarding unexpected message of version %"PRIu8"\n",
                    version);
        }
    }
    else if (got == -1)
    {
        result = errno;
        fprintf(stderr,
                "Error reading message type: %d\n",
                result);
    }
    else
    {
        fprintf(stderr,
                "Not enough data available, skipping.\n");
    }

    return result;
}

static int rush_backend_handle_socket_event(rush_backend_config const * const config,
        int const unicast_socket)
{
    int result = 0;
    int conn_socket = -1;
    struct sockaddr_storage storage = (struct sockaddr_storage) { 0 };
    socklen_t storage_len = sizeof storage;

    assert(config != NULL);
    assert(unicast_socket >= 0);

    conn_socket = accept4(unicast_socket,
            (struct sockaddr *) &storage,
            &storage_len,
            SOCK_CLOEXEC);

    if (conn_socket >= 0)
    {
        result = rush_backend_handle_new_connection(config,
                conn_socket);

        close(conn_socket);
        conn_socket = -1;
    }
    else
    {
        result = errno;
        fprintf(stderr,
                "Error accepting a new connection: %d\n",
                result);
    }

    return result;
}

static int rush_backend_listen_on_unicast(char const * const unicast_bind_addr_str,
        char const * const unicast_bind_port_str,
        int * const unicast_socket)
{
    int result = 0;
    struct addrinfo * storage = NULL;
    assert(unicast_bind_addr_str != NULL);
    assert(unicast_bind_port_str != NULL);
    assert(unicast_socket != NULL);

    struct addrinfo hints =
    {
        .ai_family = AF_UNSPEC,
        .ai_flags = AI_PASSIVE | AI_NUMERICHOST,
        .ai_socktype = SOCK_STREAM
    };

    result = getaddrinfo(unicast_bind_addr_str,
            unicast_bind_port_str,
            &hints,
            &storage);

    if (result == 0)
    {
        *unicast_socket = socket(storage->ai_family,
                storage->ai_socktype,
                0);

        if (*unicast_socket >= 0)
        {
            result = bind(*unicast_socket,
                    storage->ai_addr,
                    storage->ai_addrlen);

            if (result == 0)
            {
                result = listen(*unicast_socket,
                        SOMAXCONN);

                if (result == 0)
                {
                    static int const timeout = 5;

                    result = setsockopt(*unicast_socket,
                            IPPROTO_TCP,
                            TCP_DEFER_ACCEPT,
                            &timeout,
                            sizeof timeout);

                    if (result != 0)
                    {
                        result = errno;
                        fprintf(stderr,
                                "Error setting TCP deferred accept: %d\n",
                                result);
                        /* this is not a fatal error */
                        result = 0;
                    }
                }
                else
                {
                    result = errno;
                    fprintf(stderr,
                            "Error listening on socket: %d\n",
                            result);
                }
            }
            else
            {
                result = errno;
                fprintf(stderr,
                        "Error binding socket: %d\n",
                        result);
            }

            if (result != 0)
            {
                close(*unicast_socket);
                *unicast_socket = -1;
            }
        }
        else
        {
            result = errno;
            fprintf(stderr,
                    "Error creating socket: %d\n",
                    result);
        }

        freeaddrinfo(storage);
        storage = NULL;
    }
    else
    {
        fprintf(stderr,
                "Error parsing bind address (%s) and port (%s): %s\n",
                unicast_bind_addr_str,
                unicast_bind_port_str,
                gai_strerror(result));
        result = EINVAL;
    }

    return result;
}

int main(void)
{
    rush_backend_config config = (rush_backend_config) { 0 };
    int unicast_socket = -1;
    int inotify_fd = -1;
    int dir_inotify_fd = -1;

    config.watched_dir = "/tmp";
    config.watched_dir_len = strlen(config.watched_dir);
    config.unicast_bind_addr_str = "::";
    config.unicast_bind_port_str = "4242";

    int result = rush_backend_watch_dir(config.watched_dir,
            &inotify_fd,
            &dir_inotify_fd);

    if (result == 0)
    {
        result = rush_backend_listen_on_unicast(config.unicast_bind_addr_str,
                config.unicast_bind_port_str,
                &unicast_socket);

        if (result == 0)
        {
            int polling_fd = epoll_create1(EPOLL_CLOEXEC);

            if (polling_fd >= 0)
            {
                struct epoll_event dir_event = (struct epoll_event) { 0 };

                dir_event.events = EPOLLIN;
                dir_event.data.fd = inotify_fd;

                result = epoll_ctl(polling_fd,
                        EPOLL_CTL_ADD,
                        inotify_fd,
                        &dir_event);

                if (result == 0)
                {
                    struct epoll_event unicast_socket_event = (struct epoll_event) { 0 };

                    unicast_socket_event.events = EPOLLIN;
                    unicast_socket_event.data.fd = unicast_socket;

                    result = epoll_ctl(polling_fd,
                            EPOLL_CTL_ADD,
                            unicast_socket,
                            &unicast_socket_event);

                    if (result == 0)
                    {
                        while (result == 0)
                        {
                            struct epoll_event events = (struct epoll_event) { 0 };

                            result = epoll_wait(polling_fd,
                                    &events,
                                    1,
                                    -1);

                            if (result > 0)
                            {
                                result = 0;

                                /* process event */
                                fprintf(stdout,
                                        "Got event on %d\n",
                                        events.data.fd);

                                if (events.data.fd == inotify_fd)
                                {
                                    fprintf(stdout,
                                            "Got inotiy event!\n");
                                    rush_backend_handle_dir_event(&config,
                                            inotify_fd);
                                }
                                else if (events.data.fd == unicast_socket)
                                {
                                    fprintf(stdout,
                                            "Got socket event!\n");
                                    rush_backend_handle_socket_event(&config,
                                            unicast_socket);
                                }
                            }
                            else if (result == 0)
                            {
                                /* handle timeout */
                                fprintf(stdout,
                                        "Got timeout!\n");
                            }
                            else
                            {
                                result = errno;
                                fprintf(stderr,
                                        "Error in epoll_wait(): %d\n",
                                        result);
                            }
                        }
                    }
                    else
                    {
                        result = errno;
                        fprintf(stderr,
                                "Error in epoll_ctl(): %d\n",
                                result);
                    }
                }
                else
                {
                    result = errno;
                    fprintf(stderr,
                            "Error in epoll_ctl(): %d\n",
                            result);
                }

                close(polling_fd);
                polling_fd = -1;
            }
            else
            {
                result = errno;
                fprintf(stderr,
                        "Error in epoll_create1(): %d\n",
                        result);
            }

            close(unicast_socket);
            unicast_socket = -1;
        }
        else
        {
            fprintf(stderr,
                    "Error in rush_backend_listen_on_unicast(): %d\n",
                    result);
        }

        close(dir_inotify_fd);
        dir_inotify_fd = -1;
        close(inotify_fd);
        inotify_fd = -1;
    }
    else
    {
        fprintf(stderr,
                "Error in rush_backend_watch_dir(): %d\n",
                result);
    }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return result;
}

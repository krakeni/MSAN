
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
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

#include "../include/rush.h"
#include "../include/lib.h"
#include "../include/handlers.h"



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


static int rush_backend_handle_new_file(rush_server_config const * const config,
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
            printf("HERE I AM\n");
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

static void rush_backend_handle_dir_event(rush_server_config const * const config,
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


static void rush_backend_handle_new_connection_mcast(/* rush_server_config const * const config, */
        int const conn_socket)
{
    // THREAD VARIABLE A REORGANISER APRES
    pthread_t thread1;
    alive_table.mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    alive_table.BE_alive = NULL;

    uint8_t version = rush_message_version_none;
    uint8_t type = rush_message_type_none;
    struct sockaddr_in srcaddr = { 0 };
    socklen_t addrlen = sizeof(struct sockaddr_in);
    uint8_t buf[1024];
    memset(&buf, 0, 1024);
    recvfrom(conn_socket, buf, 1024, 0, (struct sockaddr *)&srcaddr, &addrlen);
    printf("IP SOURCE %s\n",inet_ntoa(srcaddr.sin_addr));
    //read(conn_socket, &buf, 1024);

    version = buf[0];
    type = buf[1];
    thread_args args = { 0 };
    args.ipsrc = inet_ntoa(srcaddr.sin_addr);
    args.srv_type = SRV_TYPE_BACKEND;
    if (version == rush_message_version_1)
    {
        if (type == rush_message_type_new_file)
        {
            // TYPE 1
	    BE_advertise_file_handle(buf);
        }
        else if (type == rush_message_type_alive)
        {
            //TYPE 7

        }
        else if (type == rush_message_type_discover)
        {
            //TYPE 8
	    /* uint8_t srv_type = buf[2]; */
	    /* discover_message_handle(ipsrc, srv_type); */
	    //BE_discover_message_handle(inet_ntoa(srcaddr.sin_addr));
	    args.src_srv_type = buf[2];
            if(pthread_create(&thread1, NULL, discover_message_handle, &args) == -1) {
                perror("Error in pthread_create");
        }
    }
}
}

static int rush_backend_handle_new_connection(rush_server_config const * const config,
					      int const conn_socket)
{
    fprintf(stdout, "HANDLE_NEW_CONNECTION WITH SOCKET = %d\n", conn_socket);
    int result = EINVAL;
    uint8_t version = rush_message_version_none;
    ssize_t got = 0;
    assert(config != NULL);
    assert(conn_socket >= 0);

    /*thread_args args = { 0 };
    args.srv_type = SRV_TYPE_BACKEND;
    */
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
            printf("Type: %" PRIu8 "\n", type);
            if (got == sizeof type)
            {
                if (type == rush_message_type_list_files)
                {
                    //FIXME send a type 3 with list of files
                    printf("TYPE 3 WITH THE LIST OF ALL FILE SENDED \n");
                }
                else if (type == rush_message_type_get_file)
                {
                    // TYPE == 4
                    BE_FE_rqst_content_message(conn_socket);
                }
                else if (type == rush_message_type_get_file_response)
                {
                    // TYPE == 5
		  printf("Type5\n");
		  BE_FE_send_content_message(conn_socket);
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
                "Error reading message version: %d\n",
                result);
    }
    else
    {
        fprintf(stderr,
                "Not enough data available, skipping.\n");
    }

    return result;
}

static int rush_backend_handle_socket_event(rush_server_config const * const config,
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

static int rush_backend_handle_multicast_socket_event(rush_server_config const *config, int multicast_socket)
{
    fprintf(stdout, "HANDLE_MULTICAST_SOCKET_EVENT\n");
    int result = 0;
    assert(config != NULL);
    assert(multicast_socket >= 0);

    rush_backend_handle_new_connection_mcast(/* config,  */multicast_socket);
    //Il ne faut pas close la socket
    return result;
}

int main(void)
{
    rush_server_config config = (rush_server_config) { 0 };
    int unicast_socket = -1;
    int inotify_fd = -1;
    int dir_inotify_fd = -1;
    thread_args args = { 0 };
    args.address = LOCAL_IFACE;
    args.port = FRONTEND_PORT;

    int multicast_socket = -1;
    rush_bind_server_multicast_socket(&multicast_socket, BE_MCAST_PORT, SAN_GROUP);

    config.watched_dir = "/tmp";
    config.watched_dir_len = strlen(config.watched_dir);
    config.unicast_bind_addr_str = "::";
    config.unicast_bind_port_str = "4241";

    int result = rush_backend_watch_dir(config.watched_dir,
            &inotify_fd,
            &dir_inotify_fd);
    send_ucast_request_list_all_files_msg(&args);
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
                        struct epoll_event multicast_socket_event = (struct epoll_event) { 0 };

                        multicast_socket_event.events = EPOLLIN;
                        multicast_socket_event.data.fd = multicast_socket;

                        result = epoll_ctl(polling_fd,
                                EPOLL_CTL_ADD,
                                multicast_socket,
                                &multicast_socket_event);
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
                                    else if (events.data.fd == multicast_socket)
                                    {
                                        fprintf(stdout,
                                                "Got multicast_socket event!\n");
                                        rush_backend_handle_multicast_socket_event(&config, multicast_socket);
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
	    close(multicast_socket);
            multicast_socket = -1;

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

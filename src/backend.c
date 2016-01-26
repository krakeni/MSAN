
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
            printf("HERE I AM\n");
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


static int rush_backend_handle_new_connection(rush_backend_config const * const config,
        int const conn_socket)
{
    fprintf(stdout, "HANDLE_NEW_CONNECTION WITH SOCKET = %d\n", conn_socket);
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
        printf("VERSION DU MESSAGE : %d\n", version);
        if (version == rush_message_version_1)
        {
            uint8_t type = rush_message_type_none;

            printf("HERE I AM\n");
            got = read(conn_socket,
                    &type,
                    sizeof type);
            printf("HERE I AM\n");
            printf("Type: %" PRIu8 "\n", type);
            if (got == sizeof type)
            {
                if (type == rush_message_type_new_file)
                {
                    // TYPE == 1
                    BE_advertise_file_handle(conn_socket);
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
                    BE_FE_rqst_content_message(config, conn_socket);
                }
                else if (type == rush_message_type_get_file_response)
                {
                    // TYPE == 5
                    BE_FE_send_content_message(config, conn_socket);
                }
                else if (type == rush_message_type_discover)
                {
                    // TYPE == 8
                    //On va répondre avec un alive en unicast
                    printf("MESSAGE TYPE 8 RECU\n");
                    struct sockaddr_in addr;
                    socklen_t addr_size = sizeof(struct sockaddr_in);
                    result = getpeername(conn_socket, (struct sockaddr *)&addr, &addr_size);
                    char clientip[20];
                    strcpy(clientip, inet_ntoa(addr.sin_addr));
                    printf("l'ip du Front End qui a envoyé est : %s\n", clientip);
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

void rush_backend_bind_multicast_socket(int * const multicast_socket)
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
    localSock.sin_port = htons(BE_MCAST_PORT);
    localSock.sin_addr.s_addr = INADDR_ANY;

    if(bind(*multicast_socket, (struct sockaddr*)&localSock, sizeof(localSock)))
        perror("Binding datagram socket error");

    group.imr_multiaddr.s_addr = inet_addr(SAN_GROUP);
    group.imr_interface.s_addr = inet_addr(LOCAL_IFACE);
    if(setsockopt(*multicast_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group)) < 0)
        perror("Adding multicast group error");
}

static int rush_backend_handle_multicast_socket_event(rush_backend_config const *config, int multicast_socket)
{
    fprintf(stdout, "HANDLE_MULTICAST_SOCKET_EVENT\n");
    int result = 0;
    assert(config != NULL);
    assert(multicast_socket >= 0);

    result = rush_backend_handle_new_connection(config, multicast_socket);
    //Il ne faut pas close la socket
    return result;
}


int main(void)
{
    rush_backend_config config = (rush_backend_config) { 0 };
    int unicast_socket = -1;
    int inotify_fd = -1;
    int dir_inotify_fd = -1;

    int multicast_socket = -1;
    rush_backend_bind_multicast_socket(&multicast_socket);

    config.watched_dir = "/tmp";
    config.watched_dir_len = strlen(config.watched_dir);
    config.unicast_bind_addr_str = "::";
    config.unicast_bind_port_str = "4241";

    int result = rush_backend_watch_dir(config.watched_dir,
            &inotify_fd,
            &dir_inotify_fd);

    send_mcast_alive(FE_MCAST_PORT, FRONTEND_GROUP);
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

#ifndef LIB_H_
#define LIB_H_

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

#include "rush.h"

void send_mcast_msg(char *databuf, int datalen, uint16_t port, const char* mcast_group);

void send_mcast_discover(uint16_t port, const char* mcast_group);

void send_mcast_adv_file_msg(uint16_t port, const char* mcast_group, char* path,
			     const int digest_type);

int send_ucast_msg(char *address, int port, uint8_t *message, long long message_length);

#endif /* LIB_H */

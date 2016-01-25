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
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <unistd.h>

#include "rush.h"

void send_mcast_msg(uint8_t *databuf, int datalen, uint16_t port, const char* mcast_group);

void send_mcast_discover(uint16_t port, const char* mcast_group);

void send_mcast_adv_file_msg(uint16_t port, const char* mcast_group, char* path,
			     const int digest_type);

int send_ucast_msg(char *address, int port, uint8_t *message, long long message_length);

void send_mcast_request_list_all_files_msg(uint16_t port, const char* mcast_group);

void send_ucast_request_list_all_files_msg(char *address, int port);

struct BE_file_info_list *BE_file_info_list_create_node(BE_file_info element);

void send_mcast_list_all_files(int nb_files, struct BE_file_info_list *infos, int port, char *address);

void send_mcast_alive(uint16_t port, const char* mcast_group);

void send_mcast_disp_new_file(uint16_t port, const char* mcast_group, char *filename);

void send_ucast_req_content_file(char *filename, uint16_t port, char *address);

#endif /* LIB_H */

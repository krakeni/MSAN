#ifndef LIB_H_
#define LIB_H_

#include <libgen.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
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

int upload_file(char *path, char *address, int port);

struct namelist *read_files_from_backend(const rush_server_config *config);

uint64_t ntoh64(const uint64_t *input);

void send_mcast_msg(uint8_t *databuf, int datalen, uint16_t port, const char* mcast_group);

void send_mcast_discover(uint16_t port, const char* mcast_group, uint8_t srv_type);

void send_mcast_adv_file_msg(uint16_t port, const char* mcast_group, char* path,
			     const int digest_type);

int send_ucast_msg(char *address, int port, uint8_t *message, long long message_length);

void send_mcast_request_list_all_files_msg(uint16_t port, const char* mcast_group);

void* send_ucast_request_list_all_files_msg(void *args);

struct BE_file_info_list *BE_file_info_list_create_node(BE_file_info element);

void send_mcast_list_all_files(int nb_files, struct BE_file_info_list *infos, int port, char *address);

void send_mcast_alive(uint16_t port, const char* mcast_group, uint8_t srv_type);

void send_mcast_disp_new_file(uint16_t port, const char* mcast_group, char *filename);

void send_ucast_req_content_file(char *filename, uint16_t port, char *address);

void hash_string_sha256(uint8_t hash[SHA256_DIGEST_LENGTH], char output[256]);

int get_hash_sha256(char* path, char output[256]);

#endif /* LIB_H */

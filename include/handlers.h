#ifndef HANDLERS_H_
#define HANDLERS_H_

#include <dirent.h>
#include <sys/types.h>
#include "rush.h"
#include "lib.h"
void BE_advertise_file_handle(int const conn_socket);

void BE_FE_rqst_content_message(int const conn_socket);

void BE_FE_send_content_message(int const conn_socket);

void IF_FE_send_content_message(rush_server_config const * const config, int const conn_socket);

void rush_bind_server_multicast_socket(int * const multicast_socket, int port, char *mcast_group);

#endif /* HANDLERS_H_ */

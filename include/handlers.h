#ifndef HANDLERS_H_
#define HANDLERS_H_

#include <dirent.h>
#include <sys/types.h>
#include "rush.h"
#include "lib.h"

void BE_advertise_file_handle(uint8_t buffer[1024]);

void BE_FE_rqst_content_message(int const conn_socket);

void BE_FE_send_content_message(int const conn_socket);

void IF_FE_send_content_message(rush_server_config const * const config, int const conn_socket);

/************** Multicast **************/

void rush_bind_server_multicast_socket(int * const multicast_socket, int port, char *mcast_group);

void BE_advertise_file_handle(uint8_t buffer[1024]);

void BE_alive_message_handle(char* ipsrc);

void BE_discover_message_handle(char* ipsrc);

void FE_request_file_content_mcast(int const conn_socket, uint8_t buffer[1024]);

void FE_advertising_disponibility(int const conn_socket, uint8_t buf[1024]); 

void FE_alive_message(int const conn_socket, uint8_t buf[1024], char *address);
#endif /* HANDLERS_H_ */

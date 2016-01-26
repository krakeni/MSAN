#ifndef HANDLERS_H_
#define HANDLERS_H_

#include <dirent.h>

#include "rush.h"
#include "lib.h"

typedef struct
{
    char const * unicast_bind_addr_str;
    char const * unicast_bind_port_str;
    char const * watched_dir;
    size_t watched_dir_len;

} rush_backend_config;

typedef struct
{
    char const * unicast_bind_addr_str;
    char const * unicast_bind_port_str;
    char const * watched_dir;
    size_t watched_dir_len;

} rush_frontend_config;

void BE_FE_rqst_content_message(int const conn_socket);

void BE_FE_send_content_message(int const conn_socket);

void IF_FE_send_content_message(rush_frontend_config const * const config, int const conn_socket);

/************** Multicast **************/

void rush_bind_server_multicast_socket(int * const multicast_socket, int port, char *mcast_group);

void BE_advertise_file_handle(uint8_t buffer[1024]);

void FE_request_file_content_mcast(int const conn_socket, uint8_t buffer[1024]);

void FE_advertising_disponibility(int const conn_socket, uint8_t buf[1024]); 

void FE_alive_message(int const conn_socket, uint8_t buf[1024], char *address);
#endif /* HANDLERS_H_ */

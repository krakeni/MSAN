#ifndef HANDLERS_H_
#define HANDLERS_H_

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

void BE_FE_rqst_content_message(rush_backend_config const * const config,
	int const conn_socket);

void BE_FE_send_content_message(rush_backend_config const * const config,
        int const conn_socket);

#endif /* HANDLERS_H_ */

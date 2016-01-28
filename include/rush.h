
#ifndef RUSH_H_
#define RUSH_H_

#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
//Lib for the lists and other structures
#include "sglib.h"

#define FRONTEND_GROUP "239.42.3.2"
#define SAN_GROUP "239.42.3.1"
#define BE_PORT 4241
#define FRONTEND_PORT 4242
//Changes this IP according to your Interface IP

//#define LOCAL_IFACE "127.0.0.1"
#define LOCAL_IFACE "192.168.1.115"
#define FE_MCAST_PORT 4243
#define BE_MCAST_PORT 4321
#define BE_REP_PORT 4040

//Server type
#define SRV_TYPE_FRONTEND 0
#define SRV_TYPE_BACKEND  1

typedef struct
{
    int const conn_socket;
    uint8_t buffer[1024];
    char* address;
    char *ipsrc;
    uint8_t srv_type;
} thread_args;

typedef struct
{
    char const * unicast_bind_addr_str;
    char const * unicast_bind_port_str;
    char const * watched_dir;
    size_t watched_dir_len;

} rush_server_config;

typedef struct
{
    uint16_t name_len;
    uint32_t nb_BE_having_file;
    uint8_t dgst_type_file1;
    char* filename;
    uint8_t BE1_addr_type;
    uint32_t BE1_addr;
    uint8_t BE2_addr_type;
    uint32_t BE2_addr;
    
} BE_file_info;

struct BE_file_info_list {
    BE_file_info elt;
    struct BE_file_info_list *next_elt;
};

struct namelist {
    char *elt;
    struct namelist *next_elt;
};

typedef struct 
{
    struct namelist *BE_alive;
    struct namelist *FE_alive;
    pthread_mutex_t mutex;
} shared_BE_table;
shared_BE_table be_table;

typedef enum
{
    rush_message_type_none                = 0,
    rush_message_type_new_file            = 1,
    rush_message_type_list_files          = 2,
    rush_message_type_list_files_response = 3,
    rush_message_type_get_file            = 4,
    rush_message_type_get_file_response   = 5,
    rush_message_type_file_available_here = 6,
    rush_message_type_alive               = 7,
    rush_message_type_discover            = 8,
    rush_message_new_file_from_front      = 9,
    rush_message_type_invalid
} rush_message_type;

typedef enum
{
    rush_message_version_none  = 0,
    rush_message_version_1     = 1,
    rush_message_version_invalid
} rush_message_version;

typedef enum
{
    rush_digest_type_none    = 0,
    rush_digest_type_sha1    = 1,
    rush_digest_type_sha256  = 2,
    rush_digest_type_blake2b = 3,
    rush_digest_type_invalid
} rush_digest_type;

typedef enum
{
    rush_address_type_none   = 0,
    rush_address_type_v4     = AF_INET,
    rush_address_type_v6     = AF_INET6
} rush_address_type;

#define RUSH_DIGEST_SHA1_SIZE (20)
#define RUSH_DIGEST_SHA256_SIZE (32)
#define RUSH_DIGEST_BLAKE2B_SIZE (64)
#define RUSH_DIGEST_MAXIMUM_SIZE (RUSH_DIGEST_BLAKE2B_SIZE)

#define RUSH_ADDRESS_TYPE_V4_SIZE (4)
#define RUSH_ADDRESS_TYPE_V6_SIZE (16)

static inline size_t rush_digest_type_to_size(rush_digest_type const type)
{
    size_t result = 0;

    switch(type)
    {
    case rush_digest_type_sha1:
        result = (RUSH_DIGEST_SHA1_SIZE);
        break;
    case rush_digest_type_sha256:
        result = (RUSH_DIGEST_SHA256_SIZE);
        break;
    case rush_digest_type_blake2b:
        result = (RUSH_DIGEST_BLAKE2B_SIZE);
        break;
    default:
        break;
    }

    return result;
}

static inline size_t rush_address_type_to_size(rush_address_type const type)
{
    size_t result = 0;

    switch(type)
    {
    case rush_address_type_v4:
        result = (RUSH_ADDRESS_TYPE_V4_SIZE);
        break;
    case rush_address_type_v6:
        result = (RUSH_ADDRESS_TYPE_V6_SIZE);
        break;
    default:
        break;
    }

    return result;
}

static inline int rush_raw_buffer_to_sockaddr_storage(char const * const buffer,
                                                      size_t const buffer_size,
                                                      rush_address_type const type,
                                                      struct sockaddr_storage * const storage,
                                                      size_t * const storage_size)
{
    int result = 0;

    if (buffer != NULL &&
        storage != NULL &&
        storage_size != NULL &&
        (type == rush_address_type_v4 ||
         type == rush_address_type_v6))
    {
        if (type == rush_address_type_v4)
        {
            struct sockaddr_in * sa = (struct sockaddr_in *) storage;
            *storage_size = sizeof *sa;
            storage->ss_family = AF_INET;
            sa->sin_family = AF_INET;
            sa->sin_port = 0;
            memcpy(&(sa->sin_addr.s_addr), buffer, buffer_size);
        }
        else
        {
            struct sockaddr_in6 * sa = (struct sockaddr_in6 *) storage;
            *storage_size = sizeof *sa;
            storage->ss_family = AF_INET6;
            sa->sin6_family = AF_INET6;
            sa->sin6_port = 0;
            memcpy(&(sa->sin6_addr), buffer, buffer_size);
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

static inline int rush_addrinfo_to_raw_buffer(struct addrinfo const * const info,
                                              char ** const out,
                                              size_t * const out_size,
                                              rush_address_type * const type)
{
    int result = 0;

    if (info != NULL &&
        (info->ai_family == AF_INET ||
         info->ai_family == AF_INET6) &&
        out != NULL &&
        out_size != NULL &&
        type != NULL)
    {
        *type = info->ai_family == AF_INET ? rush_address_type_v4 : rush_address_type_v6;
        *out_size = rush_address_type_to_size(*type);
        *out = malloc(*out_size);

        if (*out != NULL)
        {
            struct sockaddr const * const sa = info->ai_addr;

            if (*type == rush_address_type_v4)
            {
                struct sockaddr_in * sai = (struct sockaddr_in *) sa;
                assert(sai->sin_family == AF_INET);
                memcpy(*out, &(sai->sin_addr.s_addr), *out_size);
            }
            else
            {
                struct sockaddr_in6 * sai = (struct sockaddr_in6 *) sa;
                assert(sai->sin6_family == AF_INET6);
                memcpy(*out, &(sai->sin6_addr), *out_size);
            }
        }
        else
        {
            result = ENOMEM;
        }
    }
    else
    {
        result = EINVAL;
    }

    return result;
}

#endif /* RUSH_H_ */

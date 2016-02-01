#include <fcntl.h>
#include "../include/handlers.h"
#include "../include/rush.h"

static char *HASH_DIR = "test/";
static char *handle_dir = "/tmp/msan/";

void* BE_FE_rqst_content_message(int const conn_socket)
{
  int result = EINVAL;
  ssize_t got = 0;

  // TYPE == 4
  // UNICAST RQST CONTENT OF A FILE
  uint16_t name_len_net = 0;

  got = read(conn_socket,
             &name_len_net,
             sizeof name_len_net);

  if (got == sizeof name_len_net)
  {
    uint16_t const name_len = ntohs(name_len_net);
    char * name = malloc(name_len + 1);

    if (name != NULL)
    {
      got = read(conn_socket,
                 name,
                 name_len);

      if (got == name_len)
      {
        name[name_len] = '\0';

        fprintf(stdout,
                "DEBUG: received request for file %s\n",
                name);

        // FIXME
        // Search name in directory

      }
      else if (got == -1)
      {
        result = errno;
        fprintf(stderr,
                "Error reading name of get_file message: %d\n",
                result);
      }
      else
      {
        fprintf(stderr,
                "Not enough data available, skipping.\n");
      }

      free(name);
      name = NULL;
    }
    else
    {
      result = ENOMEM;
      fprintf(stderr,
              "Error allocating memory for name of size %"PRIu16": %d\n",
              name_len,
              result);
    }
  }
  else if (got == -1)
  {
    result = errno;
    fprintf(stderr,
            "Error reading name length of get_file message: %d\n",
            result);
  }
  else
  {
    fprintf(stderr,
            "Not enough data available, skipping.\n");
  }
  return NULL;

}

// TYPE == 5
// UNICAST MSG SEND CONTENT OF A FILE
void* BE_FE_send_content_message(int const conn_socket)
{
  int content_len, fd, filename_len, digest_len;
  ssize_t got = 0, c_write = 0;
  char buf[1500];
  char *filename, *path, *digest, *digest2;
  int status = 0;
  char digest_type = rush_digest_type_none;

  //10: headers - version - msg type
  got = read(conn_socket,
             &buf,
             10);

  memcpy(&status, buf, 1);
  printf("Status: %i\n", status);
  if (status != 0)
  {

  }

  if (got != 10)
  {
    fprintf(stderr, "Got %zu instead of 10\n", got);
  }

  memcpy(&digest_type, &buf[1], 1);
  printf("Digest type: %c\n", digest_type);

  memcpy(&content_len, &buf[2], 4);
  printf("Content len read: %d\n", content_len);

  memcpy(&filename_len, &buf[6], 4);
  printf("Filename len read: %d\n", filename_len);

  memset(buf, 0, 1500);

  got = read(conn_socket,
             &buf,
             filename_len);

  filename = malloc(filename_len * sizeof(char) + 1);

  memcpy(filename, buf, filename_len);
  filename[filename_len] = '\0';
  printf("Filename read: %s\n", filename);

  path = malloc((strlen(handle_dir) + filename_len) * sizeof(char)  + 1);
  strcpy(path, handle_dir);
  strcat(path, filename);

  printf("FilePath:%s\n", path);
  if ((fd = open(path, O_WRONLY | O_TRUNC | O_CREAT, S_IRWXU)) == -1)
  {
    perror("Error in opening dest file");
  }

  digest_len = rush_digest_type_to_size(digest_type);
  memset(buf, 0, 1500);

  got = read(conn_socket,
	     &buf[0],
	     digest_len * 2);

  if (got != digest_len)
    printf("Got: %zu\n", got);

  digest = malloc((digest_len + 1) * sizeof (char) * 2);

  if (digest != NULL)
  {
    memcpy(digest, &buf[0], digest_len * 2);
    digest[digest_len * 2] = '\0';
    printf("Digest: %s\n", digest);
  }

  while ((got = read(conn_socket, &buf, 1500)))
  {
    if (got == -1)
      perror("Unable to read socket");

    if ((c_write = write(fd, &buf, got)) == -1)
      perror("Unable to write on file");

    if (got != c_write)
      printf("Error: read size: %zu write size: %zu\n", got, c_write);
  }

  memset(buf, 0, 1500);
  digest2 = malloc((digest_len + 1) * sizeof (char) * 2);

  get_hash_sha256(path, digest2);
  digest2[digest_len * 2] = '\0';
  printf("Digest2: %s\n", digest2);

  if (strcmp(digest, digest2) == 0)
    printf("Digest verified\n");
  else
    printf("ERROR in verifing digest!\n");

  free(digest);
  free(digest2);
  close(fd);

  return NULL;
}

void* IF_FE_send_content_message(rush_server_config const * const config, int const conn_socket)
{
  int result = EINVAL;
  ssize_t got = 0;
  assert(config != NULL);

  // TYPE == 9
  // UNICAST MSG SEND CONTENT OF A FILE
  // status must not be negative
  uint8_t status = 0;

  got = read(conn_socket,
             &status,
             sizeof status);

  printf("Status: %" PRIu8 "\n", status);

  if (got == sizeof status)
  {
    // digest_type
    uint8_t digest_type = rush_digest_type_none;

    got = read(conn_socket,
               &digest_type,
               sizeof digest_type);
    printf("Digest type: %" PRIu8 "\n", digest_type);

    if (got == sizeof digest_type)
    {
      // content_len
      uint64_t content_len_net = 0;

      got = read(conn_socket,
                 &content_len_net,
                 sizeof content_len_net);
      printf("sizeof Content len net: %lu\n", sizeof content_len_net);
      printf("got: %zu\n", got);

      if (got == sizeof content_len_net)
      {
        uint64_t content_len = ntoh64(&content_len_net);

        printf("Content len: %" PRIu64 "\n", content_len);
        if (content_len_net == 0 && digest_type != rush_digest_type_none)
        {
          fprintf(stderr,
                  "Error in digest type of send_file message, should be None.\n");
        }
        else
        {
          // Status code matches non-negative errno values.
          // If the status code is non-zero, content length
          // MUST to be set to zero.
          if (status == 0)
          {
            char *content = malloc((content_len + 1) * sizeof(char));

            if (content != NULL)
            {
              got = read(conn_socket,
                         content,
                         content_len);
              printf("Content: %s\n", content);
              printf("Got: %zu\n", got);
              printf("Content_len: %zu\n", content_len);
              printf("Content_len_net: %zu\n", content_len_net);

              if (got == content_len)
              {
                content[content_len] = '\0';
                uint8_t digest_len = rush_digest_type_to_size(digest_type);
                /* Chars are encoded on 2 bytes so a 32 bytes hash will have 4 caracters. */
                digest_len *= 2;

                char * digest = malloc((digest_len + 1) * sizeof (uint8_t));
                digest[digest_len] = '\0';

                if (digest != NULL)
                {
                  got = read(conn_socket,
                             digest,
                             digest_len);
                  printf("Digest len: %" PRIu8 "\n", digest_len);
                  printf("Got: %zu\n", got);
                  printf("Digest: %s\n", digest);

                  if (got == digest_len)
                  {
                    /* Here starts the new message type 9 */
                    /* Get filename_len */
                    uint16_t filename_len_net = 0;
                    uint16_t filename_len = 0;

                    got = read(conn_socket,
                               &filename_len_net,
                               sizeof filename_len);

                    if (got == sizeof filename_len)
                    {

                      /* Get filename */
                      filename_len = ntohs(filename_len_net);
                      char *filename = malloc((filename_len + 1) * sizeof (char));

                      got = read(conn_socket,
                                 filename,
                                 filename_len);

                      filename[filename_len] = '\0';
                      printf("Filename_len : %"PRIu16"\n", filename_len);
                      printf("Filename : %s\n", filename);


                      /* Write in file */

                      FILE *file = fopen(filename, "wb");
                      if (file == NULL)
                      {
                        int errnum = errno;
                        fprintf(stderr, "Can't access the file. Reason : \n errno : %d", errnum);
                        return NULL;
                      }

                      fwrite(content, 1, content_len,  file);
                      fclose(file);


                      int hash_filename_len = strlen(HASH_DIR) + filename_len + 1;
                      char *hash_filename = malloc(hash_filename_len * sizeof (char));
                      hash_filename[hash_filename_len] = '\0';

                      /* printf("Hash_filename_len = %z(HASH_DIR) + %z(filename_len) + 1\n", (size_t)strlen(HASH_DIR), (size_t)filename_len); */


                      strcpy(hash_filename, HASH_DIR);
                      strcat(hash_filename, filename);

                      printf("Hash filename : %s\n", hash_filename);

                      FILE *hash_file = fopen(hash_filename, "w+");
                      fputs(digest, hash_file);

                      fclose(hash_file);
                    }


                  }
                  else if (got == -1)
                  {
                    result = errno;
                    fprintf(stderr,
                            "Error reading digest of send_file message: %d\n",
                            result);
                  }
                  else
                  {
                    fprintf(stderr,
                            "Not enough data available for digest, skipping.\n");
                    /* fprintf(stderr, "Got = %z\n", got); */
                  }

                  free(digest);
                  digest = NULL;
                }
                else
                {
                  result = ENOMEM;
                  fprintf(stderr,
                          "Error allocating memory for digest of size %"PRIu16": %d\n",
                          digest_len,
                          result);
                }
              }
              else if (got == -1)
              {
                result = errno;
                fprintf(stderr,
                        "Error reading content of send_file message: %d\n",
                        result);
              }
              else
              {
                fprintf(stderr,
                        "Not enough data available for content, skiping.\n");
              }

              free(content);
              content = NULL;
            }
            else
            {
              result = ENOMEM;
              fprintf(stderr,
                      "Error rallocating memory for content of size %"PRIu64": %d\n",
                      content_len,
                      result);
            }
          }
          else
          {
            if (content_len != 0)
            {
              fprintf(stderr,
                      "Error in content length of send_file message, should be 0.\n");
            }
            else
            {
              fprintf(stderr,
                      "Error in send_file message: %d\n",
                      status);
            }
          }
        }
      }
      else if (got == -1)
      {
        result = errno;
        fprintf(stderr,
                "Error reading content length of send_file message: %d\n",
                result);
      }
      else
      {
        fprintf(stderr,
                "Not enough data available for content len, skipping.\n");
      }
    }
    else if (got == -1)
    {
      result = errno;
      fprintf(stderr,
              "Error reading digest type of send_file message: %d\n",
              result);
    }
    else
    {
      fprintf(stderr,
              "Not enough data available for digest type, skipping.\n");
    }
  }
  else if (got == -1)
  {
    result = errno;
    fprintf(stderr,
            "Error reading status code of send_file message: %d\n",
            result);
  }
  else
  {
    fprintf(stderr,
            "Not enough data available for status code, skipping.\n");
  }
  return NULL;

}

void* FE_list_files_BE(void* args)
{
  thread_args* t_args = (thread_args*)args;

  uint8_t srv_type = t_args->srv_type;
  send_mcast_discover(BE_MCAST_PORT, SAN_GROUP, srv_type);
  sleep(1);
  while (alive_table.BE_alive->next_elt != NULL)
  {
    printf("BE ALIVE %s \n", alive_table.BE_alive->elt);
    t_args->address = alive_table.BE_alive->elt;
    t_args->port = BE_PORT;
    send_ucast_request_list_all_files_msg(t_args);
    alive_table.BE_alive = alive_table.BE_alive->next_elt;
  }
  printf("BE ALIVE %s \n", alive_table.BE_alive->elt);
  t_args->address = alive_table.BE_alive->elt;
  t_args->port = BE_PORT;
  send_ucast_request_list_all_files_msg(t_args);
  pthread_exit(NULL);
}

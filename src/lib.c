#include "../include/lib.h"
#include "../include/handlers.h"

uint64_t ntoh64(const uint64_t *input)
{
    uint64_t rval;
    uint8_t *data = (uint8_t *)&rval;

    data[0] = *input >> 56;
    data[1] = *input >> 48;
    data[2] = *input >> 40;
    data[3] = *input >> 32;
    data[4] = *input >> 24;
    data[5] = *input >> 16;
    data[6] = *input >> 8;
    data[7] = *input >> 0;

    return rval;
}

void send_mcast_msg(uint8_t *databuf, int datalen, uint16_t port, const char* mcast_group)
{
    struct in_addr Local_interface = (struct in_addr) { 0 };
    struct sockaddr_in mcast_sock = (struct sockaddr_in) { 0 };

    int msocket = socket(AF_INET, SOCK_DGRAM, 0);
    memset((char *) &mcast_sock, 0, sizeof(mcast_sock));
    mcast_sock.sin_family = AF_INET;
    mcast_sock.sin_addr.s_addr = inet_addr(mcast_group);
    mcast_sock.sin_port = htons(port);

    Local_interface.s_addr = inet_addr(LOCAL_IFACE);
    if(setsockopt(msocket, IPPROTO_IP, IP_MULTICAST_IF, (char *)&Local_interface, sizeof(Local_interface)) < 0)
    {
        perror("Setting local interface error");
        exit(1);
    }
    if(sendto(msocket, databuf, datalen, 0, (struct sockaddr*)&mcast_sock, sizeof(mcast_sock)) < 0)
    {
        perror("Sending datagram message error");
    }
}

/*
  Ajout d'un champ pour dire si le serveur est un back ou un frontend
 */
void send_mcast_discover(uint16_t port, const char* mcast_group, uint8_t srv_type)
{
  uint8_t msg[3];
  msg[0] = 1;
  msg[1] = 8;
  msg[2] = srv_type;
  send_mcast_msg(msg, 3, port, mcast_group);
}

void hash_string_sha256(uint8_t hash[SHA256_DIGEST_LENGTH], char output[256])
{
    int i = 0;

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
	sprintf(output + (i * 2), "%02x", hash[i]);
    }

    output[255] = 0;
}

int get_hash_sha256(char* path, char output[256])
{
    FILE* file = fopen(path, "rb");
    if (file != NULL)
    {

	uint8_t hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	const int buffer_size = 32768;
	char* buffer = malloc(buffer_size);
	int read = 0;

	if (buffer != NULL)
	{
	    while ((read = fread(buffer, 1, buffer_size, file)))
	    {
		SHA256_Update(&sha256, buffer, read);
	    }
	    SHA256_Final(hash, &sha256);

	    hash_string_sha256(hash, output);

	    fclose(file);
	    free(buffer);
	}
    return 0;
    }

    printf("File %s is missing \n", path);

    return 1;
}

/* Type 1 Params:
 * - port
 *   mcast_group
 *   path
 *   digest_type
 */
void send_mcast_adv_file_msg(uint16_t port, const char* mcast_group, char* path,
			      const int digest_type)
{
    uint64_t message_length = 0;
    // static_size = version_sz + type_sz + name_len_sz + content_len_sz + digest_type_sz;
    // static_size = 1 + 1 + 2 + 8 + 1;
    size_t static_size = 13;

    size_t digest_len = rush_digest_type_to_size(digest_type) * 2;
    char* digest = malloc((digest_len + 1) * sizeof (uint8_t));

    int present = 0;

    if (digest_type == 2)
    	present = get_hash_sha256(path, digest);

    if (!present)
    {

    digest_len = strlen(digest);

    const char delim[2] = "/";
    char* token = malloc(strlen(path));
    char* filename = NULL;

    if (token != NULL)
    {
	char* tmp = strdup(path);
	token = strtok(tmp, delim);
    }

    while (token != NULL)
    {
    	filename = token;
	token = strtok(NULL, delim);
	if (token != NULL)
	    filename = token;
    }

    // DEBUG
    printf("Version: 1\nType: 1\n");

    uint16_t name_len = strlen(filename); 

    // DEBUG
    printf("Filename size: %" PRIu16 "\n", name_len);

    uint64_t content_len = 0;

    FILE* file = fopen(path, "rb");
    if (file != NULL)
    {
	fseek(file, 0, SEEK_END);
	content_len = ftell(file);
    }

    // DEBUG
    printf("File length: %" PRIu64 "\n", content_len);
    printf("Digest type: %d\n", digest_type);
    printf("Filename: %s\n", filename);

    message_length = static_size + name_len + digest_len;
    // DEBUG
    printf("Digest: %s\n", digest);

    uint8_t message[message_length];

    message[0] = 1; // version
    message[1] = 1; // type
    message[2] = name_len;
    message[3] = name_len >> 8;
    
    int shift = 8;
    message[4] = content_len >> 0;
    for (size_t i = 5; i < static_size - 1; i++)
    {
	message[i] = content_len >> shift;
	shift += 8;
    }

    message[static_size - 1] = digest_type;    

    memcpy(message + static_size, filename, name_len);
    memcpy(message + static_size + name_len, digest, digest_len);

    message[message_length] = 0;

    fclose(file);
    free(token);

    send_mcast_msg(message, message_length, port, mcast_group);
    }
}

int send_ucast_msg(char *address, int port, uint8_t *message, long long message_length)
{
    int socket_desc;
    struct sockaddr_in server;

    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
    /* Put the proxy address there */
    server.sin_addr.s_addr = inet_addr(address);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    //Connect to remote server
    if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        perror("connect error : ");
        return 1;
    }

    puts("Connected\n");
    if( send(socket_desc , message , message_length, 0) < 0)
    {
        puts("Send failed");
        return 1;
    }
    return 0;
}


void send_mcast_request_list_all_files_msg(uint16_t port, const char* mcast_group)
{
    uint8_t msg[2];
    msg[0] = 1;
    msg[1] = 2;
    send_mcast_msg(msg, 2, port, mcast_group);
}

void send_ucast_request_list_all_files_msg(char *address, int port)
{
    uint8_t msg[2];
    msg[0] = 1;
    msg[1] = 2;
    send_ucast_msg(address, port, msg, 2);
}

struct BE_file_info_list *BE_file_info_list_create_node(BE_file_info element)
{
    struct BE_file_info_list *l = malloc(sizeof(struct BE_file_info_list));
    l->elt = element;
    l->next_elt = NULL;
    return l;
}


/*
  Forcément appelé sur le Backend car c lui qui a la liste des fichiers
*/
struct namelist *read_files_from_backend(const rush_server_config *config)
{
    DIR *watched_dir = opendir(config->watched_dir);
    struct namelist *result = NULL;

    if (!watched_dir)
    {
	//errorcase
	fprintf(stderr, "The directory %s was not found or couldn't be opened\n", config->watched_dir);
	return NULL;
    }
    else
    {
	struct dirent *dp = NULL;
        do
	{
	    if ((dp = readdir(watched_dir)) != NULL)
	    {
		//Si notre dossier n'est pas . ou .. ou nul
		if (dp->d_name && strcpy(dp->d_name, "..") && strcpy(dp->d_name, "."))
		{
		    char* temp;
		    temp = malloc(strlen(dp->d_name) + 1);
		    strcpy(temp, dp->d_name);		    
		    struct namelist *temp_l = malloc(sizeof(struct namelist));
		    temp_l->elt = temp;
		    temp_l->next_elt = NULL;
		    SGLIB_LIST_ADD(struct namelist, result, temp_l, next_elt);
		}
	    }
	} while (dp);
    }
    return result;
}

/*
  Prend en paramètre une liste de BE_file_info, cas d'arrêt quand next_ptr vaut NULL
  Infos est une liste de BE_file_info qui contiennent les champs, pour chaque fichier,
  qui permettront l'ajout dans un message type 3
*/
void send_ucast_list_all_files(struct BE_file_info_list *infos, int port, char *address)
{
    //La taille totale de notre message donc de notre buffer (en octets)
    long long total_size = 2 + 4;
    //La taille de la liste, donc le nombre de fichiers
    long long infos_len = 0;

    //On s'arrête quand on a NULL car à la fin de la liste il y a un ptr NULL
    struct BE_file_info_list *tmp = infos;
    for (long long i = 0; tmp; ++i)
    {
	++infos_len;
	tmp = tmp->next_elt;
    }
    //Pour chaque fichier, on ajoute la taille variable d'un fichier
    tmp = infos;
    for (long long i = 0; tmp; ++i)
    {
	//total_size += 2 + 4 + 1 + (*infos)[i].name_len + 1 + 4 + 1 + 4;
	total_size += 2 + 4 + 1 + tmp->elt.name_len + 1 + 4 + 1 + 4;
	tmp = tmp->next_elt;
    }
    uint8_t result[total_size];
    result[0] = 1;
    result[1] = 3;
    //L'index réel du tableau où écrire
    long long alt_index = 2;
    //On remplit vraiment le buffer du message
    for (long long i = 0; i < infos_len; i++)
    {
	memcpy(result + alt_index, &(infos->elt.name_len), 2);
        alt_index += 2;
	memcpy(result + alt_index, &(infos->elt.nb_BE_having_file), 4);
        alt_index += 4;
	memcpy(result + alt_index, &(infos->elt.dgst_type_file1), 1);
        alt_index += 1;
	memcpy(result + alt_index, &(infos->elt.dgst_type_file1), 1);
        alt_index += 1;
	memcpy(result + alt_index, &(infos->elt.filename), infos->elt.name_len);
        alt_index += infos->elt.name_len;
	memcpy(result + alt_index, &(infos->elt.BE1_addr_type), 1);
        alt_index += 1;
	memcpy(result + alt_index, &(infos->elt.BE1_addr), 4);
        alt_index += 4;
	memcpy(result + alt_index, &(infos->elt.BE2_addr), 1);
        alt_index += 1;
	memcpy(result + alt_index, &(infos->elt.BE2_addr), 4);
        alt_index += 4;
    }
    send_ucast_msg(address, port, result, total_size);
    //On détruit notre liste qui ne sert plus à rien
    SGLIB_LIST_MAP_ON_ELEMENTS(struct BE_file_info_list, infos, tmp, next_elt, {
	    free(tmp->elt.filename);
    	    free(tmp);
    	});
}


void send_mcast_alive(uint16_t port, const char* mcast_group)
{
  uint8_t msg[2];
  msg[0] = 1;
  msg[1] = 7;
  send_mcast_msg(msg, 2, port, mcast_group);
}

void send_mcast_disp_new_file(uint16_t port, const char* mcast_group, char *filename)
{
    uint32_t msglen = 4;
    msglen += strlen(filename);
    uint8_t msg[msglen];
    msg[0] = 1;
    msg[1] = 6;
    uint16_t namelen = strlen(filename);
    memcpy(msg + 2, &namelen, 2);
    memcpy(msg + 4, filename, namelen);
    send_mcast_msg(msg, msglen, port, mcast_group);
}

void send_ucast_req_content_file(char *filename, uint16_t port, char *address)
{
    uint32_t msglen = 4;
    msglen += strlen(filename);
    uint8_t msg[msglen];
    msg[0] = 1;
    msg[1] = 4;
    uint16_t namelen = strlen(filename);
    memcpy(msg + 2, &namelen, 2);
    memcpy(msg + 4, filename, namelen);
    send_ucast_msg(address, port, msg, msglen);
}

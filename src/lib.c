#include "../include/lib.h"

void send_mcast_msg(char *databuf, int datalen, uint16_t port, const char* mcast_group)
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
    close(msocket);
}

void send_mcast_discover(uint16_t port, const char* mcast_group)
{
  char msg[2];
  msg[0] = 1;
  msg[1] = 8;
  send_mcast_msg(&msg, 2, port, mcast_group);
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
        puts("connect error");
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
    char msg[2];
    msg[0] = 1;
    msg[1] = 2;
    send_mcast_msg(msg, 2, port, mcast_group);
}

void send_ucast_request_list_all_files_msg(char *address, int port)
{
    char msg[2];
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
  Prend en paramètre une liste de BE_file_info, cas d'arrêt quand next_ptr vaut NULL
  Infos est une liste de BE_file_info qui contiennent les champs, pour chaque fichier,
  qui permettront l'ajout dans un message type 3
*/
void send_ucast_list_all_files(int nb_files, struct BE_file_info_list *infos, int port, char *address)
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
    	    free(tmp);
    	});
}


void send_mcast_alive(uint16_t port, const char* mcast_group)
{
  char msg[2];
  msg[0] = 1;
  msg[1] = 7;
  send_mcast_msg(&msg, 2, port, mcast_group);
}

void send_mcast_disp_new_file(uint16_t port, const char* mcast_group, char *filename)
{
    uint32_t msglen = 4;
    msglen += strlen(filename);
    char msg[msglen];
    msg[0] = 1;
    msg[1] = 6;
    uint16_t namelen = strlen(filename);
    memcpy(msg + 2, &namelen, 2);
    memcpy(msg + 4, filename, namelen);
    send_mcast_msg(&msg, 2, port, mcast_group);    
}


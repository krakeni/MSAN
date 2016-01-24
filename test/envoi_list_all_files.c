//Pour tester la fonction send_mcast_list_all_files
//Mettre ce code dans le main du frontend par exemple

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../include/rush.h"
#include "../include/lib.h"


int main(void)
{
    
    //TEST
    //La liste des fichiers pour l'instant vide
    struct BE_file_info_list *files_list = NULL;
    //Premier element
    BE_file_info test;
    test.name_len = 3;
    test.nb_BE_having_file = 2;
    test.dgst_type_file1 = 2;
    test.filename = "lol";
    test.BE1_addr_type = 2;
    test.BE1_addr = 192168194;
    test.BE2_addr_type = 2;
    test.BE2_addr = 172168194;
    struct BE_file_info_list *test_l = BE_file_info_list_create_node(test);
    //2eme element
    BE_file_info test2;
    test2.name_len = 4;
    test2.nb_BE_having_file = 2;
    test2.dgst_type_file1 = 2;
    test2.filename = "lelz";
    test2.BE1_addr_type = 2;
    test2.BE1_addr = 193168194;
    test2.BE2_addr_type = 2;
    test2.BE2_addr = 192168194;
    struct BE_file_info_list *test2_l = BE_file_info_list_create_node(test2);
    //On add nos elements dans notre liste (en tête)
    SGLIB_LIST_ADD(BE_file_info, files_list, test_l, next_elt);
    SGLIB_LIST_ADD(BE_file_info, files_list, test2_l, next_elt);
    send_mcast_list_all_files(2, files_list, 4321, "localhost");

    return 1;
}

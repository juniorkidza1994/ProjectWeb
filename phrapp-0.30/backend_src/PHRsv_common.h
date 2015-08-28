#pragma once
#ifndef PHRSV_COMMON_H
#define PHRSV_COMMON_H

#include <my_global.h>
#include <mysql.h>

#include "common.h"
#include "mysql_common.h"
#include "simclist.h"

#define DB_IP 				    "127.0.0.1"
#define DB_USERNAME 			    "root"
#define DB_PASSWD 			    "bright"

#define DB_NAME 			    "PHRDB"

// Tables
#define PHRSV__AUTHORITIES 	            "PHRSV_authorities"
#define PHRSV__PHR_OWNERS 	            "PHRSV_phr_owners"
#define PHRSV__DATA 	          	    "PHRSV_data"

#define PHRSV_CERTFILE_PATH                 "Certs_and_keys_pool/phr_serv.pem"
#define PHRSV_CERTFILE_PASSWD               "bright"

#define PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH "Certs_and_keys_pool/rootCA_cert.pem"
#define SERVER_CA_ONLY_CERT_CERTFILE_PATH   "Certs_and_keys_pool/serverCA_cert.pem"

#define CACHE_DIRECTORY_PATH		    "PHRsv_cache"
#define CACHE_DIRECTORY_PERMISSION_MODE     777

#define PHR_DIRECTORY_PATH		    "PHRsv_phr_store"
#define PHR_DIRECTORY_PERMISSION_MODE       777

#define SQL_STATEMENT_LENGTH                1500

#define MAX_CONCURRENT_OPERATING_THREADS    50
#define INACTIVE_NODE_RELEASE_TIME_PERIOD   5  // in minute unit

struct active_phr_node
{
	unsigned int phr_id;

	unsigned int working_thread_counter;
	sem_t        working_thread_counter_mutex;
	
	unsigned int downloading_thread_counter;
	boolean      mark_delete_flag;

	sem_t        downloading_mutex;
	sem_t        deletion_mutex;
};

typedef struct active_phr_node active_phr_node_t;

// Global Variables
list_t active_phr_node_list;
sem_t  active_phr_node_list_mutex;

sem_t  remaining_operating_thread_counter_sem;
sem_t  wait_for_creating_new_child_thread_mutex;

// Global Function Prototypes
boolean verify_access_granting_ticket(char *access_granting_ticket_buffer, char *ticket_owner_name_cmp, 
	char *ticket_owner_authority_name_cmp, char *phr_owner_name_cmp, char *phr_owner_authority_name_cmp);

boolean verify_access_granting_ticket_lifetime(char *access_granting_ticket_buffer);
boolean verify_access_permission(char *access_granting_ticket_buffer, char *required_operation);

void *authorized_phr_list_loading_main(void *arg);
void *inactive_node_release_main(void *arg);
void *phr_services_main(void *arg);
void *phr_confidentiality_level_changing_main(void *arg);
void *emergency_phr_list_loading_main(void *arg);

#endif




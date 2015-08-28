#pragma once
#ifndef EMS_COMMON_H
#define EMS_COMMON_H

#include <my_global.h>
#include <mysql.h>

#include "common.h"
#include "mysql_common.h"

#define DB_IP 			             "127.0.0.1"
#define DB_USERNAME 		             "root"
#define DB_PASSWD 		             "bright"

#define DB_NAME 		             "PHRDB"

// Tables
#define EMS__BASIC_AUTHORITY_INFO            "EmS_basic_authority_info"
#define EMS__AUTHORITIES		     "EmS_authorities"
#define EMS__USERS			     "EmS_users"
#define EMS__DELEGATIONS		     "EmS_delegations"
#define EMS__SECRET_KEYS		     "EmS_secret_keys"
#define EMS__RESTRICTED_LEVEL_PHRS	     "EmS_restricted_level_phrs"
#define EMS__RESTRICTED_LEVEL_PHR_REQUESTS   "EmS_restricted_level_phr_requests"
#define EMS__SECRET_KEY_APPROVALS	     "EmS_secret_key_approvals"

#define NO_REFERENCE_USERNAME                "no_reference_user"

#define EMS_CERTFILE_PATH                    "Certs_and_keys_pool/emergency_serv.pem"
#define EMS_CERTFILE_PASSWD                  "bright"

#define EMS_EMERGENCY_ACCESS_CERTFILE_PATH   "Certs_and_keys_pool/emergency_serv_emergency_access.pem"
#define EMS_EMERGENCY_ACCESS_CERTFILE_PASSWD "bright"

#define PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH  "Certs_and_keys_pool/rootCA_cert.pem"
#define SERVER_CA_ONLY_CERT_CERTFILE_PATH    "Certs_and_keys_pool/serverCA_cert.pem"     // Use to verify the access granting ticket

#define EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH  "Certs_and_keys_pool/EmU_rootCA_cert.pem"

#define CACHE_DIRECTORY_PATH		     "EmS_cache"
#define CACHE_DIRECTORY_PERMISSION_MODE      777

#define EMS_CPABE_PRIV_KEY_PATH    	     "Certs_and_keys_pool/Enc_EmS_key"
#define EMS_CPABE_PRIV_KEY_PASSWD	     "bright"

#define CPABE_PUB_KEY_PATH                   "Certs_and_keys_pool/pub_key"
#define CPABE_DEC_PATH                       "./cpabe_dec"

#define THRESHOLD_DEC_PATH		     "java -Djava.library.path=. -classpath *:. EmS_ThresholdDecryption"

#define SQL_STATEMENT_LENGTH                 1500

#define MAX_CONCURRENT_OPERATING_THREADS     50

// Shared Variables
unsigned int GLOBAL_authority_id;
char         GLOBAL_authority_name[AUTHORITY_NAME_LENGTH + 1];
char         GLOBAL_user_auth_ip_addr[IP_ADDRESS_LENGTH + 1];
char         GLOBAL_audit_server_ip_addr[IP_ADDRESS_LENGTH + 1];
char         GLOBAL_phr_server_ip_addr[IP_ADDRESS_LENGTH + 1];
char         GLOBAL_mail_server_url[URL_LENGTH + 1];
char         GLOBAL_authority_email_address[EMAIL_ADDRESS_LENGTH + 1];
char         GLOBAL_authority_email_passwd[PASSWD_LENGTH + 1];

sem_t        remaining_operating_thread_counter_sem;
sem_t        wait_for_creating_new_child_thread_mutex;

// Function Prototypes
boolean connect_to_transaction_log_recording_service(SSL **ssl_conn_ret);
boolean get_authority_id(MYSQL *db_conn, char *authority_name, unsigned int *authority_id_ret);
boolean get_user_id(MYSQL *db_conn, char *username, char *authority_name, unsigned int *user_id_ret);

// If authority name does not exist then add it and return its id
unsigned int get_authority_id_if_not_exist_create(MYSQL *db_conn, char *authority_name);

// If username does not exist then add it and return its id
unsigned int get_user_id_if_not_exist_create(MYSQL *db_conn, char *username, char *authority_name);

// "user_authority_name_ret" or "username_ret" or both of them can be NULL
boolean get_user_info(MYSQL *db_conn, unsigned int user_id, char *user_authority_name_ret, char *username_ret);
boolean connect_to_emergency_address_serving_service(SSL **ssl_conn_ret);
boolean get_remote_emergency_server_ip_addr(char *phr_owner_authority_name, char *remote_emergency_server_ip_addr_ret);
boolean check_trusted_user_had_deduction_this_request(MYSQL *db_conn, unsigned int trusted_user_id, unsigned int phr_request_id);
boolean get_access_request_id(MYSQL *db_conn, unsigned int remote_site_phr_id, char *emergency_staff_name, char *emergency_unit_name, unsigned int *phr_request_id_ret);
boolean check_access_request_existence(MYSQL *db_conn, unsigned int remote_site_phr_id, char *emergency_staff_name, char *emergency_unit_name);

void *server_info_management_main(void *arg);
void *emergency_trusted_user_management_main(void *arg);
void *emergency_delegation_list_loading_main(void *arg);
void *restricted_level_phr_key_params_management_main(void *arg);
void *restricted_level_phr_key_params_management_remote_ems_main(void *arg);
void *phr_owner_existence_checking_main(void *arg);
void *emergency_phr_list_loading_main(void *arg);

// "error_msg_ret" can be NULL
boolean send_email(unsigned int nrecipient, char *ptr_target_email_list, unsigned int nline_payload_msg, char *ptr_payload_msg_list, char *error_msg_ret);
void config_email_payload(int index, char *msg, char payload_msg_ret[][EMAIL_MSG_LINE_LENGTH + 1]);

void *synchronization_receiving_main(void *arg);
void *synchronization_responding_main(void *arg);
void *emergency_phr_accessing_main(void *arg);
void *restricted_level_phr_access_requesting_main(void *arg);
void *restricted_level_phr_access_request_list_loading_main(void *arg);
void *restricted_level_phr_access_request_list_loading_remote_ems_main(void *arg);
void *restricted_level_phr_access_request_responding_main(void *arg);
void *restricted_level_phr_access_request_responding_remote_ems_main(void *arg);

#endif




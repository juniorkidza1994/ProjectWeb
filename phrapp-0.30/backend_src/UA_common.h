#pragma once
#ifndef UA_COMMON_H
#define UA_COMMON_H

#include <my_global.h>
#include <mysql.h>

#include "common.h"
#include "mysql_common.h"

#define DB_IP 				     "127.0.0.1"
#define DB_USERNAME 			     "root"
#define DB_PASSWD 			     "bright"

#define DB_NAME 			     "PHRDB"

// Tables
#define UA__BASIC_AUTHORITY_INFO 	     "UA_basic_authority_info"
#define UA__AUTHORITIES          	     "UA_authorities"
#define UA__ATTRIBUTES			     "UA_attributes"
#define UA__ADMINS			     "UA_admins"
#define UA__USERS		    	     "UA_users"
#define UA__USER_ATTRIBUTES		     "UA_user_attributes"
#define UA__ACCESS_PERMISSIONS		     "UA_access_permissions"
#define UA__PERMISSIONS_ASSIGNED_TO_OTHERS   "UA_permissions_assigned_to_others"
#define UA__USERS_IN_OTHER_AUTHORITIES	     "UA_users_in_other_authorities"

// These are reserved usernames so these names couldn't be registered by the user registration module
#define NO_REFERENCE_USERNAME                "no_reference_user"
#define INVALID_USERNAME                     "invalid_user"
#define PASSWD_FORGETTOR_NAME                "password_forgettor"
#define ITS_ADMIN_NAME                       "its_administrator"
#define REFERENCE_TO_ALL_ADMIN_NAMES         "reference_to_all_administrators"

#define UA_PUB_CERTFILE_PATH                 "Certs_and_keys_pool/user_auth_cert.pem"
#define UA_CERTFILE_PATH                     "Certs_and_keys_pool/user_auth.pem"
#define UA_CERTFILE_PASSWD                   "bright"

#define PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH  "Certs_and_keys_pool/rootCA_cert.pem"
#define USER_CA_ONLY_CERT_CERTFILE_PATH      "Certs_and_keys_pool/userCA_cert.pem"

#define USER_CA_FULL_CERTFILE_PATH           "Certs_and_keys_pool/userCA.pem"
#define USER_CA_CERTFILE_PASSWD              "bright"

#define OPENSSL_PHRAPP_CNF_PATH              "Certs_and_keys_pool/PHRapp_OpenSSL.cnf"

#define CPABE_PUB_KEY_PATH                   "Certs_and_keys_pool/pub_key"
#define CPABE_MASTER_KEY_PATH                "Certs_and_keys_pool/master_key"
#define CPABE_KEYGEN_PATH                    "./cpabe_keygen"

#define CACHE_DIRECTORY_PATH		     "UA_cache"
#define CACHE_DIRECTORY_PERMISSION_MODE      777

#define SQL_STATEMENT_LENGTH                 3000
#define CMD_STATEMENT_LENGTH                 1000
#define ATTRIBUTE_TOKEN_LENGTH               100
#define SALT_VALUE_LENGTH		     8

#define ACCESS_GRANTING_TICKET_LIFETIME      10 // in minute unit
#define SYNCHRONIZATION_TIME_PERIOD          1  // in minute unit

#define AUTHORITY_JOINING_REQUESTING         "authority joining requesting"
#define AUTHORITY_JOINING_APPROVAL           "authority joining approval"
#define AUTHORITY_JOINING_NO_APPROVAL        "authority joining no approval"

#define AUTHORITY_SYNCHRONIZATION_REQUESTING "authority synchronization requesting"
#define AUTHORITY_SYNCHRONIZATION_APPROVAL   "authority synchronization approval"
#define AUTHORITY_REVOCATION                 "authority revocation"

// Shared Variables
unsigned int GLOBAL_authority_id;
char         GLOBAL_authority_name[AUTHORITY_NAME_LENGTH + 1];
char         GLOBAL_audit_server_ip_addr[IP_ADDRESS_LENGTH + 1];
char         GLOBAL_phr_server_ip_addr[IP_ADDRESS_LENGTH + 1];
char         GLOBAL_emergency_server_ip_addr[IP_ADDRESS_LENGTH + 1];
char         GLOBAL_mail_server_url[URL_LENGTH + 1];
char         GLOBAL_authority_email_address[EMAIL_ADDRESS_LENGTH + 1];
char         GLOBAL_authority_email_passwd[PASSWD_LENGTH + 1];
char         *GLOBAL_pub_key_data;

sem_t        sync_lock_mutex;
sem_t        email_sending_lock_mutex;  // since we have the shared variable 'payload_msg'

// Function Prototypes
boolean connect_to_transaction_log_recording_service(SSL **ssl_conn_ret);
void gen_random_salt_value(char *salt_value_ret);   // Generate a random 8 character salt value

void *user_authentication_main(void *arg);
void *attribute_management_main(void *arg);
void *attribute_list_loading_main(void *arg);
void *user_management_main(void *arg);
void *user_list_loading_main(void *arg);
void *authority_management_main(void *arg);
void *authority_list_loading_main(void *arg);
void *access_permission_management_main(void *arg);
void *assigned_access_permission_list_loading_main(void *arg);
void *user_existence_checking_main(void *arg);
void *access_granting_ticket_responding_main(void *arg);
void *user_attribute_list_loading_main(void *arg);
void *user_info_management_main(void *arg);

void generate_ssl_cert(MYSQL *db_conn, unsigned int user_id, char *username, boolean is_admin_flag, char *passwd, char *email_address, 
	const char *ssl_cert_priv_key_path, const char *ssl_cert_req_path, const char *enc_ssl_cert_path, const char *full_enc_ssl_cert_path, 
	const char *full_enc_ssl_cert_hash_path);

void generate_cpabe_priv_key(MYSQL *db_conn, unsigned int user_id, char *username, char *passwd, const char *cpabe_priv_key_path, 
	const char *enc_cpabe_priv_key_path, const char *enc_cpabe_priv_key_hash_path);

boolean send_passwd_to_user_email_address(char *email_to, char *username, boolean is_admin_flag, char *passwd);

// "result_flag_msg" can be NULL if send_result_flag = false
boolean remove_all_user_info(SSL *ssl_client, MYSQL *db_conn, unsigned int user_id, char *username, boolean send_result_flag, char *result_flag_msg);

void *user_passwd_resetting_main(void *arg);

void *pub_key_serving_main(void *arg);
void *synchronization_requesting_main(void *arg);
void *synchronization_responding_main(void *arg);
void remove_attribute_list_of_authority(MYSQL *db_conn, unsigned int authority_id);
void remove_user_list_of_authority(SSL *ssl_client, MYSQL *db_conn, unsigned int authority_id, char *authority_name, boolean authority_revoked_by_its_admin);
void *server_info_management_main(void *arg);
void send_email_config_payload(int index, char *msg);
boolean send_email(char *email_to);
char *get_send_email_error_msg();
void *emergency_key_management_main(void *arg);
void *emergency_address_serving_main(void *arg);

#endif




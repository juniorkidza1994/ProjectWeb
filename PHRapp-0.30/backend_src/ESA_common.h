#pragma once
#ifndef ESA_COMMON_H
#define ESA_COMMON_H

#include <my_global.h>
#include <mysql.h>

#include "common.h"
#include "mysql_common.h"

#define DB_IP 				     	      "127.0.0.1"
#define DB_USERNAME 			     	      "root"
#define DB_PASSWD 			     	      "bright"

#define DB_NAME 			     	      "EmUDB"

// Tables
#define ESA__BASIC_AUTHORITY_INFO 	     	      "ESA_basic_authority_info"
#define ESA__ADMINS			     	      "ESA_admins"
#define ESA__USERS			     	      "ESA_users"
#define ESA__PHR_AUTHORITIES		     	      "ESA_phr_authorities"
	     
#define ESA_PUB_CERTFILE_PATH                	      "Certs_and_keys_pool/emergency_staff_auth_cert.pem"
#define ESA_CERTFILE_PATH                    	      "Certs_and_keys_pool/emergency_staff_auth.pem"
#define ESA_CERTFILE_PASSWD                  	      "bright"

#define EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH           "Certs_and_keys_pool/EmU_rootCA_cert.pem"
#define USER_CA_ONLY_CERT_CERTFILE_PATH      	      "Certs_and_keys_pool/EmU_userCA_cert.pem"

#define USER_CA_FULL_CERTFILE_PATH           	      "Certs_and_keys_pool/EmU_userCA.pem"
#define USER_CA_CERTFILE_PASSWD              	      "bright"

#define OPENSSL_PHRAPP_CNF_PATH              	      "Certs_and_keys_pool/PHRapp_OpenSSL.cnf"

#define CACHE_DIRECTORY_PATH		     	      "ESA_cache"
#define CACHE_DIRECTORY_PERMISSION_MODE      	      777

#define SQL_STATEMENT_LENGTH                 	      3000
#define CMD_STATEMENT_LENGTH                 	      1000
#define SALT_VALUE_LENGTH		     	      8

#define EMERGENCY_STAFF_AUTHENTICATION_TOKEN_LIFETIME 10 // in minute unit

// Shared Variables
char  GLOBAL_authority_name[AUTHORITY_NAME_LENGTH + 1];
char  GLOBAL_mail_server_url[URL_LENGTH + 1];
char  GLOBAL_authority_email_address[EMAIL_ADDRESS_LENGTH + 1];
char  GLOBAL_authority_email_passwd[PASSWD_LENGTH + 1];
char  *GLOBAL_pub_key_data;

sem_t email_sending_lock_mutex;  // since we have the shared variable 'payload_msg'

// Function Prototypes
void gen_random_salt_value(char *salt_value_ret);   // Generate a random 8 character salt value

void *user_authentication_main(void *arg);
void *pub_key_serving_main(void *arg);
void *user_info_management_main(void *arg);
void *server_info_management_main(void *arg);
void *user_list_loading_main(void *arg);
void *phr_authority_list_loading_main(void *arg);
void *user_management_main(void *arg);
void *phr_authority_management_main(void *arg);
void *user_passwd_resetting_main(void *arg);

void generate_ssl_cert(MYSQL *db_conn, unsigned int user_or_admin_id, char *username, boolean is_admin_flag, char *passwd, char *email_address, 
	const char *ssl_cert_priv_key_path, const char *ssl_cert_req_path, const char *enc_ssl_cert_path, const char *full_enc_ssl_cert_path, 
	const char *full_enc_ssl_cert_hash_path);

boolean send_passwd_to_user_email_address(char *email_to, char *username, boolean is_admin_flag, char *passwd);
void send_email_config_payload(int index, char *msg);
boolean send_email(char *email_to);
char *get_send_email_error_msg();

#endif




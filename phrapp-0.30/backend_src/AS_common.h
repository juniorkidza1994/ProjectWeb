#pragma once
#ifndef AS_COMMON_H
#define AS_COMMON_H

#include <my_global.h>
#include <mysql.h>

#include "common.h"
#include "mysql_common.h"

#define DB_IP 			            "127.0.0.1"
#define DB_USERNAME 		            "root"
#define DB_PASSWD 		            "bright"

#define DB_NAME 		            "PHRDB"

#define PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH "Certs_and_keys_pool/rootCA_cert.pem"

// Tables
#define AS__BASIC_AUTHORITY_INFO            "AS_basic_authority_info"
#define AS__AUTHORITIES                     "AS_authorities"
#define AS__USERS		            "AS_users"
#define AS__LOGIN_LOGS		            "AS_login_logs"
#define AS__EVENT_LOGS		            "AS_event_logs"

#define NO_REFERENCE_USERNAME               "no_reference_user"
#define REFERENCE_TO_ALL_ADMIN_NAMES        "reference_to_all_administrators"

#define AS_CERTFILE_PATH                    "Certs_and_keys_pool/aud_serv.pem"
#define AS_CERTFILE_PASSWD                  "bright"

#define CACHE_DIRECTORY_PATH		    "AS_cache"
#define CACHE_DIRECTORY_PERMISSION_MODE     777

#define SQL_STATEMENT_LENGTH                1500

// Shared Variables
unsigned int GLOBAL_authority_id;
char         GLOBAL_authority_name[AUTHORITY_NAME_LENGTH + 1];
unsigned int GLOBAL_no_reference_user_id;
unsigned int GLOBAL_reference_to_all_admins_id;

// Function Prototypes
unsigned int get_user_id(MYSQL *db_conn, char *username, char *authority_name, boolean is_admin_flag);  // If username does not exist then add it and return its id
boolean get_user_info(MYSQL *db_conn, unsigned int user_id, char *username_ret, char *user_authority_name_ret, boolean *is_subject_user_admin_flag_ret);

void *transaction_log_recording_main(void *arg);
void *transaction_log_auditing_main(void *arg);
void *phr_transaction_log_synchronization_main(void *arg);

#endif




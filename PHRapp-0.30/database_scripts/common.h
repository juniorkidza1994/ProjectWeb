#pragma once
#ifndef COMMON_H
#define COMMON_H

#include <my_global.h>
#include <mysql.h>

#define DB_IP 				   "127.0.0.1"
#define DB_USERNAME 			   "root"
#define DB_PASSWD 			   "bright"

#define PHRDB_NAME 			   "PHRDB"
#define EMUDB_NAME 			   "EmUDB"

#define NO_REFERENCE_USERNAME              "no_reference_user"
#define REFERENCE_TO_ALL_ADMIN_NAMES       "reference_to_all_administrators"

// User Authority
#define UA__BASIC_AUTHORITY_INFO 	   "UA_basic_authority_info"
#define UA__AUTHORITIES          	   "UA_authorities"
#define UA__ATTRIBUTES			   "UA_attributes"
#define UA__ADMINS			   "UA_admins"
#define UA__USERS			   "UA_users"
#define UA__USER_ATTRIBUTES		   "UA_user_attributes"
#define UA__ACCESS_PERMISSIONS		   "UA_access_permissions"
#define UA__PERMISSIONS_ASSIGNED_TO_OTHERS "UA_permissions_assigned_to_others"
#define UA__USERS_IN_OTHER_AUTHORITIES	   "UA_users_in_other_authorities"

// Audit Server
#define AS__BASIC_AUTHORITY_INFO 	   "AS_basic_authority_info"
#define AS__AUTHORITIES		 	   "AS_authorities"
#define AS__USERS		 	   "AS_users"
#define AS__LOGIN_LOGS		 	   "AS_login_logs"
#define AS__EVENT_LOGS		 	   "AS_event_logs"

// PHR Server
#define PHRSV__AUTHORITIES 		   "PHRSV_authorities"
#define PHRSV__PHR_OWNERS		   "PHRSV_phr_owners"
#define PHRSV__DATA			   "PHRSV_data"

// Emergency Server
#define EMS__BASIC_AUTHORITY_INFO          "EmS_basic_authority_info"
#define EMS__AUTHORITIES		   "EmS_authorities"
#define EMS__USERS			   "EmS_users"
#define EMS__DELEGATIONS		   "EmS_delegations"
#define EMS__SECRET_KEYS		   "EmS_secret_keys"
#define EMS__RESTRICTED_LEVEL_PHRS	   "EmS_restricted_level_phrs"
#define EMS__RESTRICTED_LEVEL_PHR_REQUESTS "EmS_restricted_level_phr_requests"
#define EMS__SECRET_KEY_APPROVALS	   "EmS_secret_key_approvals"

// Emergency Staff Authority
#define ESA__BASIC_AUTHORITY_INFO 	   "ESA_basic_authority_info"
#define ESA__ADMINS			   "ESA_admins"
#define ESA__USERS			   "ESA_users"
#define ESA__PHR_AUTHORITIES		   "ESA_phr_authorities"

#define USER_NAME_LENGTH		   50
#define SALT_VALUE_LENGTH		   8
#define PASSWD_RESETTING_CODE_LENGTH       8

#define ATTRIBUTE_NAME_LENGTH		   50
#define EMAIL_ADDRESS_LENGTH		   50
#define AUTHORITY_NAME_LENGTH		   50
#define PASSWD_LENGTH                      50
#define URL_LENGTH                         80
#define IP_ADDRESS_LENGTH                  15
#define EVENT_DESCRIPTION_LENGTH           300
#define DATA_DESCRIPTION_LENGTH            500
#define FLAG_LENGTH                        1

#define EMERGENCY_UNIT_NAME_LENGTH	   50
#define EMERGENCY_STAFF_NAME_LENGTH	   50

#define SHA1_DIGEST_LENGTH                 40
#define SQL_STATEMENT_LENGTH               1000

#define SSL_PUB_KEY_LENGTH		   2000

#endif




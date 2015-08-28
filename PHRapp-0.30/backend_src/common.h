#pragma once
#ifndef COMMON_H
#define COMMON_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif
#include <time.h>
#include <sys/time.h>
#include <semaphore.h>

// Macros
#define THREAD_TYPE                                               pthread_t
#define THREAD_CREATE(tid, entry, arg)                            pthread_create(&(tid), NULL, (entry), (arg))
#define THREAD_DETACH(tid)	                                  pthread_detach(tid)
#define THREAD_ID                                                 pthread_self()
#define THREAD_JOIN(tid)	                                  pthread_join(tid, NULL)
#define THREAD_CANCEL(tid)	                                  pthread_cancel(tid)

#define int_error(msg)                                            handle_error(__FILE__, __LINE__, msg)

#define MUTEX_TYPE                                                pthread_mutex_t
#define MUTEX_SETUP(x)                                            pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x)                                          pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x)                                             pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)                                           pthread_mutex_unlock(&(x))

// Constant Variables
#define USER_NAME_LENGTH	                                  50
#define ATTRIBUTE_NAME_LENGTH	                                  50
#define ATTRIBUTE_VALUE_LENGTH                                    10
#define EMAIL_ADDRESS_LENGTH	                                  50
#define AUTHORITY_NAME_LENGTH	                                  50
#define PASSWD_LENGTH                                             50
#define URL_LENGTH                                                80
#define IP_ADDRESS_LENGTH                                         15
#define PORT_NUMBER_LENGTH                                        5
#define EVENT_DESCRIPTION_LENGTH                                  300
#define PHR_OPERATION_NAME_LENGTH                                 15
#define DATA_DESCRIPTION_LENGTH                                   500
#define PASSWD_RESETTING_CODE_LENGTH                              8
#define EMAIL_MSG_LINE_LENGTH                                     520

#define ERR_MSG_LENGTH                                            300
#define BUFFER_LENGTH                                             990
#define LARGE_BUFFER_LENGTH				          2970
#define REQUEST_TYPE_LENGTH                                       100
#define RESULT_LENGTH                                             50
#define TOKEN_NAME_LENGTH                                         100
#define TOKEN_VALUE_LENGTH                                        50
#define SHA1_DIGEST_LENGTH                                        40
#define FLAG_LENGTH                                               1   // '0' or '1'
#define PATH_LENGTH                                               350
#define FILENAME_LENGTH                                           80
#define RESTRICTED_PHR_REQUEST_STATUS_LENGTH		          16  // RESTRICTED_PHR_NO_REQUEST, RESTRICTED_PHR_REQUEST_PENDING or RESTRICTED_PHR_REQUEST_APPROVAL

#define INT_TO_STR_DIGITS_LENGTH                                  10
#define DATETIME_STR_LENGTH                                       19

#define OCTET_PERMISSION_MODE_LENGTH                              3   // E.g., 777 -> allow all users in the system

#define SSL_PUB_KEY_LENGTH				          2000

// Boolean
typedef enum
{
	false = 0, true = 1
}boolean;

// Entity Type
typedef enum
{
	admin = 0, user = 1, server = 2
}entity_type;

// Read Token
#define READ_TOKEN_SUCCESS                                        	0
#define READ_TOKEN_END                                            	1
#define READ_TOKEN_INVALID                                        	2

// User Types
#define USER_IDENTITY_TOKEN                                       	"(User)"
#define ADMIN_IDENTITY_TOKEN                                      	"(Admin)"

// PHR confidentiality levels
#define PHR_SECURE_LEVEL_FLAG				          	"0"
#define PHR_RESTRICTED_LEVEL_FLAG			          	"1"
#define PHR_EXCLUSIVE_LEVEL_FLAG			         	"2"      // By default

// PHR Operation Types
#define PHR_UPLOADING                                             	"PHR uploading"
#define PHR_DOWNLOADING					          	"PHR downloading"
#define PHR_DELETION					          	"PHR deletion"

// Restricted-level PHR request statuses
#define RESTRICTED_PHR_NO_REQUEST			          	"No request"
#define RESTRICTED_PHR_REQUEST_PENDING			          	"Request pending"
#define RESTRICTED_PHR_REQUEST_APPROVED			          	"Request approved"

#define ATTRIBUTE_REGISTRATION                                    	"attribute registration"
#define ATTRIBUTE_REMOVAL                                         	"attribute removal"

#define USER_REGISTRATION				          	"user registration"
#define USER_EMAIL_ADDRESS_AND_ATTRIBUTE_LIST_EDITING             	"user e-mail address and attribute list editing"
#define USER_EMAIL_ADDRESS_EDITING                                	"user e-mail address editing"
#define USER_ATTRIBUTE_LIST_EDITING   			          	"user attribute list editing"
#define USER_ATTRIBUTE_VALUE_EDITING                              	"user attribute value editing"
#define USER_PASSWD_RESETTING                                     	"user passwd resetting"
#define USER_REMOVAL                                              	"user removal"
#define USER_ATTRIBUTE_REMOVAL                                    	"user attribute removal"
#define ADMIN_REGISTRATION				          	"admin registration"
#define ADMIN_EMAIL_ADDRESS_EDITING                               	"admin e-mail address editing"
#define ADMIN_PASSWD_RESETTING				          	"admin passwd resetting"
#define ADMIN_REMOVAL                                             	"admin removal"

#define PASSWD_CHANGING                                           	"passwd changing"
#define EMAIL_ADDRESS_CHANGING                                    	"e-mail address changing"

#define AUTHORITY_REGISTRATION                                    	"authority registration"
#define AUTHORITY_IP_ADDRESS_EDITING			          	"authority ip address editing"
#define AUTHORITY_REMOVAL                                         	"authority removal"

#define ACCESS_PERMISSION_ASSIGNMENT                              	"access permission assignment"
#define ACCESS_PERMISSION_EDITING                                 	"access permission auditing"
#define ACCESS_PERMISSION_REMOVAL                                 	"access permission removal"

#define PASSWD_RESETTING_CODE_REQUESTING                          	"passwd resetting code requesting"
#define PASSWD_RESETTING               			          	"passwd resetting"

#define SERVER_ADDRESSES_CONFIGURATION_CHANGING                   	"server addresses configuration changing"
#define MAIL_SERVER_CONFIGURATION_CHANGING                        	"mail server configuration changing"

#define LOGIN_LOG_RECORDING				          	"login log recording"
#define LOGOUT_LOG_RECORDING				          	"logout log recording"
#define EVENT_LOG_RECORDING				          	"event log recording"
#define MULTIPLE_EVENT_LOGS_RECORDING                             	"multiple event logs recording"
#define PHR_LOG_SYNCHRONIZATION				          	"PHR log synchronization"

#define USER_LOGIN_LOG_AUDITING				          	"user login log auditing"
#define ADMIN_LOGIN_LOG_AUDITING			          	"admin login log auditing"
#define SYSTEM_LOGIN_LOG_AUDITING			          	"system login log auditing"
#define USER_EVENT_LOG_AUDITING				          	"user event log auditing"
#define ADMIN_EVENT_LOG_AUDITING			          	"admin event log auditing"
#define SYSTEM_EVENT_LOG_AUDITING			          	"system event log auditing"

#define EMERGENCY_TRUSTED_USER_ADDING                             	"emergency trusted user adding"
#define EMERGENCY_TRUSTED_USER_REMOVAL                            	"emergency trusted user removal"

#define EMERGENCY_TRUSTED_USER_LIST_LOADING		          	"emergency trusted user list loading"
#define EMERGENCY_PHR_OWNER_LIST_LOADING		          	"emergency phr owner list loading"

#define EMERGENCY_KEY_GENERATING			          	"emergency key generating"
#define EMERGENCY_TRUSTED_USER_PUB_KEY_LIST_REQUESTING	          	"emergency trusted user pub key list requesting"

#define RESTRICTED_LEVEL_PHR_KEY_PARAMS_UPLOADING	          	"restricted level phr key params uploading"
#define RESTRICTED_LEVEL_PHR_KEY_PARAMS_REMOVAL		          	"restricted level phr key params removal"

#define REMOTE_EMERGENCY_SERVER_ADDR_REQUESTING                   	"remote emergency server addr requesting"
#define EMERGENCY_USER_EMAIL_ADDR_REQUESTING    	          	"emergency user email addr requesting"

#define PHR_AUTHORITY_REGISTRATION                                	"phr authority registration"
#define PHR_AUTHORITY_IP_ADDRESS_EDITING		          	"phr authority ip address editing"
#define PHR_AUTHORITY_REMOVAL                                     	"phr authority removal"

#define EMERGENCY_PHR_LIST_LOADING                                	"emergency phr list loading"
#define REQUESTED_RESTRICTED_LEVEL_PHR_LIST_LOADING               	"requested restricted level phr list loading"
#define REQUESTED_RESTRICTED_LEVEL_PHR_INFO_LOADING               	"requested restricted level phr information loading"
#define ONLY_RESTRICTED_LEVEL_PHR_LIST_LOADING 		          	"only restricted level phr list loading"

#define SECURE_LEVEL_PHR_ACCESSING			          	"secure level phr accessing"
#define RESTRICTED_LEVEL_PHR_ACCESSING			          	"restricted level phr accessing"

#define RESTRICTED_LEVEL_PHR_ACCESS_REQUESTING		          	"restricted level phr access requesting"
#define RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_CANCELLATION          	"restricted level phr access request cancellation"

#define RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_TRUSTED_USER_APPROVAL       "restricted level phr access request trusted user approval"
#define RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_TRUSTED_USER_NO_APPROVAL	"restricted level phr access request trusted user no approval"
#define RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_PHR_OWNER_CANCELLATION	"restricted level phr access request phr owner cancellation"

// Tranaction log messages
#define NO_SPECIFIC_DATA				          	     "-"

#define USER_LOGIN_LOG_AUDITING_MSG			          	     "Actor audited his/her login log"
#define ADMIN_LOGIN_LOG_AUDITING_MSG			          	     "Actor(admin) audited his/her login log"
#define SYSTEM_LOGIN_LOG_AUDITING_MSG			          	     "Actor(admin) audited the system login log"
#define USER_EVENT_LOG_AUDITING_MSG			          	     "Actor audited his/her event log"
#define ADMIN_EVENT_LOG_AUDITING_MSG			          	     "Actor(admin) audited his/her event log"
#define SYSTEM_EVENT_LOG_AUDITING_MSG			          	     "Actor(admin) audited the system event log"

#define PHR_ENCRYPTION_SUCCEEDED			         	     "Actor encrypted the PHR"
#define PHR_ENCRYPTION_FAILED				          	     "Actor failed to encrypt the PHR"
#define PHR_UPLOAD_SUCCEEDED				          	     "Actor uploaded the PHR"
#define PHR_UPLOAD_FAILED				          	     "Actor failed to upload the PHR"
#define PHR_DOWNLOAD_SUCCEEDED				          	     "Actor downloaded the PHR"
#define PHR_DOWNLOAD_FAILED				          	     "Actor failed to download the PHR"
#define PHR_DECRYPTION_SUCCEEDED			          	     "Actor decrypted the PHR"
#define PHR_DECRYPTION_FAILED				          	     "Actor failed to decrypt the PHR"
#define PHR_DELETION_SUCCEEDED				          	     "Actor deleted the PHR"
#define PHR_DELETION_FAILED				          	     "Actor failed to delete the PHR"

#define EMERGENCY_KEY_PARAMS_UPLOADING_FAILED                     	     "Actor failed to upload the restricted-level PHR's emergency key parameters. Therefore, the PHR must be changed the confidentiality level from the restricted-level to the exclusive-level."

#define EMERGENCY_TRUSTED_USER_ADDING_MSG		          	     "Actor added his/her emergency trusted user"
#define EMERGENCY_TRUSTED_USER_REMOVING_MSG		          	     "Actor removed the emergency trusted user"

#define ACCESS_PERMISSION_ASSIGNMENT_MSG                          	     "Actor assigned the access permissions to the user"
#define ACCESS_PERMISSION_EDITING_MSG                             	     "Actor edited the access permissions that was assigned to the user"
#define ACCESS_PERMISSION_REMOVAL_MSG                             	     "Actor removed the access permissions that was assigned to the user"

#define ATTRIBUTE_REGISTRATION_MSG                                	     "Actor registered the attribute"
#define ATTRIBUTE_REMOVAL_MSG                                     	     "Actor removed the attribute"

#define AUTHORITY_REGISTRATION_MSG                                	     "Actor registered the authority"
#define AUTHORITY_IP_ADDRESS_EDITING_MSG		          	     "Actor editted the authority's IP address"
#define AUTHORITY_REMOVAL_MSG                                     	     "Actor removed the authority"

#define ACCESS_PERMISSION_GRANTED_USER_WAS_REMOVED                	     "Actor removed the user that you granted the access permissions to"

#define AUDIT_SERVER_IP_ADDRESS_CHANGING_MSG		          	     "Actor changed the audit server's IP address"
#define PHR_SERVER_IP_ADDRESS_CHANGING_MSG		          	     "Actor changed the PHR server's IP address"
#define EMERGENCY_SERVER_IP_ADDRESS_CHANGING_MSG	          	     "Actor changed the emergency server's IP address"

#define MAIL_SERVER_URL_CHANGING_MSG			          	     "Actor changed the mail server url"
#define AUTHORITY_EMAIL_ADDRESS_CHANGING_MSG		          	     "Actor changed the authority's e-mail address"
#define AUTHORITY_EMAIL_PASSWD_CHANGING_MSG		          	     "Actor changed the authority's e-mail password"

#define USER_EMAIL_ADDRESS_CHANGING_MSG			          	     "Actor changed the user's e-mail address"
#define ADMIN_EMAIL_ADDRESS_CHANGING_MSG		          	     "Actor changed the admin's e-mail address"

#define PASSWD_RESETTING_CODE_REQUESTING_MSG		          	     "Actor requested the password resetting code"
#define INVALID_PASSWD_RESETTING_CODE_MSG		          	     "Actor provided the invalid password resetting code"
#define PASSWD_RESETTING_SUCCEEDED_MSG			          	     "Actor resetted the password"

#define USER_REGISTRATION_MSG				         	     "Actor registered the user"
#define USER_REMOVAL_MSG				         	     "Actor removed the user"

#define ADMIN_REGISTRATION_MSG				          	     "Actor registered the admin"
#define ADMIN_REMOVAL_MSG				          	     "Actor removed the admin"

#define USER_ATTRIBUTE_ADDING_MSG			          	     "Actor added the user's attribute"
#define USER_ATTRIBUTE_CHANGING_MSG			          	     "Actor changed the user's attribute"
#define USER_ATTRIBUTE_VALUE_CHANGING_MSG		          	     "Actor changed the user's attribute value"
#define USER_ATTRIBUTE_REMOVAL_MSG			          	     "Actor removed the user's attribute"

#define ATTRIBUTE_ASSINGED_TO_USER_WAS_REMOVED		          	     "Actor removed the attribute so the user's attribute is also removed"

#define USER_PASSWD_RESETTING_MSG			          	     "Actor resetted the user's password"
#define ADMIN_PASSWD_RESETTING_MSG			          	     "Actor resetted the admin's password"

#define USER_PASSWD_CHANGING_MSG			          	     "Actor changed the user's password"
#define ADMIN_PASSWD_CHANGING_MSG			          	     "Actor changed the admin's password"

#define SECURE_LEVEL_PHR_ACCESSING_MSG			         	     "Actor downloaded the secure-level PHR"
#define RESTRICTED_LEVEL_PHR_ACCESSING_MSG		         	     "Actor downloaded the restricted-level PHR"

#define RESTRICTED_LEVEL_PHR_ACCESS_REQUESTING_MSG		  	     "Actor requested an access to the restricted-level PHR"
#define RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_CANCELLATION_MSG      	     "Actor cancelled the access request on the restricted-level PHR"

#define RESTRICTED_LEVEL_PHR_ACCESS_REQUESTING__TRUSTED_USER_MSG             "Actor requested an access to your emergency PHR owner's restricted-level PHR"
#define RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_CANCELLATION__TRUSTED_USER_MSG   "Actor cancelled the access request on your emergency PHR owner's restricted-level PHR"

#define TRUSTED_USER_APPROVES_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_MSG	     "Actor approved the access request on the restricted-level PHR requested by the emergency staff"
#define TRUSTED_USER_NOT_APPROVE_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_MSG     "Actor rejected the access request on the restricted-level PHR requested by the emergency staff"

// Entity Canonical Names
#define ADMIN_CN                                                  	     "Admin"
#define USER_CN                                                   	     "User"
#define USER_AUTH_CN                                              	     "User Authority"
#define AUDIT_SERVER_CN                                           	     "Audit Server"
#define PHR_SERVER_CN                                             	     "PHR Server"
#define EMERGENCY_SERVER_CN				          	     "Emergency Server"
#define EMERGENCY_STAFF_AUTH_CN				          	     "Emergency Staff Authority"

// Service Ports
#define UA_USER_AUTHENTICATION_PORT                               	     "6001"
#define UA_ATTRIBUTE_MANAGEMENT_PORT                             	     "6002"
#define UA_ATTRIBUTE_LIST_LOADING_PORT                           	     "6003"
#define UA_USER_MANAGEMENT_PORT                                   	     "6004"
#define UA_USER_LIST_LOADING_PORT                                 	     "6005"
#define UA_AUTHORITY_MANAGEMENT_PORT                              	     "6006"
#define UA_AUTHORITY_LIST_LOADING_PORT                            	     "6007"
#define UA_ACCESS_PERMISSION_MANAGEMENT_PORT                      	     "6008"
#define UA_ASSIGNED_ACCESS_PERMISSION_LIST_LOADING_PORT           	     "6009"
#define UA_USER_EXISTENCE_CHECKING_PORT                           	     "6010"
#define UA_ACCESS_GRANTING_TICKET_RESPONDING_PORT                 	     "6011"
#define UA_USER_ATTRIBUTE_LIST_LOADING_PORT                       	     "6012"
#define UA_USER_INFO_MANAGEMENT_PORT                              	     "6013"
#define UA_USER_PASSWD_RESETTING_PORT                             	     "6014"
#define UA_PUB_KEY_SERVING_PORT                                   	     "6015"
#define UA_SYNCHRONIZATION_RESPONDING_PORT                        	     "6016"      //****
#define UA_SERVER_INFO_MANAGEMENT_PORT                            	     "6017"
#define UA_EMERGENCY_KEY_MANAGEMENT_PORT		          	     "6018"
#define UA_EMERGENCY_ADDRESS_SERVING_PORT		          	     "6019"
#define AS_TRANSACTION_LOG_RECORDING_PORT                         	     "6020"
#define AS_TRANSACTION_LOG_AUDITING_PORT                     	             "6021"
#define AS_PHR_TRANSACTION_LOG_SYNCHRONIZATION_PORT          	             "6022"
#define PHRSV_PHR_SERVICES_PORT                              	             "6023"
#define PHRSV_AUTHORIZED_PHR_LIST_LOADING_PORT               	             "6024"
#define PHRSV_CONFIDENTIALITY_LEVEL_CHANGING_PORT            	             "6025"
#define PHRSV_EMERGENCY_PHR_LIST_LOADING_PORT      	                     "6026"
#define EMS_SERVER_INFO_MANAGEMENT_PORT                     	             "6027"
#define EMS_EMERGENCY_TRUSTED_USER_MANAGEMENT_PORT                	     "6028"
#define EMS_EMERGENCY_DELEGATION_LIST_LOADING_PORT                	     "6029"
#define EMS_RESTRICTED_LEVEL_PHR_KEY_MANAGEMENT_PORT	          	     "6030"
#define EMS_RESTRICTED_LEVEL_PHR_KEY_MANAGEMENT_REMOTE_EMS_PORT   	     "6031"
#define EMS_PHR_OWNER_EXISTENCE_CHECKING_PORT                     	     "6032"
#define EMS_EMERGENCY_PHR_LIST_LOADING_PORT                       	     "6033"
#define EMS_DELEGATION_SYNCHRONIZATION_RECEIVING_PORT             	     "6034"
#define EMS_DELEGATION_SYNCHRONIZATION_RESPONDING_PORT            	     "6035"
#define EMS_EMERGENCY_PHR_ACCESSING_PORT                          	     "6036"
#define EMS_RESTRICTED_LEVEL_PHR_ACCESS_REQUESTING_PORT           	     "6037"
#define EMS_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_LIST_LOADING_PORT 	     "6038"
#define EMS_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_LIST_LOADING_REMOTE_EMS_PORT "6039"     //****
#define EMS_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_RESPONDING_PORT              "6040"
#define EMS_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_RESPONDING_REMOTE_EMS_PORT   "6041"     //****
#define ESA_USER_AUTHENTICATION_PORT                              	     "6042"
#define ESA_PUB_KEY_SERVING_PORT                                  	     "6043"
#define ESA_USER_INFO_MANAGEMENT_PORT                             	     "6044"
#define ESA_SERVER_INFO_MANAGEMENT_PORT			          	     "6045"
#define ESA_USER_LIST_LOADING_PORT			          	     "6046"
#define ESA_PHR_AUTHORITY_LIST_LOADING_PORT		          	     "6047"
#define ESA_USER_MANAGEMENT_PORT			          	     "6048"
#define ESA_PHR_AUTHORITY_MANAGEMENT_PORT                         	     "6049"
#define ESA_USER_PASSWD_RESETTING_PORT			          	     "6050"

// Global Function Prototypes
void set_using_safety_threads_for_openssl(boolean mode_flag);
void handle_error(const char *file, int line_no, const char *err_msg);
void seed_prng();
void init_openssl();
void uninit_openssl();
SSL_CTX *setup_server_ctx(const char *cert_path, char *passwd, const char *rootca_pub_certfile_path);
SSL_CTX *setup_client_ctx(const char *cert_path, char *passwd, const char *rootca_pub_certfile_path);

// "authority_name" can be NULL if authority_verification_flag is set to be false
long post_connection_check(SSL *ssl, char **hosts, unsigned int no_hosts, boolean authority_verification_flag, char *authority_name);

// Either "cert_ownername_ret" or "entity_type_ret" or both of them can be NULL
void get_cert_ownername(SSL *ssl_client, char *authority_name, char *cert_ownername_ret, entity_type *entity_type_ret);

// Either "cert_owner_authority_name_ret" or "cert_ownername_ret" or both of them can be NULL
void get_cert_owner_info(SSL *ssl_client, char *cert_owner_authority_name_ret, char *cert_ownername_ret);
void exec_cmd(char *cmd, unsigned int cmd_length, char *result, unsigned int result_size);
boolean get_file_size(const char *file_path, unsigned int *file_size_ret);
boolean read_bin_file(const char *file_path, char *buffer_ret, unsigned int buffer_size, unsigned int *data_size_ret);  // "data_size_ret" can be NULL
boolean write_bin_file(const char *file_path, char *mode, char *buffer, unsigned int data_len);
void gen_random_password(char *passwd_ret);

/* 
*  Notice that: encryption by using SMIME will affect to some special character 
*  (i.e., '\n' will be encoded as '\r\n' when data is decrypted).
*/ 
// "err_msg_ret" can be NULL
boolean smime_encrypt_with_cert(const char *plaintext_path, const char *ciphertext_path, const char *certfile_path, char *err_msg_ret);
boolean smime_decrypt_with_cert(const char *ciphertext_path, const char *plaintext_path, const char *certfile_path, char *passwd, char *err_msg_ret);
boolean smime_sign_with_cert(const char *data_path, const char *signed_data_path, const char *certfile_path, char *passwd, char *err_msg_ret);
boolean smime_verify_with_cert(const char *signed_data_path, const char *data_path, const char *CAfile_path, char *err_msg_ret);

// "err_msg_ret" can be NULL
boolean des3_encrypt(const char *plaintext_path, const char *ciphertext_path, char *passwd, char *err_msg_ret);
boolean des3_decrypt(const char *ciphertext_path, const char *plaintext_path, char *passwd, char *err_msg_ret);

// Basic send/receive data functions
int BIO_recv(BIO *peer, char *buf, int buf_len);
int BIO_send(BIO *peer, char *buf, int buf_len);
int SSL_recv(SSL *peer, char *buf, int buf_len);
int SSL_send(SSL *peer, char *buf, int buf_len);
void SSL_cleanup(SSL *conn);

// If any error occur, it will not show the error message to the console
int SSL_send_ignore_error(SSL *peer, char *buf, int buf_len);
int SSL_recv_ignore_error(SSL *peer, char *buf, int buf_len);

// Send/Receive file
boolean BIO_recv_file(BIO *peer, const char *file_path);
boolean BIO_send_file(BIO *peer, const char *file_path);
boolean SSL_recv_file(SSL *peer, const char *file_path);
boolean SSL_send_file(SSL *peer, const char *file_path);
boolean SSL_recv_large_file(SSL *peer, const char *file_path);
boolean SSL_send_large_file(SSL *peer, const char *file_path);

// Send/Receive data in memory buffer
boolean BIO_recv_buffer(BIO *peer, char *buffer_ret, unsigned int *buffer_size_ret);  // "buffer_size_ret" can be NULL
boolean BIO_send_buffer(BIO *peer, char *buffer, int data_length);
boolean SSL_recv_buffer(SSL *peer, char *buffer_ret, unsigned int *buffer_size_ret);  // "buffer_size_ret" can be NULL
boolean SSL_send_buffer(SSL *peer, char *buffer, int data_length);

// If any error occur, it will not show the error message to the console ("buffer_size_ret" can be NULL)
boolean SSL_recv_buffer_ignore_error(SSL *peer, char *buffer_ret, unsigned int *buffer_size_ret);

// If any error occur, it will not show the error message to the console
boolean SSL_send_buffer_ignore_error(SSL *peer, char *buffer, int data_length);

// Either "ip_address_ret" or "port_number_ret" or both of them can be NULL
void BIO_get_peer_address(BIO *bio_peer, char *ip_address_ret, char *port_number_ret);

// Either "ip_address_ret" or "port_number_ret" or both of them can be NULL
void SSL_get_peer_address(SSL *ssl_peer, char *ip_address_ret, char *port_number_ret);

// Write/Read token to/from memory buffer
void write_token_into_buffer(char *token_name, char *token_value, boolean is_first_token_flag, char *buffer);      // "token_value" can be NULL
int read_token_from_buffer(char *buffer, int token_no, char *token_name_ret, char *token_value_ret);

// Write/Read token to/from file
boolean write_token_into_file(char *token_name, char *token_value, boolean is_first_token_flag, const char *file_path);  // "token_value" can be NULL
int read_token_from_file(const char *file_path, int token_no, char *token_name_ret, char *token_value_ret);

// Integrity Checking
void sum_sha1_from_file(const char *file_path, char *sum_ret, const char *digest_path);
void sum_sha1_from_string(char *string, unsigned int length, char *hash_value_ret, const char *digest_path);
boolean verify_file_integrity(const char *file_path, char *cmp_hash_value, const char *digest_path);

// Get current date/time in format "YYYY-MM-DD HH:mm:ss"
void get_current_date_time(char *current_date_time_ret);

// File/directory management
boolean file_exists(const char *file_path);
boolean directory_exists(const char *dir_path);
boolean make_directory(const char *dir_path, mode_t octet_mode);    // "octet_mode" specifies, for example, 777
boolean determine_file_permission(const char *file_path, char *octet_mode_ret);
boolean determine_directory_permission(const char *dir_path, char *octet_mode_ret);
boolean change_file_permission(const char *file_path, mode_t octet_mode);
boolean change_directory_permission(const char *file_path, mode_t octet_mode);
boolean rename_file(const char *src_path, const char *dest_path);
boolean recursive_remove(const char *path);

// Memory allocation/deallocation
void allocate_2d_string_array(char ***array, int n, int m);
void deallocate_2d_string_array(char ***array, int n);

#endif




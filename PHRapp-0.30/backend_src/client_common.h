#pragma once
#ifndef CLIENT_COMMON_H
#define CLIENT_COMMON_H

#include "common.h"

#define SSL_CERT_PATH                       "Client_cache/client_ssl_cert"         // Use for both admin and user
#define CPABE_PRIV_KEY_PATH                 "Client_cache/client_cpabe_priv_key"   // Use for user only
#define UA_PUB_CERTFILE_PATH                "Client_cache/user_auth_cert.pem"      // Use for protecting information in a BIO channel

#define CACHE_DIRECTORY_PATH		    "Client_cache"
#define CACHE_DIRECTORY_PERMISSION_MODE     777

#define PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH "Certs_and_keys_pool/rootCA_cert.pem"

#define ENCRYPTED_PHR_TARGET_FILE_PATH      "Client_cache/encrypted_phr_target_file.tar.cpabe"
#define DECRYPTED_PHR_TARGET_FILE_PATH      "Client_cache/decrypted_phr_target_file.tar.cpabe"

#define CPABE_PUB_KEY_PATH                  "Certs_and_keys_pool/pub_key"
#define CPABE_ENC_PATH                      "./cpabe_enc"
#define CPABE_DEC_PATH                      "./cpabe_dec"

#define NO_REFERENCE_USERNAME               "no_reference_user"

// Shared variables
char GLOBAL_ssl_cert_hash[SHA1_DIGEST_LENGTH + 1];
char GLOBAL_cpabe_priv_key_hash[SHA1_DIGEST_LENGTH + 1];      // Only use for user

char GLOBAL_username[USER_NAME_LENGTH + 1];
char GLOBAL_authority_name[AUTHORITY_NAME_LENGTH + 1];
char GLOBAL_passwd[PASSWD_LENGTH + 1];
char GLOBAL_user_auth_ip_addr[IP_ADDRESS_LENGTH + 1];
char GLOBAL_audit_server_ip_addr[IP_ADDRESS_LENGTH + 1];
char GLOBAL_phr_server_ip_addr[IP_ADDRESS_LENGTH + 1];        // Only use for user
char GLOBAL_emergency_server_ip_addr[IP_ADDRESS_LENGTH + 1];  // Only use for user

// Function Prototypes
boolean authenticate_user(char *user_auth_ip_addr, char *username, char *passwd, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*basic_info_ret_callback_handler_ptr)(char *email_address, 
	char *authority_name, char *audit_server_ip_addr, char *phr_server_ip_addr, char *emergency_server_ip_addr), void (*ssl_cert_hash_ret_callback_handler_ptr)(
	char *ssl_cert_hash), void (*cpabe_priv_key_hash_ret_callback_handler_ptr)(char *cpabe_priv_key_hash));

boolean authenticate_admin(char *user_auth_ip_addr, char *username, char *passwd, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*basic_info_ret_callback_handler_ptr)(char *email_address, char *authority_name, 
	char *audit_server_ip_addr, char *phr_server_ip_addr, char *emergency_server_ip_addr), void (*mail_server_configuration_ret_callback_handler_ptr)
	(char *mail_server_url, char *authority_email_address, char *authority_email_passwd), void (*ssl_cert_hash_ret_callback_handler_ptr)(char *ssl_cert_hash));

boolean register_attribute(char *attribute_name, boolean is_numerical_attribute_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean remove_attribute(char *attribute_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void(*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

void update_attribute_list_for_admin(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg),
	void (*clear_attribute_table_callback_handler_ptr)(), void (*add_attribute_to_table_callback_handler_ptr)(char *attribute_name, boolean is_numerical_attribute_flag));

void update_attribute_list_for_user(char *authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*clear_attribute_table_callback_handler_ptr)(), 
	void (*add_attribute_to_table_callback_handler_ptr)(char *attribute_name, boolean is_numerical_attribute_flag));

boolean register_user(char *username, char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*get_user_attribute_by_index_callback_handler_ptr)
	(unsigned int index, char *user_attribute_buffer_ret));

void update_user_list(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg),
	void (*clear_user_tree_table_callback_handler_ptr)(), void (*add_user_to_tree_table_callback_handler_ptr)(char *username, char *email_address), 
	void (*attach_numerical_user_attribute_to_tree_table_callback_handler_ptr)(char *username, char *attribute_name, char *authority_name, unsigned int attribute_value), 
	void (*attach_non_numerical_user_attribute_to_tree_table_callback_handler_ptr)(char *username, char *attribute_name, char *authority_name), 
	void (*repaint_user_tree_table_callback_handler_ptr)());

boolean record_transaction_logout_log(char *username, boolean is_admin_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

void audit_all_transaction_admin_login_log(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*add_transaction_admin_login_log_to_table_callback_handler_ptr)(char *date_time, char *ip_address, boolean is_logout_flag));

void audit_some_period_time_transaction_admin_login_log(char *start_date_time, char *end_date_time, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*add_transaction_admin_login_log_to_table_callback_handler_ptr)(char *date_time, 
	char *ip_address, boolean is_logout_flag));

void audit_all_transaction_admin_event_log(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*add_transaction_event_log_to_table_callback_handler_ptr)(char *date_time, char *actor_name, char *actor_authority_name, 
	boolean is_actor_admin_flag, char *object_description, char *event_description, char *object_owner_name, char *object_owner_authority_name, 
	boolean is_object_owner_admin_flag, char *actor_ip_address));

void audit_some_period_time_transaction_admin_event_log(char *start_date_time, char *end_date_time, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*add_transaction_event_log_to_table_callback_handler_ptr)(char *date_time, 
	char *actor_name, char *actor_authority_name, boolean is_actor_admin_flag, char *object_description, char *event_description, char *object_owner_name, 
	char *object_owner_authority_name, boolean is_object_owner_admin_flag, char *actor_ip_address));

void audit_all_transaction_system_login_log(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*add_transaction_system_login_log_to_table_callback_handler_ptr)(char *date_time, char *username, char *user_authority_name, 
	boolean is_admin_flag, char *ip_address, boolean is_logout_flag));

void audit_some_period_time_transaction_system_login_log(char *start_date_time, char *end_date_time, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*add_transaction_system_login_log_to_table_callback_handler_ptr)(char *date_time, 
	char *username, char *user_authority_name, boolean is_admin_flag, char *ip_address, boolean is_logout_flag));

void audit_all_transaction_system_event_log(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*add_transaction_event_log_to_table_callback_handler_ptr)(char *date_time, char *actor_name, char *actor_authority_name, 
	boolean is_actor_admin_flag, char *object_description, char *event_description, char *object_owner_name, char *object_owner_authority_name, 
	boolean is_object_owner_admin_flag, char *actor_ip_address));

void audit_some_period_time_transaction_system_event_log(char *start_date_time, char *end_date_time, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*add_transaction_event_log_to_table_callback_handler_ptr)(char *date_time, 
	char *actor_name, char *actor_authority_name, boolean is_actor_admin_flag, char *object_description, char *event_description, char *object_owner_name, 
	char *object_owner_authority_name, boolean is_object_owner_admin_flag, char *actor_ip_address));

void update_authority_list_for_user(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg),
	void (*clear_authority_list_callback_handler_ptr)(), void (*add_authority_to_list_callback_handler_ptr)(char *authority_name));

void update_authority_list_for_admin(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg),
	void (*clear_authority_table_callback_handler_ptr)(), void (*add_authority_to_table_callback_handler_ptr)(char *authority_name, char *ip_address, 
	boolean authority_join_flag));

boolean assign_access_permission(char *desired_user_authority_name, char *desired_username, boolean upload_permission_flag, boolean download_permission_flag, 
	boolean delete_permission_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)
	(char *alert_msg));

boolean edit_access_permission(char *desired_user_authority_name, char *desired_username, boolean upload_permission_flag, boolean download_permission_flag, 
	boolean delete_permission_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)
	(char *alert_msg));

boolean remove_access_permission(char *desired_user_authority_name, char *desired_username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

void update_assigned_access_permission_list(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*clear_access_permission_table_callback_handler_ptr)(), void (*add_access_permission_to_table_callback_handler_ptr)(char *assigned_username, 
	char *assigned_user_authority_name, boolean upload_permission_flag, boolean download_permission_flag, boolean delete_permission_flag));

boolean check_user_existence(char *authority_name, char *username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean verify_upload_permission(char *phr_owner_name, char *phr_owner_authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean verify_download_permission(char *phr_owner_name, char *phr_owner_authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean verify_delete_permission(char *phr_owner_name, char *phr_owner_authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean encrypt_phr(char *phr_upload_from_path, char *access_policy, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg));
void cancel_phr_encrypting();

boolean upload_phr(char *phr_owner_name, char *phr_owner_authority_name, char *data_description, char *confidentiality_level_flag, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*update_sent_progression_callback_handler_ptr)(unsigned int percent), void (*update_remote_site_phr_id_callback_handler_ptr)(
	unsigned int remote_site_phr_id));

void cancel_phr_uploading();

boolean load_downloading_authorized_phr_list(char *phr_owner_name, char *phr_owner_authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*add_authorized_phr_list_to_table_callback_handler_ptr)
	(char *data_description, char *file_size, char *phr_conf_level, unsigned int phr_id));

boolean load_deletion_authorized_phr_list(char *phr_owner_name, char *phr_owner_authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*add_authorized_phr_list_to_table_callback_handler_ptr)
	(char *data_description, char *file_size, char *phr_conf_level, unsigned int phr_id));

boolean download_phr(char *phr_owner_name, char *phr_owner_authority_name, unsigned int phr_id, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*update_received_progression_callback_handler_ptr)(unsigned int percent));

void cancel_phr_downloading();

boolean decrypt_phr(char *phr_download_to_path, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg));
void cancel_phr_decrypting();

boolean delete_phr(char *phr_owner_name, char *phr_owner_authority_name, unsigned int phr_id, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean record_phr_encrypting_transaction_log(char *phr_owner_name, char *phr_owner_authority_name, char *phr_description, boolean success_flag, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean record_phr_uploading_transaction_log(char *phr_owner_name, char *phr_owner_authority_name, char *phr_description, boolean success_flag, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean record_phr_downloading_transaction_log(char *phr_owner_name, char *phr_owner_authority_name, char *phr_description, boolean success_flag, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean record_phr_decrypting_transaction_log(char *phr_owner_name, char *phr_owner_authority_name, char *phr_description, boolean success_flag, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean record_phr_deletion_transaction_log(char *phr_owner_name, char *phr_owner_authority_name, char *phr_description, boolean success_flag, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean record_failed_uploading_emergency_key_params_transaction_log(char *phr_owner_name, char *phr_owner_authority_name, char *phr_description, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

void update_user_attribute_list(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg),
	void (*add_numerical_user_attribute_to_table_callback_handler_ptr)(char *attribute_name, char *authority_name, unsigned int attribute_value), 
	void (*add_non_numerical_user_attribute_to_table_callback_handler_ptr)(char *attribute_name, char *authority_name));

void audit_all_transaction_user_login_log(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*add_transaction_login_log_to_table_callback_handler_ptr)(char *date_time, char *ip_address, boolean is_logout_flag));

void audit_some_period_time_transaction_user_login_log(char *start_date_time, char *end_date_time, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*add_transaction_login_log_to_table_callback_handler_ptr)(char *date_time, 
	char *ip_address, boolean is_logout_flag));

void audit_all_transaction_user_event_log(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*add_transaction_event_log_to_table_callback_handler_ptr)(char *date_time, char *actor_name, char *actor_authority_name, 
	boolean is_actor_admin_flag, char *object_description, char *event_description, char *object_owner_name, char *object_owner_authority_name, 
	boolean is_object_owner_admin_flag, char *actor_ip_address));

void audit_some_period_time_transaction_user_event_log(char *start_date_time, char *end_date_time, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*add_transaction_event_log_to_table_callback_handler_ptr)(char *date_time, 
	char *actor_name, char *actor_authority_name, boolean is_actor_admin_flag, char *object_description, char *event_description, char *object_owner_name, 
	char *object_owner_authority_name, boolean is_object_owner_admin_flag, char *actor_ip_address));

boolean edit_user_email_address_and_attribute_list(char *username, char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*get_user_attribute_by_index_callback_handler_ptr)
	(unsigned int index, char *user_attribute_buffer_ret));

boolean edit_user_email_address_only(char *username, char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean edit_user_attribute_list_only(char *username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)
	(char *alert_msg), void (*get_user_attribute_by_index_callback_handler_ptr)(unsigned int index, char *user_attribute_buffer_ret));

boolean edit_user_attribute_value(char *username, char *attribute_name, char *attribute_authority_name, char *attribute_value, void (*backend_alert_msg_callback_handler_ptr)
	(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean reset_user_passwd(char *username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean remove_user(char *username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean remove_user_attribute(char *username, char *attribute_name, char *attribute_authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean register_admin(char *username, char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

void update_admin_list(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg),
	void (*clear_admin_table_callback_handler_ptr)(), void (*add_admin_to_table_callback_handler_ptr)(char *username, char *email_address));

boolean edit_admin_email_address(char *username, char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean reset_admin_passwd(char *username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean remove_admin(char *username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean change_admin_passwd(char *new_passwd, boolean send_new_passwd_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean change_user_passwd(char *new_passwd, boolean send_new_passwd_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean change_admin_email_address(char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean change_user_email_address(char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean register_authority(char *authority_name, char *ip_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean edit_authority_ip_address(char *authority_name, char *ip_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean remove_authority(char *authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean request_passwd_resetting_code(char *user_auth_ip_addr, char *username, boolean is_admin_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg));
boolean reset_passwd(char *user_auth_ip_addr, char *username, boolean is_admin_flag, char *resetting_code, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg));
boolean load_user_authority_pub_key(char *user_auth_ip_addr, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean change_server_addresses_configuration(char *audit_server_ip_addr, char *phr_server_ip_addr, char *emergency_server_ip_addr, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean change_mail_server_configuration(char *mail_server_url, char *authority_email_address, char *authority_email_passwd, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean add_emergency_trusted_user(char *desired_trusted_user_authority_name, char *desired_trusted_username, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

void update_emergency_trusted_user_list(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*clear_emergency_trusted_user_table_callback_handler_ptr)(), void (*add_emergency_trusted_user_to_table_callback_handler_ptr)(
	char *trusted_username, char *trusted_user_authority_name));

void update_emergency_phr_owner_list(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*clear_emergency_phr_owner_table_callback_handler_ptr)(), void (*add_emergency_phr_owner_to_table_callback_handler_ptr)(
	char *phr_owner_name, char *phr_owner_authority_name));

boolean generate_unique_emergency_key(char *unique_emergency_key_attribute, char *unique_emergency_key_passwd, void (*backend_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean encrypt_threshold_secret_keys(unsigned int no_trusted_users, char **ea_trusted_user_list, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean upload_unique_emergency_key_params(unsigned int remote_site_phr_id, unsigned int threshold_value, unsigned int no_trusted_users, char **ea_trusted_user_list, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean change_restricted_level_phr_to_excusive_level_phr(unsigned int remote_site_phr_id, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean remove_restricted_level_phr_key_params(char *phr_owner_name, char *phr_owner_authority_name, unsigned int remote_site_phr_id, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

void remove_all_threshold_parameters_in_cache(unsigned int no_trusted_users);

boolean update_restricted_phr_access_request_list(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*clear_restricted_phr_access_request_table_callback_handler_ptr)(), 
	void (*add_restricted_phr_access_request_to_table_callback_handler_ptr)(char *full_requestor_name, char *full_phr_ownername, char *data_description, 
	unsigned int approvals, unsigned int threshold_value, char *request_status, unsigned int phr_id));

boolean approve_restricted_phr_access_request(char *phr_ownername, char *phr_owner_authority_name, unsigned int remote_site_phr_id, 
	char *phr_description, char *emergency_staff_name, char *emergency_unit_name, void (*backend_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

#endif




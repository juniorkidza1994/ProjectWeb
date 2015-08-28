#pragma once
#ifndef EMU_CLIENT_COMMON_H
#define EMU_CLIENT_COMMON_H

#include "common.h"

#define SSL_CERT_PATH                             "EmU_client_cache/client_ssl_cert"
#define ESA_PUB_CERTFILE_PATH                     "EmU_client_cache/emergency_staff_auth_cert.pem"      // Use for protecting information in a BIO channel

#define EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH       "Certs_and_keys_pool/EmU_rootCA_cert.pem"

#define CACHE_DIRECTORY_PATH		          "EmU_client_cache"
#define CACHE_DIRECTORY_PERMISSION_MODE           777

#define UNARCHIVED_EMERGENCY_PHR_TARGET_FILE_PATH "EmU_client_cache/unarchived_emergency_phr_target_file.tar"

// Shared variables
char GLOBAL_ssl_cert_hash[SHA1_DIGEST_LENGTH + 1];

char GLOBAL_username[USER_NAME_LENGTH + 1];
char GLOBAL_authority_name[AUTHORITY_NAME_LENGTH + 1];
char GLOBAL_passwd[PASSWD_LENGTH + 1];
char GLOBAL_emergency_staff_auth_ip_addr[IP_ADDRESS_LENGTH + 1];

// Function Prototypes
boolean authenticate_user(char *emergency_staff_auth_ip_addr, char *username, char *passwd, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*basic_info_ret_callback_handler_ptr)(char *email_address, char *authority_name), 
	void (*ssl_cert_hash_ret_callback_handler_ptr)(char *ssl_cert_hash));

boolean authenticate_admin(char *emergency_staff_auth_ip_addr, char *username, char *passwd, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*basic_info_ret_callback_handler_ptr)(char *email_address, char *authority_name), 
	void (*mail_server_configuration_ret_callback_handler_ptr)(char *mail_server_url, char *authority_email_address, char *authority_email_passwd), 
	void (*ssl_cert_hash_ret_callback_handler_ptr)(char *ssl_cert_hash));

boolean load_emergency_staff_authority_pub_key(char *emergency_staff_auth_ip_addr, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean change_emu_admin_passwd(char *new_passwd, boolean send_new_passwd_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean change_emu_user_passwd(char *new_passwd, boolean send_new_passwd_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean change_emu_admin_passwd(char *new_passwd, boolean send_new_passwd_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean change_emu_user_email_address(char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean change_emu_admin_email_address(char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean change_emu_mail_server_configuration(char *mail_server_url, char *authority_email_address, char *authority_email_passwd, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

void update_emu_user_list(boolean is_admin_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*clear_user_table_callback_handler_ptr)(), void (*add_user_to_table_callback_handler_ptr)(char *username, char *email_address));

void update_phr_authority_list(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg),
	void (*clear_phr_authority_table_or_list_callback_handler_ptr)(), void (*add_phr_authority_to_table_or_list_callback_handler_ptr)(char *authority_name, 
	char *ip_address));

boolean register_emu_user(boolean is_admin_flag, char *username, char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean edit_emu_user_email_address(boolean is_admin_flag, char *username, char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean reset_emu_user_passwd(boolean is_admin_flag, char *username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean remove_emu_user(boolean is_admin_flag, char *username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean register_phr_authority(char *phr_authority_name, char *ip_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean edit_phr_authority_ip_address(char *phr_authority_name, char *ip_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean remove_phr_authority(char *phr_authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean request_emu_passwd_resetting_code(char *emergency_staff_auth_ip_addr, char *username, boolean is_admin_flag, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean reset_emu_passwd(char *emergency_staff_auth_ip_addr, char *username, boolean is_admin_flag, char *resetting_code, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean check_phr_owner_existence(char *emergency_server_ip_addr, char *authority_name, char *phr_ownername, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean load_emergency_phr_list(char *emergency_server_ip_addr, char *authority_name, char *phr_ownername, void (*backend_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*clear_secure_phr_to_table_callback_handler_ptr)(), 
	void (*add_secure_phr_list_to_table_callback_handler_ptr)(char *data_description, char *file_size, unsigned int phr_id), 
	void (*clear_restricted_phr_to_table_callback_handler_ptr)(), void (*add_restricted_phr_list_to_table_callback_handler_ptr)(
	char *data_description, char *file_size, unsigned int approvals, unsigned int threshold_value, char *request_status, unsigned int phr_id));

boolean load_requested_restricted_phr_list(char *authority_name, char *emergency_server_ip_addr, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*add_requested_restricted_phr_tracking_list_to_table_callback_handler_ptr)(
	char *full_phr_ownername, char *data_description, char *file_size, unsigned int approvals, unsigned int threshold_value, char *request_status, 
	unsigned int phr_id, char *emergency_server_ip_addr));

boolean update_restricted_phr_list(char *emergency_server_ip_addr, char *authority_name, char *phr_ownername, void (*backend_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*clear_restricted_phr_to_table_callback_handler_ptr)(), 
	void (*add_restricted_phr_list_to_table_callback_handler_ptr)(char *data_description, char *file_size, unsigned int approvals, unsigned int threshold_value, 
	char *request_status, unsigned int phr_id));

boolean update_requested_restricted_phr_list(char *authority_name, char *emergency_server_ip_addr, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*clear_requested_restricted_phr_tracking_table_callback_handler_ptr)(), 
	void (*add_requested_restricted_phr_tracking_list_to_table_callback_handler_ptr)(char *full_phr_ownername, char *data_description, char *file_size, 
	unsigned int approvals, unsigned int threshold_value, char *request_status, unsigned int phr_id, char *emergency_server_ip_addr));

boolean download_emergency_phr(char *target_emergency_server_ip_addr, char *phr_owner_name, char *phr_owner_authority_name, unsigned int phr_id, char *phr_description, 
	boolean is_restricted_level_phr_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*set_emergency_phr_ems_side_processing_success_state_callback_handler_ptr)(), 
	void (*update_emergency_phr_received_progression_callback_handler_ptr)(unsigned int percent));

void cancel_emergency_phr_downloading();

boolean extract_emergency_phr(char *phr_download_to_path, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg));
void cancel_emergency_phr_extracting();

boolean request_restricted_level_phr_accessing(char *emergency_server_ip_addr, char *phr_owner_authority_name, char *phr_ownername, unsigned int phr_id, 
	char *phr_description, char *emergency_staff_email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

boolean cancel_restricted_level_phr_access_request(char *emergency_server_ip_addr, char *phr_owner_authority_name, char *phr_ownername, unsigned int phr_id, 
	char *phr_description, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg));

#endif




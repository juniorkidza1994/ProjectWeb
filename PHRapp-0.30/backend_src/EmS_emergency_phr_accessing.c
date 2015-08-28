#include "EmS_common.h"

#define CALCULATING_UNIQUE_STR_HASH_PATH "EmS_cache/EmS_emergency_phr_accessing.calculating_unique_str_hash"

// Local Function Prototypes
static boolean get_phr_owner_email_address(char *phr_ownername, char *phr_owner_email_addr_ret);
static boolean notify_phr_owner_emergency_phr_downloading(char *phr_ownername, boolean is_restricted_level_phr_flag, 
	char *phr_description, char *emergency_unit_name, char *emergency_staff_name);

static boolean record_emergency_phr_access_transaction_log(SSL *ssl_client, char *phr_owner_name, char *object_description, char *event_description);
static boolean connect_to_emergency_phr_downloading_service(SSL **ssl_conn_ret);
static boolean download_phr(char *desired_phr_owner_name, unsigned int phr_id, char *phr_file_path, char *error_msg_ret);
static boolean decrypt_secure_level_phr(char *decrypted_phr_target_file_path, char *ems_cpabe_priv_key_path, char *archived_phr_file_path, char *error_msg_ret);
static void respond_secure_level_phr_accessing(SSL *ssl_client);
static boolean get_threshold_value(MYSQL *db_conn, unsigned int remote_site_phr_id, unsigned int *threshold_value_ret);
static boolean get_phr_request_id(MYSQL *db_conn, unsigned int remote_site_phr_id, char *emergency_staff_name, char *emergency_unit_name, unsigned int *phr_request_id_ret);
static void get_no_approvals(MYSQL *db_conn, unsigned int phr_request_id, unsigned int *no_approvals_ret);
static boolean get_unique_emergency_key_passwd(MYSQL *db_conn, unsigned int remote_site_phr_id, unsigned int phr_request_id, char *unique_str_hash, 
	char *unique_emergency_key_passwd_ret);
static boolean decrypt_restricted_level_phr(MYSQL *db_conn, unsigned int remote_site_phr_id, char *enc_unique_emergency_key_path, char *unique_emergency_key_path, 
	char *unique_emergency_key_passwd, char *decrypted_phr_target_file_path, char *archived_phr_file_path, char *error_msg_ret);
static void remove_access_request(MYSQL *db_conn, unsigned int phr_request_id);
static void respond_restricted_level_phr_accessing(SSL *ssl_client);
static void *respond_emergency_phr_accessing_main(void *arg);

// Function Prototypes
static boolean get_phr_owner_email_address(char *phr_ownername, char *phr_owner_email_addr_ret)
{
	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    emergency_user_email_addr_requesting_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean emergency_user_email_addr_requesting_result_flag;

	// Connect to User Authority
	if(!connect_to_emergency_address_serving_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", EMERGENCY_USER_EMAIL_ADDR_REQUESTING, true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending request information failed\n");
		goto ERROR;
	}

	// Send the emergency user's email address request
	write_token_into_buffer("is_end_of_getting_emergency_user_email_address_flag", "0", true, buffer);
	write_token_into_buffer("desired_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("desired_username", phr_ownername, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the emergency user's email address request failed\n");
		goto ERROR;
	}

	// Receive the emergency user's email address requesting information
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the emergency user's email address requesting information failed\n");
		goto ERROR;
	}	

	if(read_token_from_buffer(buffer, 1, token_name, emergency_user_email_addr_requesting_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_user_email_addr_requesting_result_flag") != 0)
	{
		int_error("Extracting the emergency_user_email_addr_requesting_result_flag failed");
	}

	emergency_user_email_addr_requesting_result_flag = (strcmp(emergency_user_email_addr_requesting_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!emergency_user_email_addr_requesting_result_flag)
	{
		fprintf(stderr, "Do not found the PHR owner's email address\n");
		goto USER_NOT_FOUND;
	}

	if(read_token_from_buffer(buffer, 2, token_name, phr_owner_email_addr_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_user_email_address") != 0)
	{
		int_error("Extracting the emergency_user_email_address failed");
	}

	// Send the "is_end_of_getting_emergency_user_email_address_flag"
	write_token_into_buffer("is_end_of_getting_emergency_user_email_address_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the is_end_of_getting_emergency_user_email_address_flag failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	return true;

USER_NOT_FOUND:
ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;	
}

static boolean notify_phr_owner_emergency_phr_downloading(char *phr_ownername, boolean is_restricted_level_phr_flag, 
	char *phr_description, char *emergency_unit_name, char *emergency_staff_name)
{
	char phr_owner_email_addr[EMAIL_ADDRESS_LENGTH + 1];
	char payload_msg_list[7][EMAIL_MSG_LINE_LENGTH + 1];
	char payload_buffer[EMAIL_MSG_LINE_LENGTH + 1];
	char error_msg[ERR_MSG_LENGTH + 1];

	// Get the PHR owner's email address
	if(!get_phr_owner_email_address(phr_ownername, phr_owner_email_addr))
		goto ERROR;

	sprintf(payload_buffer, "To: %s(PHR owner)\n", phr_owner_email_addr);
	config_email_payload(0, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "From: %s(%s's emergency mailer)\n", GLOBAL_authority_email_address, GLOBAL_authority_name);
	config_email_payload(1, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Subject: Emergency staff downloaded your %s-level PHR\n", (is_restricted_level_phr_flag) ? "restricted" : "secure");
	config_email_payload(2, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "\n");  // Empty line to divide headers from body, see RFC5322
	config_email_payload(3, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Emergency staff: %s.%s\n", emergency_unit_name, emergency_staff_name);
	config_email_payload(4, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Data type: %s-level PHR information\n", (is_restricted_level_phr_flag) ? "Restricted" : "Secure");
	config_email_payload(5, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Data description: %s\n", phr_description);
	config_email_payload(6, payload_buffer, payload_msg_list);

	if(!send_email(1, phr_owner_email_addr, 7, *payload_msg_list, error_msg))
	{
		fprintf(stderr, "Sending notification to a PHR owner's email address failed (%s)\n", error_msg);
		goto ERROR;
	}
	
	return true;

ERROR:

	return false;
}

static boolean record_emergency_phr_access_transaction_log(SSL *ssl_client, char *phr_owner_name, char *object_description, char *event_description)
{
	SSL  *ssl_AS_conn = NULL;
	char buffer[BUFFER_LENGTH + 1];
	char emergency_staff_name[USER_NAME_LENGTH + 1];
	char emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];
	char current_date_time[DATETIME_STR_LENGTH  + 1];
	char client_ip_address[IP_ADDRESS_LENGTH + 1];

	// Get certificate owner's name, current date/time and client's IP address
	get_cert_owner_info(ssl_client, emergency_unit_name, emergency_staff_name);
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_client, client_ip_address, NULL);

	// Connect to Audit Server
	if(!connect_to_transaction_log_recording_service(&ssl_AS_conn))
		goto ERROR;

	// Send a request type
	write_token_into_buffer("request_type", EVENT_LOG_RECORDING, true, buffer);
	if(!SSL_send_buffer(ssl_AS_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a request type failed\n");
		goto ERROR;
	}

	// Send a transaction log
	write_token_into_buffer("actor_name", emergency_staff_name, true, buffer);
	write_token_into_buffer("actor_authority_name", emergency_unit_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_owner_name", phr_owner_name, false, buffer);
	write_token_into_buffer("object_owner_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("affected_username", NO_REFERENCE_USERNAME, false, buffer);
	write_token_into_buffer("affected_user_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_description", object_description, false, buffer);
	write_token_into_buffer("event_description", event_description, false, buffer);
	write_token_into_buffer("date_time", current_date_time, false, buffer);
	write_token_into_buffer("actor_ip_address", client_ip_address, false, buffer);

	if(!SSL_send_buffer(ssl_AS_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a transaction log failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_AS_conn);
	ssl_AS_conn = NULL;
	return true;

ERROR:

	if(ssl_AS_conn)
	{
		SSL_cleanup(ssl_AS_conn);
		ssl_AS_conn = NULL;
	}

	return false;
}

static boolean connect_to_emergency_phr_downloading_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    phr_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to PHR Server
	sprintf(phr_server_addr, "%s:%s", GLOBAL_phr_server_ip_addr, PHRSV_PHR_SERVICES_PORT);
	bio_conn = BIO_new_connect(phr_server_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		fprintf(stderr, "Connecting to PHR server failed\n");
		goto ERROR_AT_BIO_LAYER;
	}

	ctx = setup_client_ctx(EMS_CERTFILE_PATH, EMS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
	if(!(*ssl_conn_ret = SSL_new(ctx)))
            	int_error("Creating SSL context failed");
 
    	SSL_set_bio(*ssl_conn_ret, bio_conn, bio_conn);
    	if(SSL_connect(*ssl_conn_ret) <= 0)
	{
        	fprintf(stderr, "Connecting SSL object failed\n");
		goto ERROR_AT_SSL_LAYER;
	}

	hosts[0] = PHR_SERVER_CN;
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, false, NULL)) != X509_V_OK)
   	{
		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        	goto ERROR_AT_SSL_LAYER;
    	}

	// Return value of *ssl_conn_ret
	SSL_CTX_free(ctx);
    	ERR_remove_state(0);
	return true;

ERROR_AT_BIO_LAYER:

	BIO_free(bio_conn);
	bio_conn = NULL;
	ERR_remove_state(0);	
	return false;

ERROR_AT_SSL_LAYER:

	SSL_cleanup(*ssl_conn_ret);
	*ssl_conn_ret = NULL;
	SSL_CTX_free(ctx);
    	ERR_remove_state(0);
	return false;
}

static boolean download_phr(char *desired_phr_owner_name, unsigned int phr_id, char *phr_file_path, char *error_msg_ret)
{
	SSL     *ssl_conn = NULL;

	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];

	char    is_requested_phr_available_to_download_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_requested_phr_available_to_download_flag;

	// Connect to PHR Server
	if(!connect_to_emergency_phr_downloading_service(&ssl_conn))
	{
		strcpy(error_msg_ret, "Connecting to PHR server failed");
		goto ERROR;	
	}

	sprintf(phr_id_str_tmp, "%u", phr_id);

	// Send PHR downloading information
	write_token_into_buffer("desired_phr_owner_name", desired_phr_owner_name, true, buffer);
	write_token_into_buffer("desired_phr_owner_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("phr_id", phr_id_str_tmp, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		strcpy(error_msg_ret, "Sending PHR downloading information failed");
		fprintf(stderr, "%s\n", error_msg_ret);
		goto ERROR;
	}

	// Receive the "is_requested_phr_available_to_download_flag"
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		strcpy(error_msg_ret, "Receiving the is_requested_phr_available_to_download_flag failed");
		fprintf(stderr, "%s\n", error_msg_ret);
		goto ERROR;
	}

	// Get the is_requested_phr_available_to_download_flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, is_requested_phr_available_to_download_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_requested_phr_available_to_download_flag") != 0)
	{
		int_error("Extracting the is_requested_phr_available_to_download_flag failed");
	}

	is_requested_phr_available_to_download_flag = (strcmp(is_requested_phr_available_to_download_flag_str_tmp, "1") == 0) ? true : false;
	if(!is_requested_phr_available_to_download_flag)
	{
		char err_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, err_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		strcpy(error_msg_ret, err_msg);
		fprintf(stderr, "%s\n", error_msg_ret);
		goto ERROR;
	}

	// Receive the PHR file size (we ignore this parameter)
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		strcpy(error_msg_ret, "Receiving the file_size failed");
		fprintf(stderr, "%s\n", error_msg_ret);
		goto ERROR;
	}

	// Download the PHR
	if(!SSL_recv_large_file(ssl_conn, phr_file_path))
	{
		strcpy(error_msg_ret, "Downloading a PHR file from the PHR server to the emergency server failed");
		fprintf(stderr, "%s\n", error_msg_ret);
		goto ERROR;
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	return true;

ERROR:

	unlink(phr_file_path);

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;
}

static boolean decrypt_secure_level_phr(char *decrypted_phr_target_file_path, char *ems_cpabe_priv_key_path, char *archived_phr_file_path, char *error_msg_ret)
{
	char *shell_cmd;
	char err_code[ERR_MSG_LENGTH + 1];

	// Allocate a heap variable
	shell_cmd = (char *)malloc(sizeof(char)*1000*1024);
	if(!shell_cmd)
	{
		int_error("Allocating memory for \"shell_cmd\" failed");
	}

	unlink(archived_phr_file_path);	

	// Decrypt the emergency server's CP-ABE private key with the emergency sever's password
	if(!des3_decrypt(EMS_CPABE_PRIV_KEY_PATH, ems_cpabe_priv_key_path, EMS_CPABE_PRIV_KEY_PASSWD, err_code))
	{
		strcpy(error_msg_ret, "Decrypting the emergency server's CP-ABE private key failed");
		fprintf(stderr, "%s\n\"%s\"\n", error_msg_ret, err_code);
		goto ERROR;
	}

	// Decrypt the secure-level PHR
	sprintf(shell_cmd, "%s %s %s %s", CPABE_DEC_PATH, CPABE_PUB_KEY_PATH, ems_cpabe_priv_key_path, decrypted_phr_target_file_path);

	exec_cmd(shell_cmd, strlen(shell_cmd), err_code, sizeof(err_code));
	if(strcmp(err_code, "") != 0)
	{
		strcpy(error_msg_ret, "Decrypting the secure-level PHR failed");
		fprintf(stderr, "%s\n\"%s\"\n", error_msg_ret, err_code);
		goto ERROR;
	}

	unlink(ems_cpabe_priv_key_path);
	unlink(decrypted_phr_target_file_path);

	// Release memory
	free(shell_cmd);
	return true;

ERROR:

	unlink(ems_cpabe_priv_key_path);
	unlink(decrypted_phr_target_file_path);
	unlink(archived_phr_file_path);

	// Release memory
	free(shell_cmd);
	return false;
}

static void respond_secure_level_phr_accessing(SSL *ssl_client)
{
	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];
	char         emergency_staff_name[USER_NAME_LENGTH + 1];

	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         desired_phr_ownername[USER_NAME_LENGTH + 1];

	char         phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int phr_id;

	char         phr_description[DATA_DESCRIPTION_LENGTH + 1];

	char         unique_str[AUTHORITY_NAME_LENGTH + USER_NAME_LENGTH + INT_TO_STR_DIGITS_LENGTH + 1];
	char         unique_str_hash[SHA1_DIGEST_LENGTH + 1];
	char         decrypted_phr_target_file_path[PATH_LENGTH + 1];
	char         archived_phr_file_path[PATH_LENGTH + 1];
	char         ems_cpabe_priv_key_path[PATH_LENGTH + 1];

	unsigned int file_size;
	char         file_size_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];

	char         error_msg[ERR_MSG_LENGTH + 1];

	// Get the requestor info
	get_cert_owner_info(ssl_client, emergency_unit_name, emergency_staff_name);

	// Receive the requested secure-level PHR information
	if(!SSL_recv_buffer(ssl_client, buffer, NULL))
	{
		fprintf(stderr, "Receiving the requested secure-level PHR information failed\n");
		goto ERROR_BEFORE_RESEASE_WAIT_MUTEX;
	}

	// Get the requested secure-level PHR information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, desired_phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "desired_phr_owner_name") != 0)
		int_error("Extracting the desired_phr_owner_name failed");

	if(read_token_from_buffer(buffer, 2, token_name, phr_id_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_id") != 0)
		int_error("Extracting the phr_id failed");

	phr_id = atoi(phr_id_str_tmp);

	if(read_token_from_buffer(buffer, 3, token_name, phr_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_description") != 0)
		int_error("Extracting the phr_description failed");

	// Generate PHR file paths
	sprintf(unique_str, "%s%s%u", emergency_unit_name, emergency_staff_name, phr_id);
	sum_sha1_from_string(unique_str, strlen(unique_str), unique_str_hash, CALCULATING_UNIQUE_STR_HASH_PATH);

	sprintf(decrypted_phr_target_file_path, "%s/decrypted_phr_target_file%s.tar.cpabe", CACHE_DIRECTORY_PATH, unique_str_hash);
	sprintf(archived_phr_file_path, "%s/decrypted_phr_target_file%s.tar", CACHE_DIRECTORY_PATH, unique_str_hash);
	sprintf(ems_cpabe_priv_key_path, "%s/ems_key%s", CACHE_DIRECTORY_PATH, unique_str_hash);

	// Release the critical section, so that the main thread can serve new incoming requests
	if(sem_post(&wait_for_creating_new_child_thread_mutex) != 0)
		int_error("Signaling for creating the thread \"respond_emergency_phr_accessing_main\" failed");

	// Download the requested secure-level PHR
	if(!download_phr(desired_phr_ownername, phr_id, decrypted_phr_target_file_path, error_msg))
	{
		// Send the "ask_connection_still_alive"
		write_token_into_buffer("ask_connection_still_alive", NULL, true, buffer);
		SSL_send_buffer_ignore_error(ssl_client, buffer, strlen(buffer));    // Ignore an error

		// Receive the ask_connection_still_alive result
		if(!SSL_recv_buffer_ignore_error(ssl_client, buffer, NULL))
		{
			// Transaction is cancelled by the client
			goto OPERATION_HAS_BEEN_CANCELLED;
		}

		// Send the "emergency_phr_processing_success_flag"
		write_token_into_buffer("emergency_phr_processing_success_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", error_msg, false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the emergency_phr_processing_success_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Send the "ask_connection_still_alive"
	write_token_into_buffer("ask_connection_still_alive", NULL, true, buffer);
	SSL_send_buffer_ignore_error(ssl_client, buffer, strlen(buffer));    // Ignore an error

	// Receive the ask_connection_still_alive result
	if(!SSL_recv_buffer_ignore_error(ssl_client, buffer, NULL))
	{
		// Transaction is cancelled by the client
		goto OPERATION_HAS_BEEN_CANCELLED;
	}

	// Decrypt the secure-level PHR
	if(!decrypt_secure_level_phr(decrypted_phr_target_file_path, ems_cpabe_priv_key_path, archived_phr_file_path, error_msg))
	{
		// Send the "ask_connection_still_alive"
		write_token_into_buffer("ask_connection_still_alive", NULL, true, buffer);
		SSL_send_buffer_ignore_error(ssl_client, buffer, strlen(buffer));    // Ignore an error

		// Receive the ask_connection_still_alive result
		if(!SSL_recv_buffer_ignore_error(ssl_client, buffer, NULL))
		{
			// Transaction is cancelled by the client
			goto OPERATION_HAS_BEEN_CANCELLED;
		}

		// Send the "emergency_phr_processing_success_flag"
		write_token_into_buffer("emergency_phr_processing_success_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", error_msg, false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the emergency_phr_processing_success_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	unlink(ems_cpabe_priv_key_path);
	unlink(decrypted_phr_target_file_path);

	// Send the "ask_connection_still_alive"
	write_token_into_buffer("ask_connection_still_alive", NULL, true, buffer);
	SSL_send_buffer_ignore_error(ssl_client, buffer, strlen(buffer));    // Ignore an error

	// Receive the ask_connection_still_alive result
	if(!SSL_recv_buffer_ignore_error(ssl_client, buffer, NULL))
	{
		// Transaction is cancelled by the client
		goto OPERATION_HAS_BEEN_CANCELLED;
	}

	// Send the "emergency_phr_processing_success_flag"
	write_token_into_buffer("emergency_phr_processing_success_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the emergency_phr_processing_success_flag failed\n");
		goto ERROR;
	}

	// Send the PHR file size
	if(!get_file_size(archived_phr_file_path, &file_size))
	{
		fprintf(stderr, "Getting the requested secure-level PHR file size failed\n");
		goto ERROR;
	}

	sprintf(file_size_str_tmp, "%u", file_size);
	write_token_into_buffer("file_size", file_size_str_tmp, true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the file_size failed\n");
		goto ERROR;
	}

	// Send the requested secure-level PHR file
	if(!SSL_send_large_file(ssl_client, archived_phr_file_path))
	{
		fprintf(stderr, "Sending the requested secure-level PHR file failed\n");
		goto ERROR;
	}

	unlink(archived_phr_file_path);
	
	// Record a transaction log
	record_emergency_phr_access_transaction_log(ssl_client, desired_phr_ownername, phr_description, SECURE_LEVEL_PHR_ACCESSING_MSG);

	// Send the notification to the PHR owner's e-mail address
	notify_phr_owner_emergency_phr_downloading(desired_phr_ownername, false, phr_description, emergency_unit_name, emergency_staff_name);

	return;

ERROR_BEFORE_RESEASE_WAIT_MUTEX:

	// Release the critical section, so that the main thread can serve new incoming requests
	if(sem_post(&wait_for_creating_new_child_thread_mutex) != 0)
		int_error("Signaling for creating the thread \"respond_emergency_phr_accessing_main\" failed");

ERROR:
OPERATION_HAS_BEEN_CANCELLED:

	unlink(ems_cpabe_priv_key_path);
	unlink(decrypted_phr_target_file_path);
	unlink(archived_phr_file_path);
	return;
}

static boolean get_threshold_value(MYSQL *db_conn, unsigned int remote_site_phr_id, unsigned int *threshold_value_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Query for the threshold value of the desired restricted-level PHR
	sprintf(stat, "SELECT threshold_value FROM %s WHERE remote_site_phr_id = %u", EMS__RESTRICTED_LEVEL_PHRS, remote_site_phr_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		fprintf(stderr, "Getting the threshold value of the desired restricted-level PHR failed\n");
		goto NOT_FOUND;
	}

	*threshold_value_ret = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return true;

NOT_FOUND:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return false;
}

static boolean get_phr_request_id(MYSQL *db_conn, unsigned int remote_site_phr_id, char *emergency_staff_name, char *emergency_unit_name, unsigned int *phr_request_id_ret)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	// Query for the phr_request_id that was requested by the emergency staff
	sprintf(stat, "SELECT phr_request_id FROM %s WHERE remote_site_phr_id = %u AND emergency_unit_name LIKE '%s' COLLATE latin1_general_cs AND emergency_staff_name "
		"LIKE '%s' COLLATE latin1_general_cs", EMS__RESTRICTED_LEVEL_PHR_REQUESTS, remote_site_phr_id, emergency_unit_name, emergency_staff_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		fprintf(stderr, "Getting the request id on the desired restricted-level PHR failed\n");
		goto NOT_FOUND;
	}

	*phr_request_id_ret = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return true;

NOT_FOUND:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return false;
}

static void get_no_approvals(MYSQL *db_conn, unsigned int phr_request_id, unsigned int *no_approvals_ret)
{
	MYSQL_RES *result = NULL;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char      err_msg[ERR_MSG_LENGTH + 1];

	// Count the number of approvals of the specific request
	sprintf(stat, "SELECT approval_flag FROM %s WHERE phr_request_id = %u AND approval_flag = '1'", EMS__SECRET_KEY_APPROVALS, phr_request_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result            = mysql_store_result(db_conn);
	*no_approvals_ret = mysql_num_rows(result);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static boolean get_unique_emergency_key_passwd(MYSQL *db_conn, unsigned int remote_site_phr_id, unsigned int phr_request_id, char *unique_str_hash, 
	char *unique_emergency_key_passwd_ret)
{
	MYSQL_RES     *result = NULL;
  	MYSQL_ROW     row;
	char          stat[SQL_STATEMENT_LENGTH + 1];
	char	      err_msg[ERR_MSG_LENGTH + 1];
	unsigned long *lengths = NULL;

	unsigned int  i, counter = 0;
	char          secret_key_file_path[PATH_LENGTH + 1];
	char          enc_threshold_msg_file_path[PATH_LENGTH + 1];

	char          *shell_cmd;
	char          ret_code[ERR_MSG_LENGTH + 1];

	// Allocate a heap variable
	shell_cmd = (char *)malloc(sizeof(char)*1000*1024);
	if(!shell_cmd)
	{
		int_error("Allocating memory for \"shell_cmd\" failed");
	}

	// Generate a file path
	sprintf(enc_threshold_msg_file_path, "%s/enc_threshold_msg%s", CACHE_DIRECTORY_PATH, unique_str_hash);

	// Query for the secret keys of the trusted users who approve the request 
	sprintf(stat, "SELECT buffer_secret_key FROM %s WHERE phr_request_id = %u AND approval_flag = '1'", EMS__SECRET_KEY_APPROVALS, phr_request_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		lengths = mysql_fetch_lengths(result);
		sprintf(secret_key_file_path, "%s/secret_key%s%u", CACHE_DIRECTORY_PATH, unique_str_hash, counter);
		counter++;

		// Write the secret key into the disk
		if(!write_bin_file(secret_key_file_path, "wb", row[0], lengths[0]))
		{
			fprintf(stderr, "Writing the secret key failed");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Query for the encrypted threshold message of the specific restricted-level PHR
	sprintf(stat, "SELECT enc_threshold_msg FROM %s WHERE remote_site_phr_id = %u", EMS__RESTRICTED_LEVEL_PHRS, remote_site_phr_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		fprintf(stderr, "Getting the encrypted threshold message failed\n");
		goto ERROR;
	}

	lengths = mysql_fetch_lengths(result);

	// Write the encrypted threshold message into the disk
	if(!write_bin_file(enc_threshold_msg_file_path, "wb", row[0], lengths[0]))
	{
		fprintf(stderr, "Writing the encrypted threshold message failed");
		goto ERROR;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Decrypt the encrypted threshold message with a set of secret keys to retrive the unique emergency key password
	sprintf(shell_cmd, "%s %u %s %s", THRESHOLD_DEC_PATH, counter, CACHE_DIRECTORY_PATH, unique_str_hash);

	exec_cmd(shell_cmd, strlen(shell_cmd), ret_code, sizeof(ret_code));
	if(!strstr(ret_code, "unique_emergency_key_passwd: "))
	{
		fprintf(stderr, "Decrypting the encrypted threshold message failed\n\"%s\"\n", ret_code);
		goto ERROR;
	}

	strcpy(unique_emergency_key_passwd_ret, ret_code + strlen("unique_emergency_key_passwd: "));

	// Remove files
	unlink(enc_threshold_msg_file_path);
	for(i=0; i<counter; i++)
	{
		sprintf(secret_key_file_path, "%s/secret_key%s%u", CACHE_DIRECTORY_PATH, unique_str_hash, i);
		unlink(secret_key_file_path);
	}

	// Release memory
	free(shell_cmd);
	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Remove files
	unlink(enc_threshold_msg_file_path);
	for(i=0; i<counter; i++)
	{
		sprintf(secret_key_file_path, "%s/secret_key%s%u", CACHE_DIRECTORY_PATH, unique_str_hash, i);
		unlink(secret_key_file_path);
	}

	// Release memory
	free(shell_cmd);
	return false;
}

static boolean decrypt_restricted_level_phr(MYSQL *db_conn, unsigned int remote_site_phr_id, char *enc_unique_emergency_key_path, char *unique_emergency_key_path, 
	char *unique_emergency_key_passwd, char *decrypted_phr_target_file_path, char *archived_phr_file_path, char *error_msg_ret)
{
	MYSQL_RES     *result = NULL;
  	MYSQL_ROW     row;
	char          stat[SQL_STATEMENT_LENGTH + 1];
	char	      err_msg[ERR_MSG_LENGTH + 1];
	unsigned long *lengths = NULL;

	char          *shell_cmd;
	char          err_code[ERR_MSG_LENGTH + 1];

	// Allocate a heap variable
	shell_cmd = (char *)malloc(sizeof(char)*1000*1024);
	if(!shell_cmd)
	{
		int_error("Allocating memory for \"shell_cmd\" failed");
	}

	unlink(archived_phr_file_path);	

	// Query for the encrypted unique emergency key of the specific restricted-level PHR
	sprintf(stat, "SELECT enc_emergency_key FROM %s WHERE remote_site_phr_id = %u", EMS__RESTRICTED_LEVEL_PHRS, remote_site_phr_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		strcpy(error_msg_ret, "Getting the encrypted unique emergency key failed");
		fprintf(stderr, "%s\n", error_msg_ret);
		goto ERROR;
	}

	lengths = mysql_fetch_lengths(result);

	// Write the encrypted unique emergency key into the disk
	if(!write_bin_file(enc_unique_emergency_key_path, "wb", row[0], lengths[0]))
	{
		strcpy(error_msg_ret, "Writing the encrypted unique emergency key failed");
		fprintf(stderr, "%s\n", error_msg_ret);
		goto ERROR;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Decrypt the encrypted unique emergency key
	if(!des3_decrypt(enc_unique_emergency_key_path, unique_emergency_key_path, unique_emergency_key_passwd, err_code))
	{
		strcpy(error_msg_ret, "Decrypting the encrypted unique emergency key failed");
		fprintf(stderr, "%s\n\"%s\"\n", error_msg_ret, err_code);
		goto ERROR;
	}

	unlink(enc_unique_emergency_key_path);

	// Decrypt the restricted-level PHR with the unique emergency key
	sprintf(shell_cmd, "%s %s %s %s", CPABE_DEC_PATH, CPABE_PUB_KEY_PATH, unique_emergency_key_path, decrypted_phr_target_file_path);

	exec_cmd(shell_cmd, strlen(shell_cmd), err_code, sizeof(err_code));
	if(strcmp(err_code, "") != 0)
	{
		strcpy(error_msg_ret, "Decrypting the restricted-level PHR failed");
		fprintf(stderr, "%s\n\"%s\"\n", error_msg_ret, err_code);
		goto ERROR;
	}

	unlink(unique_emergency_key_path);
	unlink(decrypted_phr_target_file_path);

	// Release memory
	free(shell_cmd);
	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	unlink(enc_unique_emergency_key_path);
	unlink(unique_emergency_key_path);
	unlink(decrypted_phr_target_file_path);
	unlink(archived_phr_file_path);

	// Release memory
	free(shell_cmd);
	return false;
}

static void remove_access_request(MYSQL *db_conn, unsigned int phr_request_id)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Remove the request
	sprintf(stat, "DELETE FROM %s WHERE phr_request_id = %u", EMS__RESTRICTED_LEVEL_PHR_REQUESTS, phr_request_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	// Remove all approvals that linked to the phr_request_id
	sprintf(stat, "DELETE FROM %s WHERE phr_request_id = %u", EMS__SECRET_KEY_APPROVALS, phr_request_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
}

static void respond_restricted_level_phr_accessing(SSL *ssl_client)
{
	MYSQL        *db_conn = NULL;
	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];
	char         emergency_staff_name[USER_NAME_LENGTH + 1];

	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         desired_phr_ownername[USER_NAME_LENGTH + 1];

	char         phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int phr_id;

	char         phr_description[DATA_DESCRIPTION_LENGTH + 1];

	char         unique_str[AUTHORITY_NAME_LENGTH + USER_NAME_LENGTH + INT_TO_STR_DIGITS_LENGTH + 1];
	char         unique_str_hash[SHA1_DIGEST_LENGTH + 1];
	char         decrypted_phr_target_file_path[PATH_LENGTH + 1];
	char         archived_phr_file_path[PATH_LENGTH + 1];
	char         enc_unique_emergency_key_path[PATH_LENGTH + 1];
	char         unique_emergency_key_path[PATH_LENGTH + 1];

	unsigned int threshold_value;
	unsigned int phr_request_id;
	unsigned int no_approvals;

	char         unique_emergency_key_passwd[PASSWD_LENGTH + 1];

	unsigned int file_size;
	char         file_size_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];

	char         error_msg[ERR_MSG_LENGTH + 1];

	// Get the requestor info
	get_cert_owner_info(ssl_client, emergency_unit_name, emergency_staff_name);

	// Receive the requested restricted-level PHR information
	if(!SSL_recv_buffer(ssl_client, buffer, NULL))
	{
		fprintf(stderr, "Receiving the requested restricted-level PHR information failed\n");
		goto ERROR_BEFORE_RESEASE_WAIT_MUTEX;
	}

	// Get the requested restricted-level PHR information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, desired_phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "desired_phr_owner_name") != 0)
		int_error("Extracting the desired_phr_owner_name failed");

	if(read_token_from_buffer(buffer, 2, token_name, phr_id_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_id") != 0)
		int_error("Extracting the phr_id failed");

	phr_id = atoi(phr_id_str_tmp);

	if(read_token_from_buffer(buffer, 3, token_name, phr_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_description") != 0)
		int_error("Extracting the phr_description failed");

	// Generate PHR file paths
	sprintf(unique_str, "%s%s%u", emergency_unit_name, emergency_staff_name, phr_id);
	sum_sha1_from_string(unique_str, strlen(unique_str), unique_str_hash, CALCULATING_UNIQUE_STR_HASH_PATH);

	sprintf(decrypted_phr_target_file_path, "%s/decrypted_phr_target_file%s.tar.cpabe", CACHE_DIRECTORY_PATH, unique_str_hash);
	sprintf(archived_phr_file_path, "%s/decrypted_phr_target_file%s.tar", CACHE_DIRECTORY_PATH, unique_str_hash);
	sprintf(enc_unique_emergency_key_path, "%s/enc_unique_emergency_key%s", CACHE_DIRECTORY_PATH, unique_str_hash);
	sprintf(unique_emergency_key_path, "%s/unique_emergency_key%s", CACHE_DIRECTORY_PATH, unique_str_hash);

	// Release the critical section, so that the main thread can serve new incoming requests
	if(sem_post(&wait_for_creating_new_child_thread_mutex) != 0)
		int_error("Signaling for creating the thread \"respond_emergency_phr_accessing_main\" failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Get the threshold value
	if(!get_threshold_value(db_conn, phr_id, &threshold_value))
	{
		// Send the "ask_connection_still_alive"
		write_token_into_buffer("ask_connection_still_alive", NULL, true, buffer);
		SSL_send_buffer_ignore_error(ssl_client, buffer, strlen(buffer));    // Ignore an error

		// Receive the ask_connection_still_alive result
		if(!SSL_recv_buffer_ignore_error(ssl_client, buffer, NULL))
		{
			// Transaction is cancelled by the client
			goto OPERATION_HAS_BEEN_CANCELLED;
		}

		// Send the "emergency_phr_processing_success_flag"
		write_token_into_buffer("emergency_phr_processing_success_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Getting the threshold value failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the emergency_phr_processing_success_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Get the PHR request id
	if(!get_phr_request_id(db_conn, phr_id, emergency_staff_name, emergency_unit_name, &phr_request_id))
	{
		// Send the "ask_connection_still_alive"
		write_token_into_buffer("ask_connection_still_alive", NULL, true, buffer);
		SSL_send_buffer_ignore_error(ssl_client, buffer, strlen(buffer));    // Ignore an error

		// Receive the ask_connection_still_alive result
		if(!SSL_recv_buffer_ignore_error(ssl_client, buffer, NULL))
		{
			// Transaction is cancelled by the client
			goto OPERATION_HAS_BEEN_CANCELLED;
		}

		// Send the "emergency_phr_processing_success_flag"
		write_token_into_buffer("emergency_phr_processing_success_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Getting the PHR request id failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the emergency_phr_processing_success_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Get the number of approvals
	get_no_approvals(db_conn, phr_request_id, &no_approvals);

	if(no_approvals < threshold_value)
	{
		// Send the "ask_connection_still_alive"
		write_token_into_buffer("ask_connection_still_alive", NULL, true, buffer);
		SSL_send_buffer_ignore_error(ssl_client, buffer, strlen(buffer));    // Ignore an error

		// Receive the ask_connection_still_alive result
		if(!SSL_recv_buffer_ignore_error(ssl_client, buffer, NULL))
		{
			// Transaction is cancelled by the client
			goto OPERATION_HAS_BEEN_CANCELLED;
		}

		// Send the "emergency_phr_processing_success_flag"
		write_token_into_buffer("emergency_phr_processing_success_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "The number of approvals is not enough to decrypt the unique emergency key", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the emergency_phr_processing_success_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Get the unique emergency key password
	if(!get_unique_emergency_key_passwd(db_conn, phr_id, phr_request_id, unique_str_hash, unique_emergency_key_passwd))
	{
		// Send the "ask_connection_still_alive"
		write_token_into_buffer("ask_connection_still_alive", NULL, true, buffer);
		SSL_send_buffer_ignore_error(ssl_client, buffer, strlen(buffer));    // Ignore an error

		// Receive the ask_connection_still_alive result
		if(!SSL_recv_buffer_ignore_error(ssl_client, buffer, NULL))
		{
			// Transaction is cancelled by the client
			goto OPERATION_HAS_BEEN_CANCELLED;
		}

		// Send the "emergency_phr_processing_success_flag"
		write_token_into_buffer("emergency_phr_processing_success_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Getting the unique emergency key password failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the emergency_phr_processing_success_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Send the "ask_connection_still_alive"
	write_token_into_buffer("ask_connection_still_alive", NULL, true, buffer);
	SSL_send_buffer_ignore_error(ssl_client, buffer, strlen(buffer));    // Ignore an error

	// Receive the ask_connection_still_alive result
	if(!SSL_recv_buffer_ignore_error(ssl_client, buffer, NULL))
	{
		// Transaction is cancelled by the client
		goto OPERATION_HAS_BEEN_CANCELLED;
	}

	// Download the requested restricted-level PHR
	if(!download_phr(desired_phr_ownername, phr_id, decrypted_phr_target_file_path, error_msg))
	{
		// Send the "ask_connection_still_alive"
		write_token_into_buffer("ask_connection_still_alive", NULL, true, buffer);
		SSL_send_buffer_ignore_error(ssl_client, buffer, strlen(buffer));    // Ignore an error

		// Receive the ask_connection_still_alive result
		if(!SSL_recv_buffer_ignore_error(ssl_client, buffer, NULL))
		{
			// Transaction is cancelled by the client
			goto OPERATION_HAS_BEEN_CANCELLED;
		}

		// Send the "emergency_phr_processing_success_flag"
		write_token_into_buffer("emergency_phr_processing_success_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", error_msg, false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the emergency_phr_processing_success_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Send the "ask_connection_still_alive"
	write_token_into_buffer("ask_connection_still_alive", NULL, true, buffer);
	SSL_send_buffer_ignore_error(ssl_client, buffer, strlen(buffer));    // Ignore an error

	// Receive the ask_connection_still_alive result
	if(!SSL_recv_buffer_ignore_error(ssl_client, buffer, NULL))
	{
		// Transaction is cancelled by the client
		goto OPERATION_HAS_BEEN_CANCELLED;
	}

	// Decrypt the restricted-level PHR
	if(!decrypt_restricted_level_phr(db_conn, phr_id, enc_unique_emergency_key_path, unique_emergency_key_path, unique_emergency_key_passwd, 
		decrypted_phr_target_file_path, archived_phr_file_path, error_msg))
	{
		// Send the "ask_connection_still_alive"
		write_token_into_buffer("ask_connection_still_alive", NULL, true, buffer);
		SSL_send_buffer_ignore_error(ssl_client, buffer, strlen(buffer));    // Ignore an error

		// Receive the ask_connection_still_alive result
		if(!SSL_recv_buffer_ignore_error(ssl_client, buffer, NULL))
		{
			// Transaction is cancelled by the client
			goto OPERATION_HAS_BEEN_CANCELLED;
		}

		// Send the "emergency_phr_processing_success_flag"
		write_token_into_buffer("emergency_phr_processing_success_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", error_msg, false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the emergency_phr_processing_success_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	unlink(enc_unique_emergency_key_path);
	unlink(unique_emergency_key_path);
	unlink(decrypted_phr_target_file_path);

	// Send the "ask_connection_still_alive"
	write_token_into_buffer("ask_connection_still_alive", NULL, true, buffer);
	SSL_send_buffer_ignore_error(ssl_client, buffer, strlen(buffer));    // Ignore an error

	// Receive the ask_connection_still_alive result
	if(!SSL_recv_buffer_ignore_error(ssl_client, buffer, NULL))
	{
		// Transaction is cancelled by the client
		goto OPERATION_HAS_BEEN_CANCELLED;
	}

	// Send the "emergency_phr_processing_success_flag"
	write_token_into_buffer("emergency_phr_processing_success_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the emergency_phr_processing_success_flag failed\n");
		goto ERROR;
	}

	// Send the PHR file size
	if(!get_file_size(archived_phr_file_path, &file_size))
	{
		fprintf(stderr, "Getting the requested restricted-level PHR file size failed\n");
		goto ERROR;
	}

	sprintf(file_size_str_tmp, "%u", file_size);
	write_token_into_buffer("file_size", file_size_str_tmp, true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the file_size failed\n");
		goto ERROR;
	}

	// Send the requested restricted-level PHR file
	if(!SSL_send_large_file(ssl_client, archived_phr_file_path))
	{
		fprintf(stderr, "Sending the requested restricted-level PHR file failed\n");
		goto ERROR;
	}

	unlink(archived_phr_file_path);

	// Remove the access request from the database
	remove_access_request(db_conn, phr_request_id);

	disconnect_db(&db_conn);
	db_conn = NULL;

	// Record a transaction log
	record_emergency_phr_access_transaction_log(ssl_client, desired_phr_ownername, phr_description, RESTRICTED_LEVEL_PHR_ACCESSING_MSG);

	// Send the notification to the PHR owner's e-mail address
	notify_phr_owner_emergency_phr_downloading(desired_phr_ownername, true, phr_description, emergency_unit_name, emergency_staff_name);

	return;

ERROR_BEFORE_RESEASE_WAIT_MUTEX:

	// Release the critical section, so that the main thread can serve new incoming requests
	if(sem_post(&wait_for_creating_new_child_thread_mutex) != 0)
		int_error("Signaling for creating the thread \"respond_emergency_phr_accessing_main\" failed");

ERROR:
OPERATION_HAS_BEEN_CANCELLED:

	if(db_conn)
	{
		disconnect_db(&db_conn);
		db_conn = NULL;
	}

	unlink(enc_unique_emergency_key_path);
	unlink(unique_emergency_key_path);
	unlink(decrypted_phr_target_file_path);
	unlink(archived_phr_file_path);
	return;
}

static void *respond_emergency_phr_accessing_main(void *arg)
{
	SSL  *ssl_client = (SSL *)arg;

	char buffer[BUFFER_LENGTH + 1];
	char token_name[TOKEN_NAME_LENGTH + 1];
	char request_type[REQUEST_TYPE_LENGTH + 1];

	// Receive request type information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving request type information failed\n");
		goto ERROR;
	}

	// Get a request type information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, request_type) != READ_TOKEN_SUCCESS || strcmp(token_name, "request_type") != 0)
	{
		int_error("Extracting the request_type failed");
	}

	if(strcmp(request_type, SECURE_LEVEL_PHR_ACCESSING) == 0)
	{
		respond_secure_level_phr_accessing(ssl_client);
	}
	else if(strcmp(request_type, RESTRICTED_LEVEL_PHR_ACCESSING) == 0)
	{
		respond_restricted_level_phr_accessing(ssl_client);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_client);
	ssl_client = NULL;

	// Increase the counter
	if(sem_post(&remaining_operating_thread_counter_sem) != 0)
		int_error("Posting the counter \"remaining_operating_thread_counter_sem\" failed");

	pthread_exit(NULL);
    	return NULL;

ERROR:

	// Release the critical section, so that the main thread can serve new incoming requests
	if(sem_post(&wait_for_creating_new_child_thread_mutex) != 0)
		int_error("Signaling for creating the thread \"respond_emergency_phr_accessing_main\" failed");

	if(ssl_client)
	{
		SSL_cleanup(ssl_client);
		ssl_client = NULL;
	}

	// Increase the counter
	if(sem_post(&remaining_operating_thread_counter_sem) != 0)
		int_error("Posting the counter \"remaining_operating_thread_counter_sem\" failed");

	pthread_exit(NULL);
    	return NULL;	
}

void *emergency_phr_accessing_main(void *arg)
{
	BIO         *bio_acc    = NULL;
	BIO         *bio_client = NULL;
    	SSL         *ssl_client = NULL;
    	SSL_CTX     *ctx        = NULL;

	int         err;
	char        *host[1];

	THREAD_TYPE child_thread_id;

    	ctx = setup_server_ctx(EMS_EMERGENCY_ACCESS_CERTFILE_PATH, EMS_EMERGENCY_ACCESS_CERTFILE_PASSWD, EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(EMS_EMERGENCY_PHR_ACCESSING_PORT);
    	if(!bio_acc)
        	int_error("Creating server socket failed");
  
    	if(BIO_do_accept(bio_acc) <= 0)
        	int_error("Binding server socket failed");
  
    	for(;;)
    	{
        	if(BIO_do_accept(bio_acc) <= 0)
            		int_error("Accepting connection failed");
 
        	bio_client = BIO_pop(bio_acc);

        	if(!(ssl_client = SSL_new(ctx)))
            		int_error("Creating SSL context failed");

        	SSL_set_bio(ssl_client, bio_client, bio_client);
		if(SSL_accept(ssl_client) <= 0)
		{
        		fprintf(stderr, "Accepting SSL connection failed\n");
			goto ERROR_AT_SSL_LAYER;
		}

		host[0] = USER_CN;
    		if((err = post_connection_check(ssl_client, host, 1, false, NULL)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Pass and decrease the counter if the counter > 0, unless block until some thread increase the counter
		if(sem_wait(&remaining_operating_thread_counter_sem) != 0)
			int_error("Waiting the counter \"remaining_operating_thread_counter_sem\" failed");

		// Create a child thread
		if(THREAD_CREATE(child_thread_id, respond_emergency_phr_accessing_main, (void *)ssl_client) != 0)
			int_error("Creating a thread for \"respond_emergency_phr_accessing_main\" failed");

		// Wait for creating the new child thread
		if(sem_wait(&wait_for_creating_new_child_thread_mutex) != 0)
			int_error("Waiting for creating the thread \"respond_emergency_phr_accessing_main_main\" failed");

		// Detaching a child thread in order to allow the system automatically reclaims resources when the detached thread exits
		if(THREAD_DETACH(child_thread_id) != 0)
			int_error("Detaching a thread for \"respond_emergency_phr_accessing_main\" failed");
		
		continue;

ERROR_AT_SSL_LAYER:

		SSL_cleanup(ssl_client);
		ssl_client = NULL;
    		ERR_remove_state(0);
    	}
    
    	SSL_CTX_free(ctx);
	ctx = NULL;

    	BIO_free(bio_acc);
	bio_acc = NULL;

	pthread_exit(NULL);
    	return NULL;
}




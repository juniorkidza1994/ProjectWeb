#include "EmS_common.h"

// Local Function Prototypes
static boolean record_access_request_cancellation_transaction_logs(MYSQL *db_conn, SSL *ssl_client, char *phr_ownername, char *phr_description, unsigned int phr_request_id);
static boolean notify_related_users_access_request_cancellation(MYSQL *db_conn, SSL *ssl_client, char *phr_ownername, char *phr_description, unsigned int phr_request_id);
static boolean respond_restricted_level_phr_access_request_cancellation_main(SSL *ssl_client);
static boolean record_new_access_request_transaction_logs(MYSQL *db_conn, SSL *ssl_client, char *phr_ownername, char *phr_description);
static boolean notify_related_users_new_access_request(MYSQL *db_conn, SSL *ssl_client, char *phr_ownername, char *phr_description);
static boolean check_remote_site_phr_id_existence(MYSQL *db_conn, unsigned int remote_site_phr_id);
static boolean respond_restricted_level_phr_access_requesting_main(SSL *ssl_client);
static boolean process_request(SSL *ssl_client);

// Implementation
// Record transaction logs to the PHR owner and only the trusted users who do not have a dedection
static boolean record_access_request_cancellation_transaction_logs(MYSQL *db_conn, SSL *ssl_client, char *phr_ownername, char *phr_description, unsigned int phr_request_id)
{
	SSL          *ssl_AS_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];
	char         emergency_staff_name[USER_NAME_LENGTH + 1];
	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];
	char         current_date_time[DATETIME_STR_LENGTH  + 1];
	char         client_ip_address[IP_ADDRESS_LENGTH + 1];

	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	unsigned int trusted_user_id;
	char         trusted_user_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         trusted_username[USER_NAME_LENGTH + 1];

	// Get certificate owner's name, current date/time and client's IP address
	get_cert_owner_info(ssl_client, emergency_unit_name, emergency_staff_name);
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_client, client_ip_address, NULL);

	// Connect to Audit Server
	if(!connect_to_transaction_log_recording_service(&ssl_AS_conn))
		goto ERROR;

	// Send a request type
	write_token_into_buffer("request_type", MULTIPLE_EVENT_LOGS_RECORDING, true, buffer);
	if(!SSL_send_buffer(ssl_AS_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a request type failed\n");
		goto ERROR;
	}

	// Record a transaction log to the PHR owner
	write_token_into_buffer("is_end_of_recording_multiple_event_logs_flag", "0", true, buffer);
	write_token_into_buffer("actor_name", emergency_staff_name, false, buffer);
	write_token_into_buffer("actor_authority_name", emergency_unit_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_owner_name", phr_ownername, false, buffer);
	write_token_into_buffer("object_owner_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("affected_username", NO_REFERENCE_USERNAME, false, buffer);
	write_token_into_buffer("affected_user_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_description", phr_description, false, buffer);
	write_token_into_buffer("event_description", RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_CANCELLATION_MSG, false, buffer);
	write_token_into_buffer("date_time", current_date_time, false, buffer);
	write_token_into_buffer("actor_ip_address", client_ip_address, false, buffer);

	if(!SSL_send_buffer(ssl_AS_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a transaction log failed\n");
		goto ERROR;
	}

	// Query for all trusted users of the specific PHR owner
	sprintf(stat, "SELECT DGT.trusted_user_id FROM %s DGT, %s USR, %s AUT WHERE DGT.phr_owner_id = USR.user_id AND USR.username LIKE '%s' COLLATE latin1_general_cs "
		"AND USR.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND DGT.rejection_by_trusted_user_flag = '0'", 
		EMS__DELEGATIONS, EMS__USERS, EMS__AUTHORITIES, phr_ownername, GLOBAL_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		trusted_user_id = atoi(row[0]);

		// If the trusted user took the deduction on this request, skip recording a transaction to his event log
		if(check_trusted_user_had_deduction_this_request(db_conn, trusted_user_id, phr_request_id))
			continue;

		// Get the trusted user's info
		if(!get_user_info(db_conn, trusted_user_id, trusted_user_authority_name, trusted_username))
			int_error("Getting the trusted user's info failed");

		// Record transaction logs to only the trusted users who do not have a dedection
		write_token_into_buffer("is_end_of_recording_multiple_event_logs_flag", "0", true, buffer);
		write_token_into_buffer("actor_name", emergency_staff_name, false, buffer);
		write_token_into_buffer("actor_authority_name", emergency_unit_name, false, buffer);
		write_token_into_buffer("does_actor_is_admin_flag", "0", false, buffer);
		write_token_into_buffer("object_owner_name", phr_ownername, false, buffer);
		write_token_into_buffer("object_owner_authority_name", GLOBAL_authority_name, false, buffer);
		write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
		write_token_into_buffer("affected_username", trusted_username, false, buffer);
		write_token_into_buffer("affected_user_authority_name", trusted_user_authority_name, false, buffer);
		write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
		write_token_into_buffer("object_description", phr_description, false, buffer);
		write_token_into_buffer("event_description", RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_CANCELLATION__TRUSTED_USER_MSG, false, buffer);
		write_token_into_buffer("date_time", current_date_time, false, buffer);
		write_token_into_buffer("actor_ip_address", client_ip_address, false, buffer);

		if(!SSL_send_buffer(ssl_AS_conn, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending a transaction log failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Send the "is_end_of_recording_multiple_event_logs_flag"
	write_token_into_buffer("is_end_of_recording_multiple_event_logs_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_AS_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the is_end_of_recording_multiple_event_logs_flag failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_AS_conn);
	ssl_AS_conn = NULL;
	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(ssl_AS_conn)
	{
		SSL_cleanup(ssl_AS_conn);
		ssl_AS_conn = NULL;
	}

	return false;
}

// Notify the PHR owner and only the trusted users who do not have a dedection the access request cancellation through their email addresses
static boolean notify_related_users_access_request_cancellation(MYSQL *db_conn, SSL *ssl_client, char *phr_ownername, char *phr_description, unsigned int phr_request_id)
{
	char         emergency_staff_name[USER_NAME_LENGTH + 1];
	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];

	SSL          *ssl_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         emergency_user_email_addr_requesting_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      emergency_user_email_addr_requesting_result_flag;

	char         payload_msg_list[8][EMAIL_MSG_LINE_LENGTH + 1];
	char         payload_buffer[EMAIL_MSG_LINE_LENGTH + 1];
	char         error_msg[ERR_MSG_LENGTH + 1];

	char         phr_owner_email_addr[EMAIL_ADDRESS_LENGTH + 1];
	char         trusted_user_email_addr[EMAIL_ADDRESS_LENGTH + 1];
	char         *ptr_trusted_user_email_addr_list = NULL;

	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	unsigned int no_trusted_users        = 0;
	unsigned int no_trusted_user_counter = 0;

	unsigned int trusted_user_id;
	char         trusted_user_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         trusted_username[USER_NAME_LENGTH + 1];

	// Get certificate owner's name
	get_cert_owner_info(ssl_client, emergency_unit_name, emergency_staff_name);

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
		goto ERROR;
	}

	if(read_token_from_buffer(buffer, 2, token_name, phr_owner_email_addr) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_user_email_address") != 0)
	{
		int_error("Extracting the emergency_user_email_address failed");
	}

	// Send notification to the PHR owner
	sprintf(payload_buffer, "To: %s(PHR owner)\n", phr_owner_email_addr);
	config_email_payload(0, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "From: %s(%s's emergency mailer)\n", GLOBAL_authority_email_address, GLOBAL_authority_name);
	config_email_payload(1, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Subject: Emergency staff cancelled the access request on your restricted-level PHR\n");
	config_email_payload(2, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "\n");  // Empty line to divide headers from body, see RFC5322
	config_email_payload(3, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Emergency staff: %s.%s\n", emergency_unit_name, emergency_staff_name);
	config_email_payload(4, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Action: Cancel an access request on the restricted-level PHR\n");
	config_email_payload(5, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Data description: %s\n", phr_description);
	config_email_payload(6, payload_buffer, payload_msg_list);

	if(!send_email(1, phr_owner_email_addr, 7, *payload_msg_list, error_msg))
	{
		fprintf(stderr, "Sending notification to a PHR owner's email address failed (%s)\n", error_msg);
		goto ERROR;
	}

	// Query for all trusted users of the specific PHR owner
	sprintf(stat, "SELECT DGT.trusted_user_id FROM %s DGT, %s USR, %s AUT WHERE DGT.phr_owner_id = USR.user_id AND USR.username LIKE '%s' COLLATE latin1_general_cs "
		"AND USR.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND DGT.rejection_by_trusted_user_flag = '0'", 
		EMS__DELEGATIONS, EMS__USERS, EMS__AUTHORITIES, phr_ownername, GLOBAL_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);

	// Get number of trusted users
	no_trusted_users        = mysql_num_rows(result);
	no_trusted_user_counter = 0;

	// Allocate a heap variable
	ptr_trusted_user_email_addr_list = (char *)malloc(no_trusted_users*(EMAIL_ADDRESS_LENGTH + 1));
	if(!ptr_trusted_user_email_addr_list)
	{
		int_error("Allocating memory for \"ptr_trusted_user_email_addr_list\" failed");
	}

	while((row = mysql_fetch_row(result)))
	{
		trusted_user_id = atoi(row[0]);

		// If the trusted user took the deduction on this request, skip sending notification to him
		if(check_trusted_user_had_deduction_this_request(db_conn, trusted_user_id, phr_request_id))
			continue;

		// Get the trusted user's info
		if(!get_user_info(db_conn, trusted_user_id, trusted_user_authority_name, trusted_username))
			int_error("Getting the trusted user's info failed");

		// Send the emergency user's email address request
		write_token_into_buffer("is_end_of_getting_emergency_user_email_address_flag", "0", true, buffer);
		write_token_into_buffer("desired_authority_name", trusted_user_authority_name, false, buffer);
		write_token_into_buffer("desired_username", trusted_username, false, buffer);

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
			fprintf(stderr, "Do not found the trusted user's email address\n");
			continue;
		}

		if(read_token_from_buffer(buffer, 2, token_name, trusted_user_email_addr) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_user_email_address") != 0)
		{
			int_error("Extracting the emergency_user_email_address failed");
		}

		// Fill the trusted user's email address into the list
		strncpy(ptr_trusted_user_email_addr_list + (no_trusted_user_counter * (EMAIL_ADDRESS_LENGTH + 1)), trusted_user_email_addr, EMAIL_ADDRESS_LENGTH);
		no_trusted_user_counter++;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
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

	if(no_trusted_user_counter)
	{
		// Send notification to only the trusted users who do not have a deduction
		sprintf(payload_buffer, "To: (%s.%s's trusted user)\n", GLOBAL_authority_name, phr_ownername);
		config_email_payload(0, payload_buffer, payload_msg_list);

		sprintf(payload_buffer, "From: %s(%s's emergency mailer)\n", GLOBAL_authority_email_address, GLOBAL_authority_name);
		config_email_payload(1, payload_buffer, payload_msg_list);

		sprintf(payload_buffer, "Subject: Emergency staff cancelled the access request on your emergency PHR owner's restricted-level PHR\n");
		config_email_payload(2, payload_buffer, payload_msg_list);

		sprintf(payload_buffer, "\n");  // Empty line to divide headers from body, see RFC5322
		config_email_payload(3, payload_buffer, payload_msg_list);

		sprintf(payload_buffer, "Emergency staff: %s.%s\n", emergency_unit_name, emergency_staff_name);
		config_email_payload(4, payload_buffer, payload_msg_list);

		sprintf(payload_buffer, "PHR owner: %s.%s\n", GLOBAL_authority_name, phr_ownername);
		config_email_payload(5, payload_buffer, payload_msg_list);

		sprintf(payload_buffer, "Action: Cancel an access request on the restricted-level PHR\n");
		config_email_payload(6, payload_buffer, payload_msg_list);

		sprintf(payload_buffer, "Data description: %s\n", phr_description);
		config_email_payload(7, payload_buffer, payload_msg_list);

		if(!send_email(no_trusted_user_counter, ptr_trusted_user_email_addr_list, 8, *payload_msg_list, error_msg))
		{
			fprintf(stderr, "Sending notification to trusted users' email addresses failed (%s)\n", error_msg);
			goto ERROR;
		}
	}

	free(ptr_trusted_user_email_addr_list);
	ptr_trusted_user_email_addr_list = NULL;
	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	if(ptr_trusted_user_email_addr_list)
	{
		free(ptr_trusted_user_email_addr_list);
		ptr_trusted_user_email_addr_list = NULL;
	}

	return false;
}

static boolean respond_restricted_level_phr_access_request_cancellation_main(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         phr_ownername[USER_NAME_LENGTH + 1];
	char         phr_description[DATA_DESCRIPTION_LENGTH + 1];

	char         remote_site_phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int remote_site_phr_id;

	char         emergency_staff_name[USER_NAME_LENGTH + 1];
	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];

	unsigned int phr_request_id;

	MYSQL        *db_conn = NULL;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	// Receive the restricted-level PHR access request cancellation information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the restricted-level PHR access request cancellation information failed\n");
		goto ERROR;
	}

	// Get the restricted-level PHR access request cancellation information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		int_error("Extracting the phr_ownername failed");

	if(read_token_from_buffer(buffer, 2, token_name, remote_site_phr_id_str) != READ_TOKEN_SUCCESS || strcmp(token_name, "remote_site_phr_id") != 0)
		int_error("Extracting the remote_site_phr_id failed");

	remote_site_phr_id = atoi(remote_site_phr_id_str);

	if(read_token_from_buffer(buffer, 3, token_name, phr_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_description") != 0)
		int_error("Extracting the phr_description failed");

	// Get the emergency staff info
	get_cert_owner_info(ssl_client, emergency_unit_name, emergency_staff_name);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of the request on the requested restricted-level PHR of this emergency staff
	if(!get_access_request_id(db_conn, remote_site_phr_id, emergency_staff_name, emergency_unit_name, &phr_request_id))   // Not found
	{
		// Send the restricted_level_phr_access_request_cancellation_result_flag
		write_token_into_buffer("restricted_level_phr_access_request_cancellation_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found your request on the restricted-level PHR", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted_level_phr_access_request_cancellation_result_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Record transaction logs to the PHR owner and only the trusted users who do not have a dedection
	record_access_request_cancellation_transaction_logs(db_conn, ssl_client, phr_ownername, phr_description, phr_request_id);

	// Notify the PHR owner and only the trusted users who do not have a dedection the access request cancellation through their email addresses
	notify_related_users_access_request_cancellation(db_conn, ssl_client, phr_ownername, phr_description, phr_request_id);

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

	disconnect_db(&db_conn);
	db_conn = NULL;

	// Send the restricted_level_phr_access_request_cancellation_result_flag
	write_token_into_buffer("restricted_level_phr_access_request_cancellation_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the restricted_level_phr_access_request_cancellation_result_flag failed\n");
		goto ERROR;
	}
	
	return true;

ERROR:

	if(db_conn)
	{
		disconnect_db(&db_conn);
		db_conn = NULL;
	}

	return false;
}

// Record transaction logs to the PHR owner and all trusted users
static boolean record_new_access_request_transaction_logs(MYSQL *db_conn, SSL *ssl_client, char *phr_ownername, char *phr_description)
{
	SSL          *ssl_AS_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];
	char         emergency_staff_name[USER_NAME_LENGTH + 1];
	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];
	char         current_date_time[DATETIME_STR_LENGTH  + 1];
	char         client_ip_address[IP_ADDRESS_LENGTH + 1];

	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	unsigned int trusted_user_id;
	char         trusted_user_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         trusted_username[USER_NAME_LENGTH + 1];

	// Get certificate owner's name, current date/time and client's IP address
	get_cert_owner_info(ssl_client, emergency_unit_name, emergency_staff_name);
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_client, client_ip_address, NULL);

	// Connect to Audit Server
	if(!connect_to_transaction_log_recording_service(&ssl_AS_conn))
		goto ERROR;

	// Send a request type
	write_token_into_buffer("request_type", MULTIPLE_EVENT_LOGS_RECORDING, true, buffer);
	if(!SSL_send_buffer(ssl_AS_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a request type failed\n");
		goto ERROR;
	}

	// Record a transaction log to the PHR owner
	write_token_into_buffer("is_end_of_recording_multiple_event_logs_flag", "0", true, buffer);
	write_token_into_buffer("actor_name", emergency_staff_name, false, buffer);
	write_token_into_buffer("actor_authority_name", emergency_unit_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_owner_name", phr_ownername, false, buffer);
	write_token_into_buffer("object_owner_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("affected_username", NO_REFERENCE_USERNAME, false, buffer);
	write_token_into_buffer("affected_user_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_description", phr_description, false, buffer);
	write_token_into_buffer("event_description", RESTRICTED_LEVEL_PHR_ACCESS_REQUESTING_MSG, false, buffer);
	write_token_into_buffer("date_time", current_date_time, false, buffer);
	write_token_into_buffer("actor_ip_address", client_ip_address, false, buffer);

	if(!SSL_send_buffer(ssl_AS_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a transaction log failed\n");
		goto ERROR;
	}

	// Query for all trusted users of the specific PHR owner
	sprintf(stat, "SELECT DGT.trusted_user_id FROM %s DGT, %s USR, %s AUT WHERE DGT.phr_owner_id = USR.user_id AND USR.username LIKE '%s' COLLATE latin1_general_cs "
		"AND USR.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND DGT.rejection_by_trusted_user_flag = '0'", 
		EMS__DELEGATIONS, EMS__USERS, EMS__AUTHORITIES, phr_ownername, GLOBAL_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		trusted_user_id = atoi(row[0]);

		// Get the trusted user's info
		if(!get_user_info(db_conn, trusted_user_id, trusted_user_authority_name, trusted_username))
			int_error("Getting the trusted user's info failed");

		// Record transaction logs to all trusted users
		write_token_into_buffer("is_end_of_recording_multiple_event_logs_flag", "0", true, buffer);
		write_token_into_buffer("actor_name", emergency_staff_name, false, buffer);
		write_token_into_buffer("actor_authority_name", emergency_unit_name, false, buffer);
		write_token_into_buffer("does_actor_is_admin_flag", "0", false, buffer);
		write_token_into_buffer("object_owner_name", phr_ownername, false, buffer);
		write_token_into_buffer("object_owner_authority_name", GLOBAL_authority_name, false, buffer);
		write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
		write_token_into_buffer("affected_username", trusted_username, false, buffer);
		write_token_into_buffer("affected_user_authority_name", trusted_user_authority_name, false, buffer);
		write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
		write_token_into_buffer("object_description", phr_description, false, buffer);
		write_token_into_buffer("event_description", RESTRICTED_LEVEL_PHR_ACCESS_REQUESTING__TRUSTED_USER_MSG, false, buffer);
		write_token_into_buffer("date_time", current_date_time, false, buffer);
		write_token_into_buffer("actor_ip_address", client_ip_address, false, buffer);

		if(!SSL_send_buffer(ssl_AS_conn, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending a transaction log failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Send the "is_end_of_recording_multiple_event_logs_flag"
	write_token_into_buffer("is_end_of_recording_multiple_event_logs_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_AS_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the is_end_of_recording_multiple_event_logs_flag failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_AS_conn);
	ssl_AS_conn = NULL;
	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(ssl_AS_conn)
	{
		SSL_cleanup(ssl_AS_conn);
		ssl_AS_conn = NULL;
	}

	return false;
}

// Notify the PHR owner and all trusted users the new access request through their email addresses
static boolean notify_related_users_new_access_request(MYSQL *db_conn, SSL *ssl_client, char *phr_ownername, char *phr_description)
{
	char         emergency_staff_name[USER_NAME_LENGTH + 1];
	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];

	SSL          *ssl_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         emergency_user_email_addr_requesting_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      emergency_user_email_addr_requesting_result_flag;

	char         payload_msg_list[8][EMAIL_MSG_LINE_LENGTH + 1];
	char         payload_buffer[EMAIL_MSG_LINE_LENGTH + 1];
	char         error_msg[ERR_MSG_LENGTH + 1];

	char         phr_owner_email_addr[EMAIL_ADDRESS_LENGTH + 1];
	char         trusted_user_email_addr[EMAIL_ADDRESS_LENGTH + 1];
	char         *ptr_trusted_user_email_addr_list = NULL;

	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	unsigned int no_trusted_users        = 0;
	unsigned int no_trusted_user_counter = 0;

	unsigned int trusted_user_id;
	char         trusted_user_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         trusted_username[USER_NAME_LENGTH + 1];

	// Get certificate owner's name
	get_cert_owner_info(ssl_client, emergency_unit_name, emergency_staff_name);

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
		goto ERROR;
	}

	if(read_token_from_buffer(buffer, 2, token_name, phr_owner_email_addr) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_user_email_address") != 0)
	{
		int_error("Extracting the emergency_user_email_address failed");
	}

	// Send notification to the PHR owner
	sprintf(payload_buffer, "To: %s(PHR owner)\n", phr_owner_email_addr);
	config_email_payload(0, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "From: %s(%s's emergency mailer)\n", GLOBAL_authority_email_address, GLOBAL_authority_name);
	config_email_payload(1, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Subject: Emergency staff requested an access to your restricted-level PHR\n");
	config_email_payload(2, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "\n");  // Empty line to divide headers from body, see RFC5322
	config_email_payload(3, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Emergency staff: %s.%s\n", emergency_unit_name, emergency_staff_name);
	config_email_payload(4, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Action: Request an access permission on the restricted-level PHR\n");
	config_email_payload(5, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Data description: %s\n", phr_description);
	config_email_payload(6, payload_buffer, payload_msg_list);

	if(!send_email(1, phr_owner_email_addr, 7, *payload_msg_list, error_msg))
	{
		fprintf(stderr, "Sending notification to a PHR owner's email address failed (%s)\n", error_msg);
		goto ERROR;
	}

	// Query for all trusted users of the specific PHR owner
	sprintf(stat, "SELECT DGT.trusted_user_id FROM %s DGT, %s USR, %s AUT WHERE DGT.phr_owner_id = USR.user_id AND USR.username LIKE '%s' COLLATE latin1_general_cs "
		"AND USR.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND DGT.rejection_by_trusted_user_flag = '0'", 
		EMS__DELEGATIONS, EMS__USERS, EMS__AUTHORITIES, phr_ownername, GLOBAL_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);

	// Get number of trusted users
	no_trusted_users        = mysql_num_rows(result);
	no_trusted_user_counter = 0;

	// Allocate a heap variable
	ptr_trusted_user_email_addr_list = (char *)malloc(no_trusted_users*(EMAIL_ADDRESS_LENGTH + 1));
	if(!ptr_trusted_user_email_addr_list)
	{
		int_error("Allocating memory for \"ptr_trusted_user_email_addr_list\" failed");
	}

	while((row = mysql_fetch_row(result)))
	{
		trusted_user_id = atoi(row[0]);

		// Get the trusted user's info
		if(!get_user_info(db_conn, trusted_user_id, trusted_user_authority_name, trusted_username))
			int_error("Getting the trusted user's info failed");

		// Send the emergency user's email address request
		write_token_into_buffer("is_end_of_getting_emergency_user_email_address_flag", "0", true, buffer);
		write_token_into_buffer("desired_authority_name", trusted_user_authority_name, false, buffer);
		write_token_into_buffer("desired_username", trusted_username, false, buffer);

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
			fprintf(stderr, "Do not found the trusted user's email address\n");
			continue;
		}

		if(read_token_from_buffer(buffer, 2, token_name, trusted_user_email_addr) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_user_email_address") != 0)
		{
			int_error("Extracting the emergency_user_email_address failed");
		}

		// Fill the trusted user's email address into the list
		strncpy(ptr_trusted_user_email_addr_list + (no_trusted_user_counter * (EMAIL_ADDRESS_LENGTH + 1)), trusted_user_email_addr, EMAIL_ADDRESS_LENGTH);
		no_trusted_user_counter++;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
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

	if(no_trusted_user_counter)
	{
		// Send notification to all trusted users
		sprintf(payload_buffer, "To: (%s.%s's trusted user)\n", GLOBAL_authority_name, phr_ownername);
		config_email_payload(0, payload_buffer, payload_msg_list);

		sprintf(payload_buffer, "From: %s(%s's emergency mailer)\n", GLOBAL_authority_email_address, GLOBAL_authority_name);
		config_email_payload(1, payload_buffer, payload_msg_list);

		sprintf(payload_buffer, "Subject: Emergency staff requested an access to your emergency PHR owner's restricted-level PHR\n");
		config_email_payload(2, payload_buffer, payload_msg_list);

		sprintf(payload_buffer, "\n");  // Empty line to divide headers from body, see RFC5322
		config_email_payload(3, payload_buffer, payload_msg_list);

		sprintf(payload_buffer, "Emergency staff: %s.%s\n", emergency_unit_name, emergency_staff_name);
		config_email_payload(4, payload_buffer, payload_msg_list);

		sprintf(payload_buffer, "PHR owner: %s.%s\n", GLOBAL_authority_name, phr_ownername);
		config_email_payload(5, payload_buffer, payload_msg_list);

		sprintf(payload_buffer, "Action: Request an access permission on the restricted-level PHR\n");
		config_email_payload(6, payload_buffer, payload_msg_list);

		sprintf(payload_buffer, "Data description: %s\n", phr_description);
		config_email_payload(7, payload_buffer, payload_msg_list);

		if(!send_email(no_trusted_user_counter, ptr_trusted_user_email_addr_list, 8, *payload_msg_list, error_msg))
		{
			fprintf(stderr, "Sending notification to all trusted users' email addresses failed (%s)\n", error_msg);
			goto ERROR;
		}
	}

	free(ptr_trusted_user_email_addr_list);
	ptr_trusted_user_email_addr_list = NULL;
	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	if(ptr_trusted_user_email_addr_list)
	{
		free(ptr_trusted_user_email_addr_list);
		ptr_trusted_user_email_addr_list = NULL;
	}

	return false;
}

static boolean check_remote_site_phr_id_existence(MYSQL *db_conn, unsigned int remote_site_phr_id)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char      err_msg[ERR_MSG_LENGTH + 1];

	boolean   found_flag = false;

	// Check for the existence of the specific restricted-level PHR
	sprintf(stat, "SELECT remote_site_phr_id FROM %s WHERE remote_site_phr_id = %u", EMS__RESTRICTED_LEVEL_PHRS, remote_site_phr_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(row)
	{
		found_flag = true;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return found_flag;
}

static boolean respond_restricted_level_phr_access_requesting_main(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         phr_ownername[USER_NAME_LENGTH + 1];
	char         phr_description[DATA_DESCRIPTION_LENGTH + 1];

	char         remote_site_phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int remote_site_phr_id;

	char         emergency_staff_name[USER_NAME_LENGTH + 1];
	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];
	char         emergency_staff_email_address[EMAIL_ADDRESS_LENGTH + 1];

	MYSQL        *db_conn = NULL;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	// Receive the restricted-level PHR access requesting information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the restricted-level PHR access requesting information failed\n");
		goto ERROR;
	}

	// Get the restricted-level PHR access requesting information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		int_error("Extracting the phr_ownername failed");

	if(read_token_from_buffer(buffer, 2, token_name, remote_site_phr_id_str) != READ_TOKEN_SUCCESS || strcmp(token_name, "remote_site_phr_id") != 0)
		int_error("Extracting the remote_site_phr_id failed");

	remote_site_phr_id = atoi(remote_site_phr_id_str);

	if(read_token_from_buffer(buffer, 3, token_name, phr_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_description") != 0)
		int_error("Extracting the phr_description failed");

	if(read_token_from_buffer(buffer, 4, token_name, emergency_staff_email_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_staff_email_address") != 0)
		int_error("Extracting the emergency_staff_email_address failed");

	// Get the emergency staff info
	get_cert_owner_info(ssl_client, emergency_unit_name, emergency_staff_name);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);
	
	// Check for the existence of the requested restricted-level PHR
	if(!check_remote_site_phr_id_existence(db_conn, remote_site_phr_id))  // Not found
	{
		// Send the restricted_level_phr_access_requesting_result_flag
		write_token_into_buffer("restricted_level_phr_access_requesting_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found the requested restricted-level PHR", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted_level_phr_access_requesting_result_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Check for the existence of the request on the requested restricted-level PHR of this emergency staff
	if(check_access_request_existence(db_conn, remote_site_phr_id, emergency_staff_name, emergency_unit_name))   // Found
	{
		// Send the restricted_level_phr_access_requesting_result_flag
		write_token_into_buffer("restricted_level_phr_access_requesting_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "You have requested on this restricted-level PHR already", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted_level_phr_access_requesting_result_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Insert the new request
	sprintf(stat, "INSERT INTO %s(remote_site_phr_id, approval_notification_flag, emergency_unit_name, emergency_staff_name, emergency_staff_email_address) "
		"VALUES(%u, '0', '%s', '%s', '%s')", EMS__RESTRICTED_LEVEL_PHR_REQUESTS, remote_site_phr_id, emergency_unit_name, emergency_staff_name, 
		emergency_staff_email_address);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	// Record transaction logs to the PHR owner and all trusted users
	record_new_access_request_transaction_logs(db_conn, ssl_client, phr_ownername, phr_description);

	// Notify the PHR owner and all trusted users the new access request through their email addresses
	notify_related_users_new_access_request(db_conn, ssl_client, phr_ownername, phr_description);

	disconnect_db(&db_conn);
	db_conn = NULL;

	// Send the restricted_level_phr_access_requesting_result_flag
	write_token_into_buffer("restricted_level_phr_access_requesting_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the restricted_level_phr_access_requesting_result_flag failed\n");
		goto ERROR;
	}

	return true;

ERROR:

	if(db_conn)
	{
		disconnect_db(&db_conn);
		db_conn = NULL;
	}

	return false;
}

static boolean process_request(SSL *ssl_client)
{
	char buffer[BUFFER_LENGTH + 1];
	char token_name[TOKEN_NAME_LENGTH + 1];
	char request[REQUEST_TYPE_LENGTH + 1];

	// Receive request information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving request information failed\n");
		goto ERROR;
	}

	// Get a request information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, request) != READ_TOKEN_SUCCESS || strcmp(token_name, "request") != 0)
		int_error("Extracting the request failed");

	if(strcmp(request, RESTRICTED_LEVEL_PHR_ACCESS_REQUESTING) == 0)
	{
		return respond_restricted_level_phr_access_requesting_main(ssl_client);
	}
	else if(strcmp(request, RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_CANCELLATION) == 0)
	{
		return respond_restricted_level_phr_access_request_cancellation_main(ssl_client);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *restricted_level_phr_access_requesting_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(EMS_EMERGENCY_ACCESS_CERTFILE_PATH, EMS_EMERGENCY_ACCESS_CERTFILE_PASSWD, EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(EMS_RESTRICTED_LEVEL_PHR_ACCESS_REQUESTING_PORT);
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

		hosts[0] = USER_CN; 
    		if((err = post_connection_check(ssl_client, hosts, 1, false, NULL)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Process request
		if(!process_request(ssl_client))
			goto ERROR_AT_SSL_LAYER;
		
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




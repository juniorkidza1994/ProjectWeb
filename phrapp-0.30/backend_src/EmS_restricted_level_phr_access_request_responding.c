#include "EmS_common.h"

// Local Function Prototypes
static boolean get_delegation_id(MYSQL *db_conn, unsigned int trusted_user_id, unsigned int phr_owner_id, unsigned int *delegation_id_ret);
static boolean respond_approval_if_phr_owner_in_current_authority(SSL *ssl_client, char *trusted_username, char *trusted_user_authority_name, char *phr_ownername, 
	unsigned int remote_site_phr_id, char *phr_description, char *emergency_unit_name, char *emergency_staff_name);

static boolean send_encrypted_thrshold_secret_key(MYSQL *db_conn, SSL *ssl_client, unsigned int delegation_id, unsigned int remote_site_phr_id, char *file_data);
static boolean receive_unencrypted_threshold_secret_key(MYSQL *db_conn, SSL *ssl_client, unsigned int trusted_user_id, unsigned int phr_request_id, char *file_data, 
	char *file_chunk, char *query);

static void get_no_approvals(MYSQL *db_conn, unsigned int phr_request_id, unsigned int *no_approvals_ret);
static void get_threshold_value(MYSQL *db_conn, unsigned int remote_site_phr_id, unsigned int *threshold_value_ret);
static boolean is_approval_notification_flag_setted(MYSQL *db_conn, unsigned int phr_request_id);
static void set_approval_notification_flag(MYSQL *db_conn, unsigned int phr_request_id);
static void get_emergency_staff_email_address(MYSQL *db_conn, unsigned int phr_request_id, char *emergency_staff_email_address_ret);
static boolean notify_emergency_staff_request_approval(char *emergency_staff_email_address, char *phr_ownername, char *phr_description);

static boolean record_access_request_responding_transaction_log(SSL *ssl_client, char *trusted_username, char *trusted_user_authority_name, char *phr_ownername, 
	char *phr_owner_authority_name, char *phr_description, char *emergency_staff_name, char *emergency_unit_name, char *event_description);

static boolean get_phr_owner_email_address(char *phr_ownername, char *phr_owner_email_addr_ret);
static boolean notify_phr_owner_trusted_user_respond_access_request(char *phr_ownername, char *trusted_username, char *trusted_user_authority_name, 
	char *phr_description, char *emergency_staff_name, char *emergency_unit_name, boolean approval_flag, unsigned int no_approvals, unsigned int threshold_value);

// The another authority's Emergency Server service
static boolean connect_to_remote_restricted_level_phr_access_request_responding_service(char *authority_name, char *emergency_server_ip_addr, SSL **ssl_conn_ret);
static boolean respond_approval_if_phr_owner_in_another_authority(SSL *ssl_client, char *trusted_username, char *trusted_user_authority_name, char *phr_ownername, 
	char *phr_owner_authority_name, unsigned int remote_site_phr_id, char *phr_description, char *emergency_unit_name, char *emergency_staff_name);

static boolean respond_restricted_level_phr_access_request_approval_main(SSL *ssl_client);
static boolean respond_restricted_level_phr_access_request_no_approval_main(SSL *ssl_client);
static boolean respond_restricted_level_phr_access_request_cancellation_main(SSL *ssl_client);
static boolean process_request(SSL *ssl_client);
static boolean process_request_by_remote_ems(SSL *ssl_client);

// Implementation
static boolean get_delegation_id(MYSQL *db_conn, unsigned int trusted_user_id, unsigned int phr_owner_id, unsigned int *delegation_id_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char      err_msg[ERR_MSG_LENGTH + 1];

	boolean   has_delegation_flag = false;

	// Query for the delegation between specific PHR owner and trusted user
	sprintf(stat, "SELECT delegation_id FROM %s WHERE trusted_user_id = %u AND rejection_by_trusted_user_flag = '0' AND phr_owner_id = %u", 
		EMS__DELEGATIONS, trusted_user_id, phr_owner_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(row)
	{
		*delegation_id_ret = atoi(row[0]);
		has_delegation_flag = true;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return has_delegation_flag;
}

static boolean send_encrypted_thrshold_secret_key(MYSQL *db_conn, SSL *ssl_client, unsigned int delegation_id, unsigned int remote_site_phr_id, char *file_data)
{
	MYSQL_RES     *result = NULL;
  	MYSQL_ROW     row;
	char          stat[SQL_STATEMENT_LENGTH + 1];
	char          err_msg[ERR_MSG_LENGTH + 1];
	unsigned long *lengths = NULL;
	unsigned long file_data_length;

	// Query the corresponding trusted user's encrypted threshold secret key and write it to buffer
	sprintf(stat, "SELECT enc_secret_key FROM %s WHERE delegation_id = %u AND remote_site_phr_id = %u", EMS__SECRET_KEYS, delegation_id, remote_site_phr_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row    = mysql_fetch_row(result);
	if(!row)
	{
		int_error("Getting an encrypted threshold secret key from the database failed");
	}

	lengths = mysql_fetch_lengths(result);
	file_data_length = lengths[0];

	memcpy(file_data, row[0], file_data_length);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Send the encrypted threshold secrey key
	if(!SSL_send_buffer(ssl_client, file_data, file_data_length))
	{
		fprintf(stderr, "Sending the encrypted threshold secret key failed\n");
		goto ERROR;
	}

	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return false;	
}

static boolean receive_unencrypted_threshold_secret_key(MYSQL *db_conn, SSL *ssl_client, unsigned int trusted_user_id, unsigned int phr_request_id, char *file_data, 
	char *file_chunk, char *query)
{
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];
	unsigned int len, file_size;

	// Receive the unencrypted threshold secret key
	if(SSL_recv_buffer(ssl_client, file_data, &file_size) == 0)
	{
		fprintf(stderr, "Receiving the unencrypted threshold secret key failed\n");
		goto ERROR;
	}

	// Insert a new secret key approval row
	sprintf(stat, "INSERT INTO %s(trusted_user_id, phr_request_id, approval_flag, buffer_secret_key) "
		"VALUES(%u, %u, '1', '%%s')", EMS__SECRET_KEY_APPROVALS, trusted_user_id, phr_request_id);

	// Take the escaped SQL string
	mysql_real_escape_string(db_conn, file_chunk, file_data, file_size);
	len = snprintf(query, sizeof(stat)+sizeof(char)*((1000*1024)*2+1), stat, file_chunk);

	if(mysql_real_query(db_conn, query, len))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}

	return true;

ERROR:

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

static void get_threshold_value(MYSQL *db_conn, unsigned int remote_site_phr_id, unsigned int *threshold_value_ret)
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
		int_error("Getting the threshold value of the desired restricted-level PHR failed");
	}

	*threshold_value_ret = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static boolean is_approval_notification_flag_setted(MYSQL *db_conn, unsigned int phr_request_id)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	boolean   approval_notification_flag = false;

	// Query for the approval notification flag of the specific request
	sprintf(stat, "SELECT approval_notification_flag FROM %s WHERE phr_request_id = %u", EMS__RESTRICTED_LEVEL_PHR_REQUESTS, phr_request_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		int_error("Getting the approval notification flag of the specific request failed");
	}

	approval_notification_flag = (strcmp(row[0], "1") == 0) ? true : false;

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return approval_notification_flag;
}

static void set_approval_notification_flag(MYSQL *db_conn, unsigned int phr_request_id)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Set the approval_notification_flag
	sprintf(stat, "UPDATE %s SET approval_notification_flag = '1' WHERE phr_request_id = %u", EMS__RESTRICTED_LEVEL_PHR_REQUESTS, phr_request_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
}

static void get_emergency_staff_email_address(MYSQL *db_conn, unsigned int phr_request_id, char *emergency_staff_email_address_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Query for the emergency staff's email address
	sprintf(stat, "SELECT emergency_staff_email_address FROM %s WHERE phr_request_id = %u", EMS__RESTRICTED_LEVEL_PHR_REQUESTS, phr_request_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		int_error("Getting the emergency staff's email address of the specific request failed");
	}

	strcpy(emergency_staff_email_address_ret, row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static boolean notify_emergency_staff_request_approval(char *emergency_staff_email_address, char *phr_ownername, char *phr_description)
{
	char payload_msg_list[6][EMAIL_MSG_LINE_LENGTH + 1];
	char payload_buffer[EMAIL_MSG_LINE_LENGTH + 1];
	char error_msg[ERR_MSG_LENGTH + 1];

	sprintf(payload_buffer, "To: %s(Emergency staff)\n", emergency_staff_email_address);
	config_email_payload(0, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "From: %s(%s's emergency mailer)\n", GLOBAL_authority_email_address, GLOBAL_authority_name);
	config_email_payload(1, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Subject: Your request on the restricted-level PHR has been approved\n");
	config_email_payload(2, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "\n");  // Empty line to divide headers from body, see RFC5322
	config_email_payload(3, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "PHR owner: %s.%s\n", GLOBAL_authority_name, phr_ownername);
	config_email_payload(4, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Data description: %s\n", phr_description);
	config_email_payload(5, payload_buffer, payload_msg_list);

	if(!send_email(1, emergency_staff_email_address, 6, *payload_msg_list, error_msg))
	{
		fprintf(stderr, "Sending notification to an emergency staff's email address failed (%s)\n", error_msg);
		goto ERROR;
	}
	
	return true;

ERROR:

	return false;
}

static boolean record_access_request_responding_transaction_log(SSL *ssl_client, char *trusted_username, char *trusted_user_authority_name, char *phr_ownername, 
	char *phr_owner_authority_name, char *phr_description, char *emergency_staff_name, char *emergency_unit_name, char *event_description)
{
	SSL  *ssl_AS_conn = NULL;
	char buffer[BUFFER_LENGTH + 1];
	char current_date_time[DATETIME_STR_LENGTH  + 1];
	char client_ip_address[IP_ADDRESS_LENGTH + 1];
	char event_description_with_emergency_staff_indication[EVENT_DESCRIPTION_LENGTH + 1];

	// Get the current date/time and client's IP address
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_client, client_ip_address, NULL);

	sprintf(event_description_with_emergency_staff_indication, "%s: %s.%s", event_description, emergency_unit_name, emergency_staff_name);

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

	// Record a transaction log to the PHR owner
	write_token_into_buffer("actor_name", trusted_username, true, buffer);
	write_token_into_buffer("actor_authority_name", trusted_user_authority_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_owner_name", phr_ownername, false, buffer);
	write_token_into_buffer("object_owner_authority_name", phr_owner_authority_name, false, buffer);
	write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("affected_username", NO_REFERENCE_USERNAME, false, buffer);
	write_token_into_buffer("affected_user_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_description", phr_description, false, buffer);
	write_token_into_buffer("event_description", event_description_with_emergency_staff_indication, false, buffer);
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

static boolean notify_phr_owner_trusted_user_respond_access_request(char *phr_ownername, char *trusted_username, char *trusted_user_authority_name, 
	char *phr_description, char *emergency_staff_name, char *emergency_unit_name, boolean approval_flag, unsigned int no_approvals, unsigned int threshold_value)
{
	char phr_owner_email_addr[EMAIL_ADDRESS_LENGTH + 1];
	char payload_msg_list[10][EMAIL_MSG_LINE_LENGTH + 1];
	char payload_buffer[EMAIL_MSG_LINE_LENGTH + 1];
	char error_msg[ERR_MSG_LENGTH + 1];

	// Get the PHR owner's email address
	if(!get_phr_owner_email_address(phr_ownername, phr_owner_email_addr))
		goto ERROR;

	sprintf(payload_buffer, "To: %s(PHR owner)\n", phr_owner_email_addr);
	config_email_payload(0, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "From: %s(%s's emergency mailer)\n", GLOBAL_authority_email_address, GLOBAL_authority_name);
	config_email_payload(1, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Subject: Your trusted user responded on your restricted-level PHR access request\n");
	config_email_payload(2, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "\n");  // Empty line to divide headers from body, see RFC5322
	config_email_payload(3, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Emergency staff: %s.%s\n", emergency_unit_name, emergency_staff_name);
	config_email_payload(4, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Data description: %s\n", phr_description);
	config_email_payload(5, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Trusted user: %s.%s\n", trusted_user_authority_name, trusted_username);
	config_email_payload(6, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Action: %s the request\n", (approval_flag) ? "Approved" : "Rejected");
	config_email_payload(7, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "No. of approvals/Threshold value: %u/%u\n", no_approvals, threshold_value);
	config_email_payload(8, payload_buffer, payload_msg_list);

	sprintf(payload_buffer, "Request status: %s\n", (no_approvals >= threshold_value) ? "Approved" : "Pending");
	config_email_payload(9, payload_buffer, payload_msg_list);
	
	if(!send_email(1, phr_owner_email_addr, 10, *payload_msg_list, error_msg))
	{
		fprintf(stderr, "Sending notification to a PHR owner's email address failed (%s)\n", error_msg);
		goto ERROR;
	}
	
	return true;

ERROR:

	return false;
}

static boolean respond_approval_if_phr_owner_in_current_authority(SSL *ssl_client, char *trusted_username, char *trusted_user_authority_name, char *phr_ownername, 
	unsigned int remote_site_phr_id, char *phr_description, char *emergency_unit_name, char *emergency_staff_name)
{
	unsigned int trusted_user_id = 0;
	unsigned int phr_owner_id    = 0;
	unsigned int delegation_id   = 0;
	unsigned int phr_request_id  = 0;
	char         buffer[BUFFER_LENGTH + 1];

	MYSQL        *db_conn    = NULL;
	char         *file_data  = NULL;
	char         *file_chunk = NULL;
	char         *query      = NULL;

	unsigned int threshold_value;
	unsigned int no_approvals;

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Get the trusted user id
	if(!get_user_id(db_conn, trusted_username, trusted_user_authority_name, &trusted_user_id))  // Not found
	{
		// Send the restricted_level_phr_access_request_params_checking_result_flag
		write_token_into_buffer("restricted_level_phr_access_request_params_checking_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found the trusted user", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted_level_phr_access_request_params_checking_result_flag failed\n");
			goto ERROR;
		}

		goto ERROR;

	}

	// Get the PHR owner id
	if(!get_user_id(db_conn, phr_ownername, GLOBAL_authority_name, &phr_owner_id))  // Not found
	{
		// Send the restricted_level_phr_access_request_params_checking_result_flag
		write_token_into_buffer("restricted_level_phr_access_request_params_checking_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found the PHR owner", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted_level_phr_access_request_params_checking_result_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Check for the delegation between specific PHR owner and trusted user
	if(!get_delegation_id(db_conn, trusted_user_id, phr_owner_id, &delegation_id))  // Not found
	{
		// Send the restricted_level_phr_access_request_params_checking_result_flag
		write_token_into_buffer("restricted_level_phr_access_request_params_checking_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found the delegation", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted_level_phr_access_request_params_checking_result_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Check for the existence of the request on the specific restricted-level PHR of this emergency staff
	if(!get_access_request_id(db_conn, remote_site_phr_id, emergency_staff_name, emergency_unit_name, &phr_request_id))  // Not found
	{
		// Send the restricted_level_phr_access_request_params_checking_result_flag
		write_token_into_buffer("restricted_level_phr_access_request_params_checking_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found the request on the specific restricted-level PHR", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted_level_phr_access_request_params_checking_result_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Check for the existence of a deduction on the specific request of this emergency staff
	if(check_trusted_user_had_deduction_this_request(db_conn, trusted_user_id, phr_request_id))  // Found
	{
		// Send the restricted_level_phr_access_request_params_checking_result_flag
		write_token_into_buffer("restricted_level_phr_access_request_params_checking_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "You have taken a deduction on the request on the restricted-level PHR already", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted_level_phr_access_request_params_checking_result_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Send the restricted_level_phr_access_request_params_checking_result_flag
	write_token_into_buffer("restricted_level_phr_access_request_params_checking_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the restricted_level_phr_access_request_params_checking_result_flag failed\n");
		goto ERROR;
	}

	// Allocate heap variables
	file_data = (char *)malloc(sizeof(char)*1000*1024);
	if(!file_data)
	{
		int_error("Allocating memory for \"file_data\" failed");
	}

	file_chunk = (char *)malloc(sizeof(char)*((1000*1024)*2+1));
	if(!file_chunk)
	{
		int_error("Allocating memory for \"file_chunk\" failed");
	}

	query = (char *)malloc(sizeof(char)*(((1000*1024)*2+1)+(SQL_STATEMENT_LENGTH+1)+1));
	if(!query)
	{
		int_error("Allocating memory for \"query\" failed");
	}

	// Send the encrypted threshold secrey key
	if(!send_encrypted_thrshold_secret_key(db_conn, ssl_client, delegation_id, remote_site_phr_id, file_data))
		goto ERROR;

	// Receive the unencrypted threshold secret key
	if(!receive_unencrypted_threshold_secret_key(db_conn, ssl_client, trusted_user_id, phr_request_id, file_data, file_chunk, query))
		goto ERROR;
	
	// Free heap variables
	if(file_data)
	{
		free(file_data);
		file_data = NULL;
	}

	if(file_chunk)
	{
		free(file_chunk);
		file_chunk = NULL;
	}

	if(query)
	{
		free(query);
		query = NULL;
	}

	get_threshold_value(db_conn, remote_site_phr_id, &threshold_value);
	get_no_approvals(db_conn, phr_request_id, &no_approvals);

	// Record a transaction log only if the trusted user is in the same authority with the PHR owner
	if(strcmp(trusted_user_authority_name, GLOBAL_authority_name) == 0)
	{
		// Record a transaction log
		record_access_request_responding_transaction_log(ssl_client, trusted_username, GLOBAL_authority_name, phr_ownername, GLOBAL_authority_name, 
			phr_description, emergency_staff_name, emergency_unit_name, TRUSTED_USER_APPROVES_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_MSG);
	}

	// Send the notification to the PHR owner's e-mail address
	notify_phr_owner_trusted_user_respond_access_request(phr_ownername, trusted_username, trusted_user_authority_name, 
		phr_description, emergency_staff_name, emergency_unit_name, true, no_approvals, threshold_value);

	// If the approvals are more than or equal to the threshold value and the approval_notification_flag = 0, 
	// send notification to the emergency staff's email address and then set approval_notification_flag = 1
	if(no_approvals >= threshold_value && !is_approval_notification_flag_setted(db_conn, phr_request_id))
	{
		char emergency_staff_email_address[EMAIL_ADDRESS_LENGTH + 1];

		set_approval_notification_flag(db_conn, phr_request_id);
		get_emergency_staff_email_address(db_conn, phr_request_id, emergency_staff_email_address);			

		// Send notification to the emergency staff's email address
		notify_emergency_staff_request_approval(emergency_staff_email_address, phr_ownername, phr_description);
	}

	disconnect_db(&db_conn);
	db_conn = NULL;
	return true;

ERROR:

	if(db_conn)
	{
		disconnect_db(&db_conn);
		db_conn = NULL;
	}

	// Free heap variables
	if(file_data)
	{
		free(file_data);
		file_data = NULL;
	}

	if(file_chunk)
	{
		free(file_chunk);
		file_chunk = NULL;
	}

	if(query)
	{
		free(query);
		query = NULL;
	}

	return false;
}

// The another authority's Emergency Server service
static boolean connect_to_remote_restricted_level_phr_access_request_responding_service(char *authority_name, char *emergency_server_ip_addr, SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    emergency_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to Emergency Server of another authority
	sprintf(emergency_server_addr, "%s:%s", emergency_server_ip_addr, EMS_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_RESPONDING_REMOTE_EMS_PORT/*"7041"*/);  //****
	bio_conn = BIO_new_connect(emergency_server_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		fprintf(stderr, "Connecting to %s's emergency server failed\n", authority_name);
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

	hosts[0] = EMERGENCY_SERVER_CN;
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, true, authority_name)) != X509_V_OK)
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

static boolean respond_approval_if_phr_owner_in_another_authority(SSL *ssl_client, char *trusted_username, char *trusted_user_authority_name, char *phr_ownername, 
	char *phr_owner_authority_name, unsigned int remote_site_phr_id, char *phr_description, char *emergency_unit_name, char *emergency_staff_name)
{
	SSL          *ssl_conn = NULL;
	char         remote_emergency_server_ip_addr[IP_ADDRESS_LENGTH + 1];
	char         remote_site_phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];

	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         restricted_level_phr_access_request_params_checking_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      restricted_level_phr_access_request_params_checking_result_flag;

	unsigned int file_size;
	char         *file_data = NULL;

	// Get remote Emergency Server's IP address
	if(!get_remote_emergency_server_ip_addr(phr_owner_authority_name, remote_emergency_server_ip_addr))
	{
		// Send the restricted_level_phr_access_request_params_checking_result_flag
		write_token_into_buffer("restricted_level_phr_access_request_params_checking_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Getting the peer-authority emergency server's ip address failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted_level_phr_access_request_params_checking_result_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Connect to the another authority's Emergency Server
	if(!connect_to_remote_restricted_level_phr_access_request_responding_service(phr_owner_authority_name, remote_emergency_server_ip_addr, &ssl_conn))
	{
		// Send the restricted_level_phr_access_request_params_checking_result_flag
		write_token_into_buffer("restricted_level_phr_access_request_params_checking_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Connecting to peer-authority emergency server failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted_level_phr_access_request_params_checking_result_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	sprintf(remote_site_phr_id_str_tmp, "%u", remote_site_phr_id);

	// Send the restricted-level PHR access request responding information
	write_token_into_buffer("request", RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_TRUSTED_USER_APPROVAL, true, buffer);
	write_token_into_buffer("phr_ownername", phr_ownername, false, buffer);
	write_token_into_buffer("trusted_user_authority_name", trusted_user_authority_name, false, buffer);
	write_token_into_buffer("trusted_username", trusted_username, false, buffer);
	write_token_into_buffer("remote_site_phr_id", remote_site_phr_id_str_tmp, false, buffer);
	write_token_into_buffer("phr_description", phr_description, false, buffer);
	write_token_into_buffer("emergency_unit_name", emergency_unit_name, false, buffer);
	write_token_into_buffer("emergency_staff_name", emergency_staff_name, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the restricted-level PHR access request responding information failed\n");
		goto ERROR;
	}

	// Receive the restricted-level PHR access request responding result information
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the restricted-level PHR access request responding result information failed\n");
		goto ERROR;
	}

	// Get the restricted_level_phr_access_request_params_checking_result_flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, restricted_level_phr_access_request_params_checking_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "restricted_level_phr_access_request_params_checking_result_flag") != 0)
	{
		int_error("Extracting the restricted_level_phr_access_request_params_checking_result_flag failed");
	}

	restricted_level_phr_access_request_params_checking_result_flag = (strcmp(
	restricted_level_phr_access_request_params_checking_result_flag_str_tmp, "1") == 0) ? true : false;

	// Forward packet to the client
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the restricted-level PHR access request responding result information failed\n");
		goto ERROR;
	}

	// Error occurs at the remote server
	if(!restricted_level_phr_access_request_params_checking_result_flag)
		goto ERROR;

	// Allocate a heap variable
	file_data = (char *)malloc(sizeof(char)*1000*1024);
	if(!file_data)
	{
		int_error("Allocating memory for \"file_data\" failed");
	}

	// Receive the encrypted threshold secret key from the remote server
	if(SSL_recv_buffer(ssl_conn, file_data, &file_size) == 0)
	{
		fprintf(stderr, "Receiving the encrypted threshold secret key failed\n");
		goto ERROR;
	}

	// Send the encrypted threshold secrey key to the client
	if(!SSL_send_buffer(ssl_client, file_data, file_size))
	{
		fprintf(stderr, "Sending the encrypted threshold secret key failed\n");
		goto ERROR;
	}

	// Receive the unencrypted threshold secret key from the client
	if(SSL_recv_buffer(ssl_client, file_data, &file_size) == 0)
	{
		fprintf(stderr, "Receiving the unencrypted threshold secret key failed\n");
		goto ERROR;
	}

	// Send the unencrypted threshold secrey key to the remote server
	if(!SSL_send_buffer(ssl_conn, file_data, file_size))
	{
		fprintf(stderr, "Sending the unencrypted threshold secret key failed\n");
		goto ERROR;
	}

	// Free a heap variable
	if(file_data)
	{
		free(file_data);
		file_data = NULL;
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;

	// Record a transaction log
	record_access_request_responding_transaction_log(ssl_client, trusted_username, trusted_user_authority_name, phr_ownername, phr_owner_authority_name, phr_description, 
		emergency_staff_name, emergency_unit_name, TRUSTED_USER_APPROVES_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_MSG);

	return true;

ERROR:

	// Free a heap variable
	if(file_data)
	{
		free(file_data);
		file_data = NULL;
	}
	
	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;
}

// By the trusted user
static boolean respond_restricted_level_phr_access_request_approval_main(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         phr_ownername[USER_NAME_LENGTH + 1];
	char         phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];

	char         phr_description[DATA_DESCRIPTION_LENGTH + 1];

	char         remote_site_phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int remote_site_phr_id;

	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];
	char         emergency_staff_name[USER_NAME_LENGTH + 1];

	char         trusted_username[USER_NAME_LENGTH + 1];

	// Receive the restricted-level PHR access request approval information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the restricted-level PHR access request approval information failed\n");
		goto ERROR;
	}

	// Get the restricted-level PHR access request approval information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		int_error("Extracting the phr_ownername failed");

	if(read_token_from_buffer(buffer, 2, token_name, phr_owner_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_owner_authority_name") != 0)
		int_error("Extracting the phr_owner_authority_name failed");

	if(read_token_from_buffer(buffer, 3, token_name, remote_site_phr_id_str) != READ_TOKEN_SUCCESS || strcmp(token_name, "remote_site_phr_id") != 0)
		int_error("Extracting the remote_site_phr_id failed");

	remote_site_phr_id = atoi(remote_site_phr_id_str);

	if(read_token_from_buffer(buffer, 4, token_name, phr_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_description") != 0)
		int_error("Extracting the phr_description failed");

	if(read_token_from_buffer(buffer, 5, token_name, emergency_unit_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_unit_name") != 0)
		int_error("Extracting the emergency_unit_name failed");

	if(read_token_from_buffer(buffer, 6, token_name, emergency_staff_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_staff_name") != 0)
		int_error("Extracting the emergency_staff_name failed");

	// Get the trusted user's name
	get_cert_ownername(ssl_client, GLOBAL_authority_name, trusted_username, NULL);

	if(strcmp(phr_owner_authority_name, GLOBAL_authority_name) == 0)  // Current authority
	{
		return respond_approval_if_phr_owner_in_current_authority(ssl_client, trusted_username, GLOBAL_authority_name, phr_ownername, remote_site_phr_id, 
			phr_description, emergency_unit_name, emergency_staff_name);
	}
	else  // Another authority
	{
		return respond_approval_if_phr_owner_in_another_authority(ssl_client, trusted_username, GLOBAL_authority_name, phr_ownername, 
			phr_owner_authority_name, remote_site_phr_id, phr_description, emergency_unit_name, emergency_staff_name);
	}

ERROR:

	return false;
}

static boolean respond_restricted_level_phr_access_request_no_approval_main(SSL *ssl_client)
{
return true;
}

static boolean respond_restricted_level_phr_access_request_cancellation_main(SSL *ssl_client)
{
return true;
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

	if(strcmp(request, RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_TRUSTED_USER_APPROVAL) == 0)
	{
		return respond_restricted_level_phr_access_request_approval_main(ssl_client);
	}
	else if(strcmp(request, RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_TRUSTED_USER_NO_APPROVAL) == 0)
	{
		return respond_restricted_level_phr_access_request_no_approval_main(ssl_client);
	}
	else if(strcmp(request, RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_PHR_OWNER_CANCELLATION) == 0)
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

void *restricted_level_phr_access_request_responding_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(EMS_CERTFILE_PATH, EMS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(EMS_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_RESPONDING_PORT);
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
    		if((err = post_connection_check(ssl_client, hosts, 1, true, GLOBAL_authority_name)) != X509_V_OK)
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

static boolean process_request_by_remote_ems(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         request[REQUEST_TYPE_LENGTH + 1];
	char         phr_ownername[USER_NAME_LENGTH + 1];
	char         trusted_user_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         trusted_username[USER_NAME_LENGTH + 1];

	char         remote_site_phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int remote_site_phr_id;

	char         phr_description[DATA_DESCRIPTION_LENGTH + 1];
	char         emergency_unit_name[AUTHORITY_NAME_LENGTH + 1];
	char         emergency_staff_name[USER_NAME_LENGTH + 1];

	// Receive the restricted-level PHR access request responding information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the restricted-level PHR access request responding information failed\n");
		goto ERROR;
	}

	// Get the restricted-level PHR access request responding information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, request) != READ_TOKEN_SUCCESS || strcmp(token_name, "request") != 0)
		int_error("Extracting the request failed");

	if(read_token_from_buffer(buffer, 2, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		int_error("Extracting the phr_ownername failed");

	if(read_token_from_buffer(buffer, 3, token_name, trusted_user_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "trusted_user_authority_name") != 0)
		int_error("Extracting the trusted_user_authority_name failed");

	if(read_token_from_buffer(buffer, 4, token_name, trusted_username) != READ_TOKEN_SUCCESS || strcmp(token_name, "trusted_username") != 0)
		int_error("Extracting the trusted_username failed");

	if(read_token_from_buffer(buffer, 5, token_name, remote_site_phr_id_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "remote_site_phr_id") != 0)
		int_error("Extracting the remote_site_phr_id failed");

	remote_site_phr_id = atoi(remote_site_phr_id_str_tmp);

	if(read_token_from_buffer(buffer, 6, token_name, phr_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_description") != 0)
		int_error("Extracting the phr_description failed");

	if(read_token_from_buffer(buffer, 7, token_name, emergency_unit_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_unit_name") != 0)
		int_error("Extracting the emergency_unit_name failed");

	if(read_token_from_buffer(buffer, 8, token_name, emergency_staff_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_staff_name") != 0)
		int_error("Extracting the emergency_staff_name failed");

	if(strcmp(request, RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_TRUSTED_USER_APPROVAL) == 0)
	{
		return respond_approval_if_phr_owner_in_current_authority(ssl_client, trusted_username, trusted_user_authority_name, 
			phr_ownername, remote_site_phr_id, phr_description, emergency_unit_name, emergency_staff_name);
	}
	/*else if(strcmp(request, RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_TRUSTED_USER_NO_APPROVAL) == 0)
	{
		return respond_no_approval_if_phr_owner_in_current_authority(ssl_client, trusted_username, trusted_user_authority_name, 
			phr_ownername, remote_site_phr_id, phr_description, emergency_unit_name, emergency_staff_name);	
	}*/
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *restricted_level_phr_access_request_responding_remote_ems_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(EMS_CERTFILE_PATH, EMS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(EMS_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_RESPONDING_REMOTE_EMS_PORT);
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

		hosts[0] = EMERGENCY_SERVER_CN;
    		if((err = post_connection_check(ssl_client, hosts, 1, false, NULL)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Process request
		if(!process_request_by_remote_ems(ssl_client))
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




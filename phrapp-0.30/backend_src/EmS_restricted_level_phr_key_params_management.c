#include "EmS_common.h"

#define SGN_ACCESS_GRANTING_TICKET_PATH "EmS_cache/EmS_restricted_level_phr_key_params_management.sgn_access_granting_ticket"
#define ACCESS_GRANTING_TICKET_PATH     "EmS_cache/EmS_restricted_level_phr_key_params_management.access_granting_ticket"

// Local Function Prototypes
static void remove_restricted_level_phr_key_params(MYSQL *db_conn, unsigned int remote_site_phr_id);
static void insert_restricted_level_phr_row(MYSQL *db_conn, unsigned int remote_site_phr_id, unsigned int phr_owner_id, unsigned int threshold_value);
static boolean receive_emergency_key(SSL *ssl_client, MYSQL *db_conn, unsigned int remote_site_phr_id, char *file_data, char *file_chunk, char *query);
static boolean receive_recovery_emergency_key(SSL *ssl_client, MYSQL *db_conn, unsigned int remote_site_phr_id, char *file_data, char *file_chunk, char *query);
static boolean receive_threshold_msg(SSL *ssl_client, MYSQL *db_conn, unsigned int remote_site_phr_id, char *file_data, char *file_chunk, char *query);
static boolean receive_threshold_secret_keys(SSL *ssl_client, MYSQL *db_conn, unsigned int remote_site_phr_id, char *file_data, char *file_chunk, char *query);
static boolean get_delegation_id(MYSQL *db_conn, unsigned int phr_owner_id, unsigned int trusted_user_id, unsigned int *delegation_id_ret);
static boolean receive_restricted_level_phr_key_params_main(SSL *ssl_client);
static boolean verify_access_granting_ticket(char *access_granting_ticket_buffer, char *ticket_owner_name_cmp, char *ticket_owner_authority_name_cmp, 
	char *phr_owner_name_cmp, char *phr_owner_authority_name_cmp);

static boolean verify_access_granting_ticket_lifetime(char *access_granting_ticket_buffer);
static boolean verify_requestor_delete_permission(SSL *ssl_client, char *phr_owner_name, char *phr_owner_authority_name, char *requestor_name, char *requestor_authority_name);
static boolean has_delete_permission(char *access_granting_ticket_buffer);

// The another authority's Emergency Server service
static boolean connect_to_remote_restricted_level_phr_key_params_removal_service(char *authority_name, char *emergency_server_ip_addr, SSL **ssl_conn_ret);

static boolean remove_restricted_level_phr_key_params_at_remote_emergency_server(unsigned int remote_site_phr_id, char *authority_name);
static boolean remove_restricted_level_phr_key_params_main(SSL *ssl_client);
static boolean process_request(SSL *ssl_client);
static boolean remove_restricted_level_phr_key_params_invoked_by_another_authority_main(SSL *ssl_client);

// Implementation
static void remove_restricted_level_phr_key_params(MYSQL *db_conn, unsigned int remote_site_phr_id)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int phr_request_id;

	// Remove all restricted-level PHR key parameters that linked to the remote_site_phr_id
	sprintf(stat, "DELETE FROM %s WHERE remote_site_phr_id = %u", EMS__RESTRICTED_LEVEL_PHRS, remote_site_phr_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	sprintf(stat, "DELETE FROM %s WHERE remote_site_phr_id = %u", EMS__SECRET_KEYS, remote_site_phr_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	// Query for the phr_request_id regarding to the PHR if any
	sprintf(stat, "SELECT phr_request_id FROM %s WHERE remote_site_phr_id = %u", EMS__RESTRICTED_LEVEL_PHR_REQUESTS, remote_site_phr_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		phr_request_id = atoi(row[0]);

		// Remove all approvals on the PHR
		sprintf(stat, "DELETE FROM %s WHERE phr_request_id = %u", EMS__SECRET_KEY_APPROVALS, phr_request_id);
		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Remove all requests on the PHR
	sprintf(stat, "DELETE FROM %s WHERE remote_site_phr_id = %u", EMS__RESTRICTED_LEVEL_PHR_REQUESTS, remote_site_phr_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
}

static void insert_restricted_level_phr_row(MYSQL *db_conn, unsigned int remote_site_phr_id, unsigned int phr_owner_id, unsigned int threshold_value)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Insert a new restricted-level PHR row
	sprintf(stat, "INSERT INTO %s(remote_site_phr_id, phr_owner_id, threshold_value) VALUES(%u, %u, %u)", 
		EMS__RESTRICTED_LEVEL_PHRS, remote_site_phr_id, phr_owner_id, threshold_value);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}	
}

static boolean receive_emergency_key(SSL *ssl_client, MYSQL *db_conn, unsigned int remote_site_phr_id, char *file_data, char *file_chunk, char *query)
{
	unsigned int len, file_size;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	// Receive the encrypted emergency key
	if(SSL_recv_buffer(ssl_client, file_data, &file_size) == 0)
	{
		fprintf(stderr, "Receiving the emergency key failed\n");
		goto ERROR;
	}

	// Update the encrypted emergency key into the row which has the primary key associated with the remote_site_phr_id
	sprintf(stat, "UPDATE %s SET enc_emergency_key='%%s' WHERE remote_site_phr_id=%u", EMS__RESTRICTED_LEVEL_PHRS, remote_site_phr_id);

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

static boolean receive_recovery_emergency_key(SSL *ssl_client, MYSQL *db_conn, unsigned int remote_site_phr_id, char *file_data, char *file_chunk, char *query)
{
	unsigned int len, file_size;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	// Receive the encrypted recovery emergency key
	if(SSL_recv_buffer(ssl_client, file_data, &file_size) == 0)
	{
		fprintf(stderr, "Receiving the recovery emergency key failed\n");
		goto ERROR;
	}

	// Update the encrypted recovery emergency key into the row which has the primary key associated with the remote_site_phr_id
	sprintf(stat, "UPDATE %s SET enc_recovery_emergency_key='%%s' WHERE remote_site_phr_id=%u", EMS__RESTRICTED_LEVEL_PHRS, remote_site_phr_id);

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

static boolean receive_threshold_msg(SSL *ssl_client, MYSQL *db_conn, unsigned int remote_site_phr_id, char *file_data, char *file_chunk, char *query)
{
	unsigned int len, file_size;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	// Receive the encrypted threshold message
	if(SSL_recv_buffer(ssl_client, file_data, &file_size) == 0)
	{
		fprintf(stderr, "Receiving the threshold message failed\n");
		goto ERROR;
	}

	// Update the encrypted threshold message into the row which has the primary key associated with the remote_site_phr_id
	sprintf(stat, "UPDATE %s SET enc_threshold_msg='%%s' WHERE remote_site_phr_id=%u", EMS__RESTRICTED_LEVEL_PHRS, remote_site_phr_id);

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

static boolean get_delegation_id(MYSQL *db_conn, unsigned int phr_owner_id, unsigned int trusted_user_id, unsigned int *delegation_id_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char      err_msg[ERR_MSG_LENGTH + 1];

	// Query the delegation_id (ignore the rejection_by_trusted_user_flag variable)
	sprintf(stat, "SELECT delegation_id FROM %s WHERE phr_owner_id=%u AND trusted_user_id=%u", EMS__DELEGATIONS, phr_owner_id, trusted_user_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	// A delegation does not exist in database
	if(!row)
	{
		goto NOT_FOUND;
	}

	*delegation_id_ret = atoi(row[0]);
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

	*delegation_id_ret = 0;
	return false;
}

static boolean receive_threshold_secret_keys(SSL *ssl_client, MYSQL *db_conn, unsigned int remote_site_phr_id, char *file_data, char *file_chunk, char *query)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         phr_owner_name[USER_NAME_LENGTH + 1];
	unsigned int phr_owner_id;
	unsigned int delegation_id;

	char         is_end_of_threshold_secret_key_uploading_flag_str[FLAG_LENGTH + 1];
	boolean      is_end_of_threshold_secret_key_uploading_flag;

	char         trusted_username[USER_NAME_LENGTH + 1];
	char         trusted_user_authority_name[AUTHORITY_NAME_LENGTH + 1];
	unsigned int trusted_user_id;

	unsigned int len, file_size;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	// Get certificate owner's name
	get_cert_ownername(ssl_client, GLOBAL_authority_name, phr_owner_name, NULL);

	// Get the PHR owner id
	if(!get_user_id(db_conn, phr_owner_name, GLOBAL_authority_name, &phr_owner_id))
	{
		// Send the found_phr_owner_flag
		write_token_into_buffer("found_phr_owner_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found the PHR owner", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the found_phr_owner_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Send the found_phr_owner_flag
	write_token_into_buffer("found_phr_owner_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the found_phr_owner_flag failed\n");
		goto ERROR;
	}

	while(1)
	{
		// Receive the threshold secret key uploading information
		if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving the threshold secret key uploading information failed\n");
			goto ERROR;
		}

		// Get the threshold secret key uploading information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_threshold_secret_key_uploading_flag_str) != READ_TOKEN_SUCCESS 
			|| strcmp(token_name, "is_end_of_threshold_secret_key_uploading_flag") != 0)
		{
			int_error("Extracting the is_end_of_threshold_secret_key_uploading_flag failed");
		}

		is_end_of_threshold_secret_key_uploading_flag = atoi(is_end_of_threshold_secret_key_uploading_flag_str);
		if(is_end_of_threshold_secret_key_uploading_flag)
		{
			break;
		}

		if(read_token_from_buffer(buffer, 2, token_name, trusted_username) != READ_TOKEN_SUCCESS || strcmp(token_name, "trusted_username") != 0)
		{
			int_error("Extracting the trusted_username failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, trusted_user_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "trusted_user_authority_name") != 0)
		{
			int_error("Extracting the trusted_user_authority_name failed");
		}

		// Get the trusted user id
		if(!get_user_id(db_conn, trusted_username, trusted_user_authority_name, &trusted_user_id))
		{
			// Send the found_delegation_flag
			write_token_into_buffer("found_delegation_flag", "0", true, buffer);
			write_token_into_buffer("error_msg", "Do not found the emergency trusted user", false, buffer);

			if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
			{
				fprintf(stderr, "Sending the found_delegation_flag failed\n");
				goto ERROR;
			}

			goto ERROR;
		}

		// Get the delegation id
		if(!get_delegation_id(db_conn, phr_owner_id, trusted_user_id, &delegation_id))
		{
			// Send the found_delegation_flag
			write_token_into_buffer("found_delegation_flag", "0", true, buffer);
			write_token_into_buffer("error_msg", "Do not found the delegation", false, buffer);

			if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
			{
				fprintf(stderr, "Sending the found_delegation_flag failed\n");
				goto ERROR;
			}

			goto ERROR;
		}

		// Send the found_delegation_flag
		write_token_into_buffer("found_delegation_flag", "1", true, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the found_delegation_flag failed\n");
			goto ERROR;
		}

		// Receive the encrypted threshold secret key
		if(SSL_recv_buffer(ssl_client, file_data, &file_size) == 0)
		{
			fprintf(stderr, "Receiving the threshold secret key failed\n");
			goto ERROR;
		}

		// Insert a new secret key row
		sprintf(stat, "INSERT INTO %s(delegation_id, remote_site_phr_id, enc_secret_key) "
			"VALUES(%u, %u, '%%s')", EMS__SECRET_KEYS, delegation_id, remote_site_phr_id);

		// Take the escaped SQL string
		mysql_real_escape_string(db_conn, file_chunk, file_data, file_size);
	  	len = snprintf(query, sizeof(stat)+sizeof(char)*((1000*1024)*2+1), stat, file_chunk);

		if(mysql_real_query(db_conn, query, len))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}
	}

	return true;

ERROR:

	return false;
}

// Only the PHR owner can do this transaction
static boolean receive_restricted_level_phr_key_params_main(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         remote_site_phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int remote_site_phr_id;

	char         phr_ownername[USER_NAME_LENGTH + 1];
	unsigned int phr_owner_id;

	char         threshold_value_str[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int threshold_value;

	MYSQL        *db_conn    = NULL;
	char         *file_data  = NULL;
	char         *file_chunk = NULL;
	char         *query      = NULL;

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

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// We assume that the PHR owner is the same one with the uploader because only the PHR owner can do this transaction
	get_cert_ownername(ssl_client, GLOBAL_authority_name, phr_ownername, NULL);
	if(!get_user_id(db_conn, phr_ownername, GLOBAL_authority_name, &phr_owner_id))
	{
		int_error("Getting the user id failed");
	}

	// Receive the PHR requesting information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the PHR requesting information failed\n");
		goto ERROR;
	}

	// Get the PHR requesting information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, remote_site_phr_id_str) != READ_TOKEN_SUCCESS || strcmp(token_name, "remote_site_phr_id") != 0)
		int_error("Extracting the remote_site_phr_id failed");

	remote_site_phr_id = atoi(remote_site_phr_id_str);

	if(read_token_from_buffer(buffer, 2, token_name, threshold_value_str) != READ_TOKEN_SUCCESS || strcmp(token_name, "threshold_value") != 0)
		int_error("Extracting the threshold_value failed");

	threshold_value = atoi(threshold_value_str);

	// Insert a new restricted-level PHR row
	insert_restricted_level_phr_row(db_conn, remote_site_phr_id, phr_owner_id, threshold_value);

	// Receive the encrypted emergency key
	if(!receive_emergency_key(ssl_client, db_conn, remote_site_phr_id, file_data, file_chunk, query))
	{
		goto ERROR;
	}

	// Receive the encrypted recovery emergency key
	if(!receive_recovery_emergency_key(ssl_client, db_conn, remote_site_phr_id, file_data, file_chunk, query))
	{
		goto ERROR;
	}

	// Receive the encrypted threshold message
	if(!receive_threshold_msg(ssl_client, db_conn, remote_site_phr_id, file_data, file_chunk, query))
	{
		goto ERROR;
	}

	// Receive the encrypted threshold secret keys
	if(!receive_threshold_secret_keys(ssl_client, db_conn, remote_site_phr_id, file_data, file_chunk, query))
	{
		goto ERROR;
	}

	disconnect_db(&db_conn);

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

	return true;

ERROR:

	// If any error occurs then remove all restricted-level PHR key parameters that linked to the remote_site_phr_id
	remove_restricted_level_phr_key_params(db_conn, remote_site_phr_id);

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

static boolean verify_access_granting_ticket(char *access_granting_ticket_buffer, char *ticket_owner_name_cmp, char *ticket_owner_authority_name_cmp, 
	char *phr_owner_name_cmp, char *phr_owner_authority_name_cmp)
{
	char token_name[TOKEN_NAME_LENGTH + 1];
	char ticket_owner_name[USER_NAME_LENGTH + 1];
	char ticket_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char phr_owner_name[USER_NAME_LENGTH + 1];
	char phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];

	// Get the access granting ticket info tokens from buffer
	if(read_token_from_buffer(access_granting_ticket_buffer, 1, token_name, ticket_owner_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "ticket_owner_name") != 0)
	{
		int_error("Extracting the ticket_owner_name failed");
	}

	if(strcmp(ticket_owner_name, ticket_owner_name_cmp) != 0)
		return false;

	if(read_token_from_buffer(access_granting_ticket_buffer, 2, token_name, ticket_owner_authority_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "ticket_owner_authority_name") != 0)
	{
		int_error("Extracting the ticket_owner_authority_name failed");
	}

	if(strcmp(ticket_owner_authority_name, ticket_owner_authority_name_cmp) != 0)
		return false;

	if(read_token_from_buffer(access_granting_ticket_buffer, 3, token_name, phr_owner_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "phr_owner_name") != 0)
	{
		int_error("Extracting the phr_owner_name failed");
	}

	if(strcmp(phr_owner_name, phr_owner_name_cmp) != 0)
		return false;

	if(read_token_from_buffer(access_granting_ticket_buffer, 4, token_name, phr_owner_authority_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "phr_owner_authority_name") != 0)
	{
		int_error("Extracting the phr_owner_authority_name failed");
	}

	if(strcmp(phr_owner_authority_name, phr_owner_authority_name_cmp) != 0)
		return false;

	return true;
}

static boolean verify_access_granting_ticket_lifetime(char *access_granting_ticket_buffer)
{
	char      token_name[TOKEN_NAME_LENGTH + 1];
	char      expired_date_time_str[DATETIME_STR_LENGTH + 1];      // Format is "YYYY-MM-DD.HH:mm:ss"

	int       diff_time;   // In second unit
	time_t    now, expired_date_time;
	struct tm tm_expired_date_time;

	// Get the access granting ticket lifetime token from buffer
	if(read_token_from_buffer(access_granting_ticket_buffer, 8, token_name, expired_date_time_str) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "expired_date_time") != 0)
	{
		int_error("Extracting the expired_date_time failed");
	}

	// Construct ticket expired date and time from string format to time_t format
	memset(&tm_expired_date_time, 0, sizeof(struct tm));
	strptime(expired_date_time_str, "%Y-%m-%d.%X", &tm_expired_date_time); 
	expired_date_time = mktime(&tm_expired_date_time);

	// Get current date and time
	now = time(NULL);

	// Find different time
	diff_time = (int)difftime(expired_date_time, now);
	if(diff_time >= 0)
		return true;
	else
		return false;
}

static boolean has_delete_permission(char *access_granting_ticket_buffer)
{
	char token_name[TOKEN_NAME_LENGTH + 1];
	char delete_permission_flag_str[FLAG_LENGTH + 1];     // "0" or "1"
	
	// Get the delete permission flag token from buffer
	if(read_token_from_buffer(access_granting_ticket_buffer, 7, token_name, delete_permission_flag_str) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "delete_permission_flag") != 0)
	{
		int_error("Extracting the delete_permission_flag failed");
	}
	
	if(strcmp(delete_permission_flag_str, "1") == 0)
		return true;
	else
		return false;
}

static boolean verify_requestor_delete_permission(SSL *ssl_client, char *phr_owner_name, char *phr_owner_authority_name, char *requestor_name, char *requestor_authority_name)
{
	char buffer[BUFFER_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];
	char access_granting_ticket_buffer[BUFFER_LENGTH + 1];

	// Receive the access granting ticket
	if(!SSL_recv_file(ssl_client, SGN_ACCESS_GRANTING_TICKET_PATH))
	{
		fprintf(stderr, "Receiving an access granting ticket failed\n");
		goto ERROR;
	}

	// Verify the access granting ticket with the server CA's public key
	if(!smime_verify_with_cert(SGN_ACCESS_GRANTING_TICKET_PATH, ACCESS_GRANTING_TICKET_PATH, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH, err_msg))
	{
		// Send the PHR access permission verification result flag
		write_token_into_buffer("phr_access_permission_verification_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Verifying the access granting ticket signature failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the PHR access permission verification result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

	// Read the access granting ticket info into a buffer
	if(!read_bin_file(ACCESS_GRANTING_TICKET_PATH, access_granting_ticket_buffer, sizeof(access_granting_ticket_buffer), NULL))
	{
		fprintf(stderr, "Reading the access granting ticket info failed\n");
		goto ERROR;
	}

	unlink(ACCESS_GRANTING_TICKET_PATH);

	// Verifications
	if(!verify_access_granting_ticket(access_granting_ticket_buffer, requestor_name, requestor_authority_name, phr_owner_name, phr_owner_authority_name))
	{		
		// Send the PHR access permission verification result flag
		write_token_into_buffer("phr_access_permission_verification_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Verifying the access granting ticket failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the PHR access permission verification result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	if(!verify_access_granting_ticket_lifetime(access_granting_ticket_buffer))
	{		
		// Send the PHR access permission verification result flag
		write_token_into_buffer("phr_access_permission_verification_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Verifying the access granting ticket lifetime failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the PHR access permission verification result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}


	if(!has_delete_permission(access_granting_ticket_buffer))
	{
		// Send the PHR access permission verification result flag
		write_token_into_buffer("phr_access_permission_verification_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Verifying the access permission failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the PHR access permission verification result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Send the PHR access permission verification result flag
	write_token_into_buffer("phr_access_permission_verification_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the PHR access permission verification result flag failed\n");
		goto ERROR;
	}

	return true;

ERROR:

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);
	unlink(ACCESS_GRANTING_TICKET_PATH);
	return false;
}

// The another authority's Emergency Server service
static boolean connect_to_remote_restricted_level_phr_key_params_removal_service(char *authority_name, char *emergency_server_ip_addr, SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    emergency_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to Emergency Server of another authority
	sprintf(emergency_server_addr, "%s:%s", emergency_server_ip_addr, EMS_RESTRICTED_LEVEL_PHR_KEY_MANAGEMENT_REMOTE_EMS_PORT);
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

static boolean remove_restricted_level_phr_key_params_at_remote_emergency_server(unsigned int remote_site_phr_id, char *authority_name)
{
	SSL  *ssl_conn = NULL;
	char remote_emergency_server_ip_addr[IP_ADDRESS_LENGTH + 1];
	char remote_site_phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];
	char buffer[BUFFER_LENGTH + 1];

	// Get remote Emergency Server's IP address
	if(!get_remote_emergency_server_ip_addr(authority_name, remote_emergency_server_ip_addr))
	{
		goto ERROR;
	}

	// Connect to the another authority's Emergency Server
	if(!connect_to_remote_restricted_level_phr_key_params_removal_service(authority_name, remote_emergency_server_ip_addr, &ssl_conn))
	{
		goto ERROR;
	}
	
	// Send the remote site PHR id
	sprintf(remote_site_phr_id_str, "%u", remote_site_phr_id);
	write_token_into_buffer("remote_site_phr_id", remote_site_phr_id_str, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the remote site PHR id failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	return true;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;
}

// Every authorized users can do this transaction
static boolean remove_restricted_level_phr_key_params_main(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         phr_owner_name[USER_NAME_LENGTH + 1];
	char         phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];

	char         requestor_name[USER_NAME_LENGTH + 1];
	char         requestor_authority_name[AUTHORITY_NAME_LENGTH + 1];

	char         remote_site_phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int remote_site_phr_id;

	// Receive the restricted-level PHR key parameters
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the restricted-level PHR key parameters failed\n");
		goto ERROR;
	}

	// Get the restricted-level PHR key parameter tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_owner_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_owner_name") != 0)
		int_error("Extracting the phr_owner_name failed");

	if(read_token_from_buffer(buffer, 2, token_name, phr_owner_authority_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "phr_owner_authority_name") != 0)
	{
		int_error("Extracting the phr_owner_authority_name failed");
	}

	if(read_token_from_buffer(buffer, 3, token_name, remote_site_phr_id_str) != READ_TOKEN_SUCCESS || strcmp(token_name, "remote_site_phr_id") != 0)
		int_error("Extracting the remote_site_phr_id failed");

	remote_site_phr_id = atoi(remote_site_phr_id_str);

	// Get requestor's name and authority name
	get_cert_owner_info(ssl_client, requestor_authority_name, requestor_name);

	// Verify the requestor's delete permission on the PHR owner's PHRs
	if(!verify_requestor_delete_permission(ssl_client, phr_owner_name, phr_owner_authority_name, requestor_name, requestor_authority_name))
	{
		goto ERROR;
	}

	if(strcmp(phr_owner_authority_name, GLOBAL_authority_name) == 0)  // Current authority
	{
		MYSQL *db_conn = NULL;

		// Connect the database
		connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

		// Remove all restricted-level PHR key parameters that linked to the remote_site_phr_id
		remove_restricted_level_phr_key_params(db_conn, remote_site_phr_id);

		disconnect_db(&db_conn);
	}
	else  // Another authority
	{
		// Connect to the PHR owner authority's Emergency Server to remove all restricted-level PHR key parameters that linked to the remote_site_phr_id
		if(!remove_restricted_level_phr_key_params_at_remote_emergency_server(remote_site_phr_id, phr_owner_authority_name))
		{
			goto ERROR;
		}
	}

	return true;

ERROR:

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

	if(strcmp(request, RESTRICTED_LEVEL_PHR_KEY_PARAMS_UPLOADING) == 0)          // Only the PHR owner can do this transaction
	{
		return receive_restricted_level_phr_key_params_main(ssl_client);
	}
	else if(strcmp(request, RESTRICTED_LEVEL_PHR_KEY_PARAMS_REMOVAL) == 0)       // Every authorized users can do this transaction
	{
		return remove_restricted_level_phr_key_params_main(ssl_client);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *restricted_level_phr_key_params_management_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(EMS_CERTFILE_PATH, EMS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(EMS_RESTRICTED_LEVEL_PHR_KEY_MANAGEMENT_PORT);
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

static boolean remove_restricted_level_phr_key_params_invoked_by_another_authority_main(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         remote_site_phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int remote_site_phr_id;

	MYSQL        *db_conn = NULL;

	// Receive the remote site PHR id
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the remote site PHR id failed\n");
		goto ERROR;
	}

	// Get the remote site PHR id token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, remote_site_phr_id_str) != READ_TOKEN_SUCCESS || strcmp(token_name, "remote_site_phr_id") != 0)
		int_error("Extracting the remote_site_phr_id failed");

	remote_site_phr_id = atoi(remote_site_phr_id_str);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Remove all restricted-level PHR key parameters that linked to the remote_site_phr_id
	remove_restricted_level_phr_key_params(db_conn, remote_site_phr_id);

	disconnect_db(&db_conn);
	return true;

ERROR:

	if(db_conn)
	{
		disconnect_db(&db_conn);
		db_conn = NULL;
	}

	return false;
}

void *restricted_level_phr_key_params_management_remote_ems_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(EMS_CERTFILE_PATH, EMS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(EMS_RESTRICTED_LEVEL_PHR_KEY_MANAGEMENT_REMOTE_EMS_PORT);
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

		// Remove all restricted-level PHR key parameters invoked by an another authority's Emergency Server
		if(!remove_restricted_level_phr_key_params_invoked_by_another_authority_main(ssl_client))
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




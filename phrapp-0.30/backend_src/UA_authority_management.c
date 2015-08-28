#include "UA_common.h"

// Local Function Prototypes
static boolean record_transaction_log_on_authority(SSL *ssl_client, char *authority_name, char *event_description);
static boolean register_authority(SSL *ssl_client);
static boolean edit_authority_ip_address(SSL *ssl_client);
static void remove_access_permission_assigned_by_revoked_phr_owner(MYSQL *db_conn, unsigned int phr_owner_id, unsigned int phr_owner_authority_id);
static boolean record_transaction_log_on_access_permission_granted_user_was_removed_by_current_authority(SSL *ssl_client, char *revoked_username, 
	char *revoked_user_authority_name, char *phr_owner_name);

static boolean record_transaction_log_on_access_permission_granted_user_was_removed_by_another_authority(SSL *ssl_client, 
	char *revoked_username, char *revoked_user_authority_name, char *phr_owner_name);

static void remove_access_permission_assigned_to_revoked_object_user(SSL *ssl_client, MYSQL *db_conn, unsigned int object_user_id, char *object_owner_name, 
	unsigned int object_user_authority_id, char *object_user_authorirty_name, boolean authority_revoked_by_its_admin);

static boolean remove_authority(SSL *ssl_client);
static boolean process_request(SSL *ssl_client);

// Implementation
static boolean record_transaction_log_on_authority(SSL *ssl_client, char *authority_name, char *event_description)
{
	SSL  *ssl_conn_AS = NULL;
	char buffer[BUFFER_LENGTH + 1];
	char username[USER_NAME_LENGTH + 1];
	char current_date_time[DATETIME_STR_LENGTH  + 1];
	char client_ip_address[IP_ADDRESS_LENGTH + 1];
	char object_description[DATA_DESCRIPTION_LENGTH + 1];

	// Get certificate owner's name, current date/time and client's IP address
	get_cert_ownername(ssl_client, GLOBAL_authority_name, username, NULL);
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_client, client_ip_address, NULL);

	sprintf(object_description, "Authority: %s", authority_name);

	// Connect to Audit Server
	if(!connect_to_transaction_log_recording_service(&ssl_conn_AS))
		goto ERROR;

	// Send a request type
	write_token_into_buffer("request_type", EVENT_LOG_RECORDING, true, buffer);
	if(!SSL_send_buffer(ssl_conn_AS, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a request type failed\n");
		goto ERROR;
	}

	// Send a transaction log on authority
	write_token_into_buffer("actor_name", username, true, buffer);
	write_token_into_buffer("actor_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", "1", false, buffer);
	write_token_into_buffer("object_owner_name", NO_REFERENCE_USERNAME, false, buffer);
	write_token_into_buffer("object_owner_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("affected_username", NO_REFERENCE_USERNAME, false, buffer);
	write_token_into_buffer("affected_user_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_description", object_description, false, buffer);
	write_token_into_buffer("event_description", event_description, false, buffer);
	write_token_into_buffer("date_time", current_date_time, false, buffer);
	write_token_into_buffer("actor_ip_address", client_ip_address, false, buffer);

	if(!SSL_send_buffer(ssl_conn_AS, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a transaction log on authority failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_conn_AS);
	ssl_conn_AS = NULL;
	return true;

ERROR:

	if(ssl_conn_AS)
	{
		SSL_cleanup(ssl_conn_AS);
		ssl_conn_AS = NULL;
	}

	return false;
}

static boolean register_authority(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         ip_address[IP_ADDRESS_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	boolean      authority_found = false;
	unsigned int authority_id;

	// Receive authority registration information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving authority registration information failed\n");
		goto ERROR;
	}

	// Get authority registration information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "authority_name") != 0)
		int_error("Extracting the authority_name failed");

	if(read_token_from_buffer(buffer, 2, token_name, ip_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "ip_address") != 0)
		int_error("Extracting the ip_address failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of authority name
	sprintf(stat, "SELECT authority_id FROM %s WHERE authority_name LIKE '%s' COLLATE latin1_general_cs", UA__AUTHORITIES, authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The authority name exists
	if(row)
	{
		authority_found = true;
		authority_id    = atoi(row[0]);
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(authority_found && authority_id == GLOBAL_authority_id)
	{
		// Send the authority registration result flag
		write_token_into_buffer("authority_registration_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "You already sit on this authority", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the authority registration result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}
	else if(authority_found)
	{
		// Send the authority registration result flag
		write_token_into_buffer("authority_registration_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Authority name exists already", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the authority registration result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Insert a new authority
	sprintf(stat, "INSERT INTO %s(authority_name, user_auth_ip_addr, authority_join_flag) VALUES('%s', '%s', '0')", UA__AUTHORITIES, authority_name, ip_address);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
	
	disconnect_db(&db_conn);

	// Send the authority registration result flag
	write_token_into_buffer("authority_registration_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the authority registration result flag failed\n");
		goto ERROR;
	}

	// Record a transaction log
	record_transaction_log_on_authority(ssl_client, authority_name, AUTHORITY_REGISTRATION_MSG);
	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
	return false;
}

static boolean edit_authority_ip_address(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         ip_address[IP_ADDRESS_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];	

	unsigned int authority_id;

	// Receive authority ip address editing information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving authority ip address editing information failed\n");
		goto ERROR;
	}

	// Get authority ip address editing information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "authority_name") != 0)
		int_error("Extracting the authority_name failed");

	if(read_token_from_buffer(buffer, 2, token_name, ip_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "ip_address") != 0)
		int_error("Extracting the ip_address failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of authority name
	sprintf(stat, "SELECT authority_id FROM %s WHERE authority_name LIKE '%s' COLLATE latin1_general_cs", UA__AUTHORITIES, authority_name);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The authority does not exist
	if(!row)
	{
		// Send the authority ip address editing result flag
		write_token_into_buffer("authority_ip_address_editing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Authority does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the authority ip address editing result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	authority_id = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Update authority's IP address
	sprintf(stat, "UPDATE %s SET user_auth_ip_addr = '%s' WHERE authority_id = %u", UA__AUTHORITIES, ip_address, authority_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      	int_error(err_msg);
	}

	disconnect_db(&db_conn);

	// Send the authority ip address editing result flag
	write_token_into_buffer("authority_ip_address_editing_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the authority ip address editing result flag failed\n");
		goto ERROR;
	}

	// Record a transaction log
	record_transaction_log_on_authority(ssl_client, authority_name, AUTHORITY_IP_ADDRESS_EDITING_MSG);
	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
	return false;
}

void remove_attribute_list_of_authority(MYSQL *db_conn, unsigned int authority_id)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Delete the authority's attribute list
	sprintf(stat, "DELETE FROM %s WHERE authority_id = %u", UA__ATTRIBUTES, authority_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
}

static void remove_access_permission_assigned_by_revoked_phr_owner(MYSQL *db_conn, unsigned int phr_owner_id, unsigned int phr_owner_authority_id)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Delete the access permission assigned by the PHR owner
	sprintf(stat, "DELETE FROM %s WHERE phr_owner_id = %u AND phr_owner_authority_id = %u", UA__ACCESS_PERMISSIONS, phr_owner_id, phr_owner_authority_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
}

static boolean record_transaction_log_on_access_permission_granted_user_was_removed_by_current_authority(
	SSL *ssl_client, char *revoked_username, char *revoked_user_authority_name, char *phr_owner_name)
{
	SSL  *ssl_conn_AS = NULL;
	char buffer[BUFFER_LENGTH + 1];
	char current_date_time[DATETIME_STR_LENGTH  + 1];
	char peer_ip_address[IP_ADDRESS_LENGTH + 1];

	// Get current date/time and peer's IP address
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_client, peer_ip_address, NULL);

	// Connect to Audit Server
	if(!connect_to_transaction_log_recording_service(&ssl_conn_AS))
		goto ERROR;

	// Send a request type
	write_token_into_buffer("request_type", EVENT_LOG_RECORDING, true, buffer);
	if(!SSL_send_buffer(ssl_conn_AS, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a request type failed\n");
		goto ERROR;
	}

	// Send a transaction log
	write_token_into_buffer("actor_name", ITS_ADMIN_NAME, true, buffer);
	write_token_into_buffer("actor_authority_name", revoked_user_authority_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", "1", false, buffer);
	write_token_into_buffer("object_owner_name", revoked_username, false, buffer);
	write_token_into_buffer("object_owner_authority_name", revoked_user_authority_name, false, buffer);
	write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("affected_username", phr_owner_name, false, buffer);
	write_token_into_buffer("affected_user_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_description", NO_SPECIFIC_DATA, false, buffer);
	write_token_into_buffer("event_description", ACCESS_PERMISSION_GRANTED_USER_WAS_REMOVED, false, buffer);
	write_token_into_buffer("date_time", current_date_time, false, buffer);
	write_token_into_buffer("actor_ip_address", peer_ip_address, false, buffer);

	if(!SSL_send_buffer(ssl_conn_AS, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a transaction log failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_conn_AS);
	ssl_conn_AS = NULL;
	return true;

ERROR:

	if(ssl_conn_AS)
	{
		SSL_cleanup(ssl_conn_AS);
		ssl_conn_AS = NULL;
	}

	return false;
}

static boolean record_transaction_log_on_access_permission_granted_user_was_removed_by_another_authority(
	SSL *ssl_client, char *revoked_username, char *revoked_user_authority_name, char *phr_owner_name)
{
	SSL  *ssl_conn_AS = NULL;
	char buffer[BUFFER_LENGTH + 1];
	char actor_name[USER_NAME_LENGTH + 1];
	char current_date_time[DATETIME_STR_LENGTH  + 1];
	char client_ip_address[IP_ADDRESS_LENGTH + 1];

	// Get certificate owner's name, current date/time and client's IP address
	get_cert_ownername(ssl_client, GLOBAL_authority_name, actor_name, NULL);
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_client, client_ip_address, NULL);

	// Connect to Audit Server
	if(!connect_to_transaction_log_recording_service(&ssl_conn_AS))
		goto ERROR;

	// Send a request type
	write_token_into_buffer("request_type", EVENT_LOG_RECORDING, true, buffer);
	if(!SSL_send_buffer(ssl_conn_AS, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a request type failed\n");
		goto ERROR;
	}

	// Send transaction assigned access permission user removal log information
	write_token_into_buffer("actor_name", actor_name, true, buffer);
	write_token_into_buffer("actor_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", "1", false, buffer);
	write_token_into_buffer("object_owner_name", revoked_username, false, buffer);
	write_token_into_buffer("object_owner_authority_name", revoked_user_authority_name, false, buffer);
	write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("affected_username", phr_owner_name, false, buffer);
	write_token_into_buffer("affected_user_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_description", NO_SPECIFIC_DATA, false, buffer);
	write_token_into_buffer("event_description", ACCESS_PERMISSION_GRANTED_USER_WAS_REMOVED, false, buffer);
	write_token_into_buffer("date_time", current_date_time, false, buffer);
	write_token_into_buffer("actor_ip_address", client_ip_address, false, buffer);

	if(!SSL_send_buffer(ssl_conn_AS, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a transaction log failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_conn_AS);
	ssl_conn_AS = NULL;
	return true;

ERROR:

	if(ssl_conn_AS)
	{
		SSL_cleanup(ssl_conn_AS);
		ssl_conn_AS = NULL;
	}

	return false;
}

static void remove_access_permission_assigned_to_revoked_object_user(SSL *ssl_client, MYSQL *db_conn, unsigned int object_user_id, char *object_owner_name, 
	unsigned int object_user_authority_id, char *object_user_authorirty_name, boolean authority_revoked_by_its_admin)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int assigned_permission_id;
	char         phr_owner_name[USER_NAME_LENGTH + 1];

	// Query for user list that assigned access permissions to the revoked object user
	sprintf(stat, "SELECT PAO.assigned_permission_id, USR.username FROM %s PAO, %s USR WHERE PAO.object_user_id = '%u' AND PAO.object_user_authority_id = '%u' AND "
		"PAO.user_id = USR.user_id", UA__PERMISSIONS_ASSIGNED_TO_OTHERS, UA__USERS, object_user_id, object_user_authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		assigned_permission_id = atoi(row[0]);
		strcpy(phr_owner_name, row[1]);

		// Delete assigned access permissions of each PHR owner
		sprintf(stat, "DELETE FROM %s WHERE assigned_permission_id = %u", UA__PERMISSIONS_ASSIGNED_TO_OTHERS, assigned_permission_id);
		if(mysql_query(db_conn, stat))
		{
			sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		      	int_error(err_msg);
		}

		// Record a transaction log
		if(authority_revoked_by_its_admin)  // Remove by another authority's admin
		{
			record_transaction_log_on_access_permission_granted_user_was_removed_by_current_authority(
				ssl_client, object_owner_name, object_user_authorirty_name, phr_owner_name);
		}
		else  // Remove by current authority's admin
		{
			record_transaction_log_on_access_permission_granted_user_was_removed_by_another_authority(
				ssl_client, object_owner_name, object_user_authorirty_name, phr_owner_name);
		}
	}
	
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

void remove_user_list_of_authority(SSL *ssl_client, MYSQL *db_conn, unsigned int authority_id, char *authority_name, boolean authority_revoked_by_its_admin)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_id;
	char         username[USER_NAME_LENGTH + 1];

	// Query for user list of desired authority
	sprintf(stat, "SELECT user_id, username FROM %s WHERE authority_id = %u", UA__USERS_IN_OTHER_AUTHORITIES, authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		user_id = atoi(row[0]);
		strcpy(username, row[1]);

		remove_access_permission_assigned_by_revoked_phr_owner(db_conn, user_id, authority_id);
		remove_access_permission_assigned_to_revoked_object_user(ssl_client, db_conn, user_id, username, authority_id, authority_name, authority_revoked_by_its_admin);
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Delete the user list of desired authority
	sprintf(stat, "DELETE FROM %s WHERE authority_id = %u", UA__USERS_IN_OTHER_AUTHORITIES, authority_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
}

static boolean remove_authority(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         authority_name[AUTHORITY_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int authority_id;

	// Receive authority removal information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving authority removal information failed\n");
		goto ERROR;
	}

	// Get an authority removal information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "authority_name") != 0)
		int_error("Extracting the authority_name failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of authority name
	sprintf(stat, "SELECT authority_id FROM %s WHERE authority_name LIKE '%s' COLLATE latin1_general_cs", UA__AUTHORITIES, authority_name);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The authority does not exist
	if(!row)
	{
		// Send the authority removal result flag
		write_token_into_buffer("authority_removal_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Authority does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the authority removal result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	authority_id = atoi(row[0]);
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(authority_id == GLOBAL_authority_id)
	{
		// Send the authority removal result flag
		write_token_into_buffer("authority_removal_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "You can't remove the authority that you belong to", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the authority removal result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Lock the synchronization
	if(sem_wait(&sync_lock_mutex) != 0)
		int_error("Locking the mutex failed");

	remove_attribute_list_of_authority(db_conn, authority_id);

	// Delete both the user list and the access permissions regarding to revoked authority
	remove_user_list_of_authority(ssl_client, db_conn, authority_id, authority_name, false);

	// Delete the authority
	sprintf(stat, "DELETE FROM %s WHERE authority_id = %u", UA__AUTHORITIES, authority_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}

	// Unlock the synchronization
	if(sem_post(&sync_lock_mutex) != 0)
		int_error("Unlocking the mutex failed");

	disconnect_db(&db_conn);

	// Send the authority removal result flag
	write_token_into_buffer("authority_removal_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the authority removal result flag failed\n");
		goto ERROR;
	}

	// Record a transaction log
	record_transaction_log_on_authority(ssl_client, authority_name, AUTHORITY_REMOVAL_MSG);
	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
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

	if(strcmp(request, AUTHORITY_REGISTRATION) == 0)
	{
		return register_authority(ssl_client);
	}
	else if(strcmp(request, AUTHORITY_IP_ADDRESS_EDITING) == 0)
	{
		return edit_authority_ip_address(ssl_client);
	}
	else if(strcmp(request, AUTHORITY_REMOVAL) == 0)
	{
		return remove_authority(ssl_client);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *authority_management_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(UA_AUTHORITY_MANAGEMENT_PORT);
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

		hosts[0] = ADMIN_CN; 
    		if((err = post_connection_check(ssl_client, hosts, 1, true, GLOBAL_authority_name)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Process a request
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




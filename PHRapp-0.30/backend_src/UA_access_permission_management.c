#include "UA_common.h"

// Local Function Prototypes
static boolean record_transaction_log(SSL *ssl_client, char *desired_username, char *desired_user_authority_name, char *object_description, char *event_description);

// "assigned_permission_id_ret" can be NULL if we just need to testify the existence of permission
static boolean does_desired_user_access_permission_exists(MYSQL *db_conn, unsigned int phr_owner_id, unsigned int desired_user_id, 
	unsigned int desired_user_authority_id, unsigned int *assigned_permission_id_ret);

static boolean get_phr_owner_id(MYSQL *db_conn, char *phr_owner_name, unsigned int *phr_owner_id_ret);
static boolean does_desired_user_exists(MYSQL *db_conn, char *desired_username, char *desired_user_authority_name, 
	unsigned int *desired_user_id_ret, unsigned int *desired_user_authority_id_ret);

static boolean assign_access_permission(SSL *ssl_client, char *desired_user_authority_name, char *desired_username, 
	boolean upload_permission_flag, boolean download_permission_flag, boolean delete_permission_flag);

static boolean edit_access_permission(SSL *ssl_client, char *desired_user_authority_name, char *desired_username, 
	boolean upload_permission_flag, boolean download_permission_flag, boolean delete_permission_flag);

static boolean remove_access_permission(SSL *ssl_client, char *desired_user_authority_name, char *desired_username);
static boolean process_request(SSL *ssl_client);

// Implementation
static boolean record_transaction_log(SSL *ssl_client, char *desired_username, char *desired_user_authority_name, char *object_description, char *event_description)
{
	SSL  *ssl_conn_AS = NULL;
	char buffer[BUFFER_LENGTH + 1];
	char phr_owner_name[USER_NAME_LENGTH + 1];
	char current_date_time[DATETIME_STR_LENGTH  + 1];
	char client_ip_address[IP_ADDRESS_LENGTH + 1];

	// Get certificate owner's name, current date/time and client's IP address
	get_cert_ownername(ssl_client, GLOBAL_authority_name, phr_owner_name, NULL);
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

	// Send a transaction log
	write_token_into_buffer("actor_name", phr_owner_name, true, buffer);
	write_token_into_buffer("actor_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_owner_name", desired_username, false, buffer);
	write_token_into_buffer("object_owner_authority_name", desired_user_authority_name, false, buffer);
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
		fprintf(stderr, "Sending a transaction (access permission) log failed\n");
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

// "assigned_permission_id_ret" can be NULL if we just only need to testify the existence of permission
static boolean does_desired_user_access_permission_exists(MYSQL *db_conn, unsigned int phr_owner_id, unsigned int desired_user_id, 
	unsigned int desired_user_authority_id, unsigned int *assigned_permission_id_ret)
{
  	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Check for the existence of access permission for this desired user
	sprintf(stat, "SELECT assigned_permission_id FROM %s WHERE user_id = %u AND object_user_id = %u AND object_user_authority_id = %u", 
		UA__PERMISSIONS_ASSIGNED_TO_OTHERS, phr_owner_id, desired_user_id, desired_user_authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	if(!row)
	{
		goto ERROR;
	}

	if(assigned_permission_id_ret != NULL)
	{
		*assigned_permission_id_ret = atoi(row[0]);
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
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

static boolean get_phr_owner_id(MYSQL *db_conn, char *phr_owner_name, unsigned int *phr_owner_id_ret)
{
  	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Query for the PHR owner id
	sprintf(stat, "SELECT user_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, phr_owner_name);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
	
	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	if(!row)
	{
		goto ERROR;		
	}

	*phr_owner_id_ret = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
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

static boolean does_desired_user_exists(MYSQL *db_conn, char *desired_username, char *desired_user_authority_name, 
	unsigned int *desired_user_id_ret, unsigned int *desired_user_authority_id_ret)
{
  	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Check for the existence of the desired user
	if(strcmp(desired_user_authority_name, GLOBAL_authority_name) == 0)
	{
		sprintf(stat, "SELECT user_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, desired_username);
	}
	else
	{
		sprintf(stat, "SELECT UOA.user_id, UOA.authority_id FROM %s UOA, %s AUT WHERE UOA.authority_id = AUT.authority_id AND "
			"AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND UOA.username LIKE '%s' COLLATE latin1_general_cs", 
			UA__USERS_IN_OTHER_AUTHORITIES, UA__AUTHORITIES, desired_user_authority_name, desired_username);
	}

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		goto ERROR;
	}

	*desired_user_id_ret           = atoi(row[0]);
	*desired_user_authority_id_ret = (strcmp(desired_user_authority_name, GLOBAL_authority_name) == 0) ? GLOBAL_authority_id : atoi(row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
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

static boolean assign_access_permission(SSL *ssl_client, char *desired_user_authority_name, char *desired_username, 
	boolean upload_permission_flag, boolean download_permission_flag, boolean delete_permission_flag)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         phr_owner_name[USER_NAME_LENGTH + 1];
	unsigned int phr_owner_id;
	unsigned int desired_user_authority_id;
	unsigned int desired_user_id;
	unsigned int assigned_permission_id;	

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	char         object_description[DATA_DESCRIPTION_LENGTH + 1];

	// Get certificate owner's name
	get_cert_ownername(ssl_client, GLOBAL_authority_name, phr_owner_name, NULL);

	// The desired user must not be the same one with the PHR owner
	if(strcmp(desired_user_authority_name, GLOBAL_authority_name) == 0 && strcmp(desired_username, phr_owner_name) == 0)
	{
		// Send the access permission assignment result flag
		write_token_into_buffer("access_permission_assignment_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "You have access permissions to your own data already", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the access permission assignment result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of the desired user
	if(!does_desired_user_exists(db_conn, desired_username, desired_user_authority_name, &desired_user_id, &desired_user_authority_id))
	{
		// Send the access permission assignment result flag
		write_token_into_buffer("access_permission_assignment_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found the user that you're looking for", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the access permission assignment result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Query for the PHR owner id
	if(!get_phr_owner_id(db_conn, phr_owner_name, &phr_owner_id))
	{
		// Send the access permission assignment result flag
		write_token_into_buffer("access_permission_assignment_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Getting the PHR owner id from a database failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the access permission assignment result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Check for the existence of access permission for this desired user
	if(does_desired_user_access_permission_exists(db_conn, phr_owner_id, desired_user_id, desired_user_authority_id, &assigned_permission_id))
	{
		// Send the access permission assignment result flag
		write_token_into_buffer("access_permission_assignment_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "You have assigned the permission to this user already", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the access permission assignment result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Insert the access permission for this desired user (permissions_assigned_to_others)
	sprintf(stat, "INSERT INTO %s(user_id, object_user_id, object_user_authority_id, upload_permission_flag, download_permission_flag, "
		"delete_permission_flag) VALUES(%u, %u, %u, '%s', '%s', '%s')", UA__PERMISSIONS_ASSIGNED_TO_OTHERS, phr_owner_id, desired_user_id, 
		desired_user_authority_id, (upload_permission_flag) ? "1" : "0", (download_permission_flag) ? "1" : "0", (delete_permission_flag) ? "1" : "0");

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	// If the desired user is in the same authority with the PHR owner then insert desired user's 
	// access permission in an access_permissions table, unless wait for synchronization mechanism
	if(desired_user_authority_id == GLOBAL_authority_id)
	{
		// Insert the access permission for this desired user (access_permissions)
		sprintf(stat, "INSERT INTO %s(user_id, phr_owner_id, phr_owner_authority_id, upload_permission_flag, download_permission_flag, "
			"delete_permission_flag) VALUES(%u, %u, %u, '%s', '%s', '%s')", UA__ACCESS_PERMISSIONS, desired_user_id, phr_owner_id, 
			GLOBAL_authority_id, (upload_permission_flag) ? "1" : "0", (download_permission_flag) ? "1" : "0", (delete_permission_flag) ? "1" : "0");

		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}	
	}
	
	disconnect_db(&db_conn);

	// Send the access permission assignment result flag
	write_token_into_buffer("access_permission_assignment_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the access permission assignment result flag failed\n");
		goto ERROR;
	}

	// Record a transaction log
	sprintf(object_description, "Access permission: <upload: %s><download: %s><delete: %s>", (upload_permission_flag) ? "true" : "false", 
		(download_permission_flag) ? "true" : "false", (delete_permission_flag) ? "true" : "false");

	record_transaction_log(ssl_client, desired_username, desired_user_authority_name, object_description, ACCESS_PERMISSION_ASSIGNMENT_MSG);
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

static boolean edit_access_permission(SSL *ssl_client, char *desired_user_authority_name, char *desired_username, 
	boolean upload_permission_flag, boolean download_permission_flag, boolean delete_permission_flag)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         phr_owner_name[USER_NAME_LENGTH + 1];
	unsigned int phr_owner_id;
	unsigned int desired_user_authority_id;
	unsigned int desired_user_id;
	unsigned int assigned_permission_id;	

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	char         object_description[DATA_DESCRIPTION_LENGTH + 1];

	// Get certificate owner's name
	get_cert_ownername(ssl_client, GLOBAL_authority_name, phr_owner_name, NULL);

	// The desired user must not be the same one with the PHR owner
	if(strcmp(desired_user_authority_name, GLOBAL_authority_name) == 0 && strcmp(desired_username, phr_owner_name) == 0)
	{
		// Send the access permission editing result flag
		write_token_into_buffer("access_permission_editing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Invalid operation", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the access permission editing result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of the desired user
	if(!does_desired_user_exists(db_conn, desired_username, desired_user_authority_name, &desired_user_id, &desired_user_authority_id))
	{
		// Send the access permission editing result flag
		write_token_into_buffer("access_permission_editing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found your desired user", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the access permission editing result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Query for the PHR owner id
	if(!get_phr_owner_id(db_conn, phr_owner_name, &phr_owner_id))
	{
		// Send the access permission editing result flag
		write_token_into_buffer("access_permission_editing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Getting the PHR owner id from a database failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the access permission editing result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Check for the existence of access permission for this desired user
	if(!does_desired_user_access_permission_exists(db_conn, phr_owner_id, desired_user_id, desired_user_authority_id, &assigned_permission_id))
	{
		// Send the access permission editing result flag
		write_token_into_buffer("access_permission_editing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Getting the assigned permission id from a database failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the access permission editing result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Update the access permission for this desired user (permissions_assigned_to_others)
	sprintf(stat, "UPDATE %s SET upload_permission_flag = '%s', download_permission_flag = '%s', delete_permission_flag = '%s'"
		"WHERE assigned_permission_id = %u", UA__PERMISSIONS_ASSIGNED_TO_OTHERS, (upload_permission_flag) ? "1" : "0", 
		(download_permission_flag) ? "1" : "0", (delete_permission_flag) ? "1" : "0", assigned_permission_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	// If the desired user is in the same authority with the PHR owner then update desired user's 
	// access permission in an access_permissions table, unless wait for synchronization mechanism
	if(desired_user_authority_id == GLOBAL_authority_id)
	{
		// Update the access permission for this desired user (access_permissions)
		sprintf(stat, "UPDATE %s SET upload_permission_flag = '%s', download_permission_flag = '%s', delete_permission_flag = '%s' WHERE user_id = %u "
			"AND phr_owner_id = %u AND phr_owner_authority_id = %u", UA__ACCESS_PERMISSIONS, (upload_permission_flag) ? "1" : "0", (download_permission_flag)
			? "1" : "0", (delete_permission_flag) ? "1" : "0", desired_user_id, phr_owner_id, GLOBAL_authority_id);

		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}	
	}
	
	disconnect_db(&db_conn);

	// Send the access permission editing result flag
	write_token_into_buffer("access_permission_editing_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the access permission editing result flag failed\n");
		goto ERROR;
	}

	// Record a transaction log
	sprintf(object_description, "Access permission: <upload: %s><download: %s><delete: %s>", (upload_permission_flag) ? "true" : "false", 
		(download_permission_flag) ? "true" : "false", (delete_permission_flag) ? "true" : "false");

	record_transaction_log(ssl_client, desired_username, desired_user_authority_name, object_description, ACCESS_PERMISSION_EDITING_MSG);
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

static boolean remove_access_permission(SSL *ssl_client, char *desired_user_authority_name, char *desired_username)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         phr_owner_name[USER_NAME_LENGTH + 1];
	unsigned int phr_owner_id;
	unsigned int desired_user_authority_id;
	unsigned int desired_user_id;
	unsigned int assigned_permission_id;	

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	// Get certificate owner's name
	get_cert_ownername(ssl_client, GLOBAL_authority_name, phr_owner_name, NULL);

	// The desired user must not be the same one with the PHR owner
	if(strcmp(desired_user_authority_name, GLOBAL_authority_name) == 0 && strcmp(desired_username, phr_owner_name) == 0)
	{
		// Send the access permission removal result flag
		write_token_into_buffer("access_permission_removal_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Invalid operation", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the access permission removal result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of the desired user
	if(!does_desired_user_exists(db_conn, desired_username, desired_user_authority_name, &desired_user_id, &desired_user_authority_id))
	{
		// Send the access permission removal result flag
		write_token_into_buffer("access_permission_removal_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found your desired user", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the access permission removal result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Query for the PHR owner id
	if(!get_phr_owner_id(db_conn, phr_owner_name, &phr_owner_id))
	{
		// Send the access permission removal result flag
		write_token_into_buffer("access_permission_removal_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Getting the PHR owner id from a database failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the access permission removal result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Check for the existence of access permission for this desired user
	if(!does_desired_user_access_permission_exists(db_conn, phr_owner_id, desired_user_id, desired_user_authority_id, &assigned_permission_id))
	{
		// Send the access permission removal result flag
		write_token_into_buffer("access_permission_removal_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Getting the assigned permission id from a database failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the access permission removal result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Delete the access permission for this desired user (permissions_assigned_to_others)
	sprintf(stat, "DELETE FROM %s WHERE assigned_permission_id = %u", UA__PERMISSIONS_ASSIGNED_TO_OTHERS, assigned_permission_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}

	// If the desired user is in the same authority with the PHR owner then delete desired user's 
	// access permission in an access_permissions table, unless wait for synchronization mechanism
	if(desired_user_authority_id == GLOBAL_authority_id)
	{
		// Delete the access permission for this desired user (access_permissions)
		sprintf(stat, "DELETE FROM %s WHERE user_id = %u AND phr_owner_id = %u AND phr_owner_authority_id = %u", 
			UA__ACCESS_PERMISSIONS, desired_user_id, phr_owner_id, GLOBAL_authority_id);

		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}	
	}

	disconnect_db(&db_conn);

	// Send the access permission removal result flag
	write_token_into_buffer("access_permission_removal_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the access permission removal result flag failed\n");
		goto ERROR;
	}

	// Record a transaction log
	record_transaction_log(ssl_client, desired_username, desired_user_authority_name, NO_SPECIFIC_DATA, ACCESS_PERMISSION_REMOVAL_MSG);
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
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    request[REQUEST_TYPE_LENGTH + 1];
	char    desired_user_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char    desired_username[USER_NAME_LENGTH + 1];

	char    permission_flag_str_tmp[FLAG_LENGTH + 1];     // "0" or "1"
	boolean upload_permission_flag;
	boolean download_permission_flag;
	boolean delete_permission_flag;

	// Receive access permission operation request information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving access permission operation request information failed\n");
		goto ERROR;
	}

	// Get access permission information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, request) != READ_TOKEN_SUCCESS || strcmp(token_name, "request") != 0)
		int_error("Extracting the request failed");

	if(read_token_from_buffer(buffer, 2, token_name, desired_user_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "desired_user_authority_name") != 0)
		int_error("Extracting the desired_user_authority_name failed");

	if(read_token_from_buffer(buffer, 3, token_name, desired_username) != READ_TOKEN_SUCCESS || strcmp(token_name, "desired_username") != 0)
		int_error("Extracting the desired_username failed");

	if(strcmp(request, ACCESS_PERMISSION_ASSIGNMENT) == 0 || strcmp(request, ACCESS_PERMISSION_EDITING) == 0)
	{
		if(read_token_from_buffer(buffer, 4, token_name, permission_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "upload_permission_flag") != 0)
			int_error("Extracting the upload_permission_flag failed");

		upload_permission_flag = (strcmp(permission_flag_str_tmp, "1") == 0) ? true : false;

		if(read_token_from_buffer(buffer, 5, token_name, permission_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "download_permission_flag") != 0)
			int_error("Extracting the download_permission_flag failed");

		download_permission_flag = (strcmp(permission_flag_str_tmp, "1") == 0) ? true : false;

		if(read_token_from_buffer(buffer, 6, token_name, permission_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "delete_permission_flag") != 0)
			int_error("Extracting the delete_permission_flag failed");

		delete_permission_flag = (strcmp(permission_flag_str_tmp, "1") == 0) ? true : false;
	}

	if(strcmp(request, ACCESS_PERMISSION_ASSIGNMENT) == 0)
	{
		return assign_access_permission(ssl_client, desired_user_authority_name, desired_username, 
			upload_permission_flag, download_permission_flag, delete_permission_flag);
	}
	else if(strcmp(request, ACCESS_PERMISSION_EDITING) == 0)
	{
		return edit_access_permission(ssl_client, desired_user_authority_name, desired_username, 
			upload_permission_flag, download_permission_flag, delete_permission_flag);
	}
	else if(strcmp(request, ACCESS_PERMISSION_REMOVAL) == 0)
	{
		return remove_access_permission(ssl_client, desired_user_authority_name, desired_username);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *access_permission_management_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(UA_ACCESS_PERMISSION_MANAGEMENT_PORT);
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




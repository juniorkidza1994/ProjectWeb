#include "AS_common.h"

// Local Function Prototypesevent
static boolean record_login_log_for_user_authority(SSL *ssl_client);
static boolean record_logout_log_for_user(SSL *ssl_client);
static boolean record_event_log_for_user(SSL *ssl_client);
static boolean record_event_log_for_server(SSL *ssl_client);
static boolean record_multiple_event_logs_for_server(SSL *ssl_client);
static boolean synchronize_phr_log(SSL *ssl_client);
static boolean process_request(SSL *ssl_client);

// Implementation
static boolean record_login_log_for_user_authority(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];
	char         is_admin_flag_str_tmp[FLAG_LENGTH + 1];  // "1" or "0"
	boolean      is_admin_flag;
	char         date_time[DATETIME_STR_LENGTH + 1];
	char         ip_address[IP_ADDRESS_LENGTH + 1];

	MYSQL        *db_conn = NULL;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_id;

	// Receive transaction login log information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving transaction login log information failed\n");
		goto ERROR;
	}

	// Get transaction login log information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
	{
		int_error("Extracting the username failed");
	}

	if(read_token_from_buffer(buffer, 2, token_name, is_admin_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "is_admin_flag") != 0)
	{
		int_error("Extracting the is_admin_flag failed");
	}

	is_admin_flag = (strcmp(is_admin_flag_str_tmp, "1") == 0) ? true : false;

	if(read_token_from_buffer(buffer, 3, token_name, date_time) != READ_TOKEN_SUCCESS || strcmp(token_name, "date_time") != 0)
	{
		int_error("Extracting the date_time failed");
	}

	if(read_token_from_buffer(buffer, 4, token_name, ip_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "ip_address") != 0)
	{
		int_error("Extracting the ip_address failed");
	}
	
	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	user_id = get_user_id(db_conn, username, GLOBAL_authority_name, is_admin_flag);

	// Insert transaction login log into database
	sprintf(stat, "INSERT INTO %s(user_id, date_time, ip_address, is_logout_flag) VALUES(%u, '%s', '%s', '0')", AS__LOGIN_LOGS, user_id, date_time, ip_address);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	disconnect_db(&db_conn);
	return true;

ERROR:

	return false;
}

static boolean record_logout_log_for_user(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];
	char         is_admin_flag_str_tmp[FLAG_LENGTH + 1];          // "1" or "0"
	boolean      is_admin_flag;
	char         current_date_time[DATETIME_STR_LENGTH + 1];     // Get current date/time at server
	char         ip_address[IP_ADDRESS_LENGTH + 1];              // Get an IP address at server

	MYSQL        *db_conn = NULL;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_id;

	// Receive transaction login log information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving transaction login log information failed\n");
		goto ERROR;
	}

	// Get transaction login log information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
	{
		int_error("Extracting the username failed");
	}

	if(read_token_from_buffer(buffer, 2, token_name, is_admin_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "is_admin_flag") != 0)
	{
		int_error("Extracting the is_admin_flag failed");
	}

	is_admin_flag = (strcmp(is_admin_flag_str_tmp, "1") == 0) ? true : false;

	// Get date/time and client's IP address
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_client, ip_address, NULL);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	user_id = get_user_id(db_conn, username, GLOBAL_authority_name, is_admin_flag);

	// Insert transaction login log into database
	sprintf(stat, "INSERT INTO %s(user_id, date_time, ip_address, is_logout_flag) VALUES(%u, '%s', '%s', '1')", AS__LOGIN_LOGS, user_id, current_date_time, ip_address);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	disconnect_db(&db_conn);
	return true;

ERROR:

	return false;
}

static boolean record_event_log_for_user(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         actor_name[USER_NAME_LENGTH + 1];
	char         object_owner_name[USER_NAME_LENGTH + 1];
	char         affected_username[USER_NAME_LENGTH + 1];

	char         actor_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         object_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         affected_user_authority_name[AUTHORITY_NAME_LENGTH + 1];

	char         does_user_is_admin_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      does_actor_is_admin_flag;
	boolean      does_object_owner_is_admin_flag;
	boolean      does_affected_user_is_admin_flag;

	char         object_description[DATA_DESCRIPTION_LENGTH + 1];
	char         event_description[EVENT_DESCRIPTION_LENGTH + 1];
	char         current_date_time[DATETIME_STR_LENGTH + 1];        // Get current date/time at server
	char         actor_ip_address[IP_ADDRESS_LENGTH + 1];           // Get an IP address at server

	MYSQL        *db_conn = NULL;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         object_description_chunk[DATA_DESCRIPTION_LENGTH*2 + 1];
	char         event_description_chunk[EVENT_DESCRIPTION_LENGTH*2 + 1];
	char	     query[(SQL_STATEMENT_LENGTH + 1) + (DATA_DESCRIPTION_LENGTH*2 + 1) + (EVENT_DESCRIPTION_LENGTH*2 + 1)];
	unsigned int len;
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int actor_id;
	unsigned int object_owner_id;
	unsigned int affected_user_id;

	boolean      sync_flag;

	// Receive transaction event log information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving transaction event log information failed\n");
		goto ERROR;
	}

	// Get transaction event log information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, actor_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "actor_name") != 0)
	{
		int_error("Extracting the actor_name failed");
	}

	if(read_token_from_buffer(buffer, 2, token_name, actor_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "actor_authority_name") != 0)
	{
		int_error("Extracting the actor_authority_name failed");
	}

	if(read_token_from_buffer(buffer, 3, token_name, does_user_is_admin_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "does_actor_is_admin_flag") != 0)
	{
		int_error("Extracting the does_actor_is_admin_flag failed");
	}

	does_actor_is_admin_flag = (strcmp(does_user_is_admin_flag_str_tmp, "1") == 0) ? true : false;

	if(read_token_from_buffer(buffer, 4, token_name, object_owner_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "object_owner_name") != 0)
	{
		int_error("Extracting the object_owner_name failed");
	}

	if(read_token_from_buffer(buffer, 5, token_name, object_owner_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "object_owner_authority_name") != 0)
	{
		int_error("Extracting the object_owner_authority_name failed");
	}

	if(read_token_from_buffer(buffer, 6, token_name, does_user_is_admin_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "does_object_owner_is_admin_flag") != 0)
	{
		int_error("Extracting the does_object_owner_is_admin_flag failed");
	}

	does_object_owner_is_admin_flag = (strcmp(does_user_is_admin_flag_str_tmp, "1") == 0) ? true : false;

	if(read_token_from_buffer(buffer, 7, token_name, affected_username) != READ_TOKEN_SUCCESS || strcmp(token_name, "affected_username") != 0)
	{
		int_error("Extracting the affected_username failed");
	}

	if(read_token_from_buffer(buffer, 8, token_name, affected_user_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "affected_user_authority_name") != 0)
	{
		int_error("Extracting the affected_user_authority_name failed");
	}

	if(read_token_from_buffer(buffer, 9, token_name, does_user_is_admin_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "does_affected_user_is_admin_flag") != 0)
	{
		int_error("Extracting the does_affected_user_is_admin_flag failed");
	}

	does_affected_user_is_admin_flag = (strcmp(does_user_is_admin_flag_str_tmp, "1") == 0) ? true : false;

	if(read_token_from_buffer(buffer, 10, token_name, object_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "object_description") != 0)
	{
		int_error("Extracting the object_description failed");
	}

	if(read_token_from_buffer(buffer, 11, token_name, event_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "event_description") != 0)
	{
		int_error("Extracting the event_description failed");
	}

	// Get date/time and client's IP address
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_client, actor_ip_address, NULL);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	actor_id         = get_user_id(db_conn, actor_name, actor_authority_name, does_actor_is_admin_flag);
	object_owner_id  = get_user_id(db_conn, object_owner_name, object_owner_authority_name, does_object_owner_is_admin_flag);
	affected_user_id = get_user_id(db_conn, affected_username, affected_user_authority_name, does_affected_user_is_admin_flag);

	if((strstr(event_description, "PHR") || strstr(event_description, "emergency")) && (strcmp(actor_authority_name, object_owner_authority_name) != 0 
		|| strcmp(actor_authority_name, affected_user_authority_name) != 0 || strcmp(object_owner_authority_name, affected_user_authority_name) != 0))
	{
		sync_flag = true;
	}
	else
	{
		sync_flag = false;
	}

	// Insert a transaction event log into the database
	sprintf(stat, "INSERT INTO %s(actor_id, object_owner_id, affected_user_id, object_description, event_description, date_time, actor_ip_address, "
		"sync_flag) VALUES(%u, %u, %u, '%%s', '%%s', '%s', '%s', '%s')", AS__EVENT_LOGS, actor_id, object_owner_id, affected_user_id, current_date_time, 
		actor_ip_address, (sync_flag) ? "1" : "0");
	
	// Take the escaped SQL strings
	mysql_real_escape_string(db_conn, object_description_chunk, object_description, strlen(object_description));
	mysql_real_escape_string(db_conn, event_description_chunk, event_description, strlen(event_description));

	len = snprintf(query, sizeof(query), stat, object_description_chunk, event_description_chunk);

	if(mysql_real_query(db_conn, query, len))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	disconnect_db(&db_conn);
	return true;

ERROR:

	return false;
}

static boolean record_event_log_for_server(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         actor_name[USER_NAME_LENGTH + 1];
	char         object_owner_name[USER_NAME_LENGTH + 1];
	char         affected_username[USER_NAME_LENGTH + 1];

	char         actor_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         object_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         affected_user_authority_name[AUTHORITY_NAME_LENGTH + 1];

	char         does_user_is_admin_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      does_actor_is_admin_flag;
	boolean      does_object_owner_is_admin_flag;
	boolean      does_affected_user_is_admin_flag;

	char         object_description[DATA_DESCRIPTION_LENGTH + 1];
	char         event_description[EVENT_DESCRIPTION_LENGTH + 1];
	char         date_time[DATETIME_STR_LENGTH + 1];
	char         actor_ip_address[IP_ADDRESS_LENGTH + 1];

	MYSQL        *db_conn = NULL;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         object_description_chunk[DATA_DESCRIPTION_LENGTH*2 + 1];
	char         event_description_chunk[EVENT_DESCRIPTION_LENGTH*2 + 1];
	char	     query[(SQL_STATEMENT_LENGTH + 1) + (DATA_DESCRIPTION_LENGTH*2 + 1) + (EVENT_DESCRIPTION_LENGTH*2 + 1)];
	unsigned int len;
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int actor_id;
	unsigned int object_owner_id;
	unsigned int affected_user_id;

	boolean      sync_flag;

	// Receive transaction event log information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving transaction event log information failed\n");
		goto ERROR;
	}

	// Get transaction event log information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, actor_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "actor_name") != 0)
	{
		int_error("Extracting the actor_name failed");
	}

	if(read_token_from_buffer(buffer, 2, token_name, actor_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "actor_authority_name") != 0)
	{
		int_error("Extracting the actor_authority_name failed");
	}

	if(read_token_from_buffer(buffer, 3, token_name, does_user_is_admin_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "does_actor_is_admin_flag") != 0)
	{
		int_error("Extracting the does_actor_is_admin_flag failed");
	}

	does_actor_is_admin_flag = (strcmp(does_user_is_admin_flag_str_tmp, "1") == 0) ? true : false;

	if(read_token_from_buffer(buffer, 4, token_name, object_owner_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "object_owner_name") != 0)
	{
		int_error("Extracting the object_owner_name failed");
	}

	if(read_token_from_buffer(buffer, 5, token_name, object_owner_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "object_owner_authority_name") != 0)
	{
		int_error("Extracting the object_owner_authority_name failed");
	}

	if(read_token_from_buffer(buffer, 6, token_name, does_user_is_admin_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "does_object_owner_is_admin_flag") != 0)
	{
		int_error("Extracting the does_object_owner_is_admin_flag failed");
	}

	does_object_owner_is_admin_flag = (strcmp(does_user_is_admin_flag_str_tmp, "1") == 0) ? true : false;

	if(read_token_from_buffer(buffer, 7, token_name, affected_username) != READ_TOKEN_SUCCESS || strcmp(token_name, "affected_username") != 0)
	{
		int_error("Extracting the affected_username failed");
	}

	if(read_token_from_buffer(buffer, 8, token_name, affected_user_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "affected_user_authority_name") != 0)
	{
		int_error("Extracting the affected_user_authority_name failed");
	}

	if(read_token_from_buffer(buffer, 9, token_name, does_user_is_admin_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "does_affected_user_is_admin_flag") != 0)
	{
		int_error("Extracting the does_affected_user_is_admin_flag failed");
	}

	does_affected_user_is_admin_flag = (strcmp(does_user_is_admin_flag_str_tmp, "1") == 0) ? true : false;

	if(read_token_from_buffer(buffer, 10, token_name, object_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "object_description") != 0)
	{
		int_error("Extracting the object_description failed");
	}

	if(read_token_from_buffer(buffer, 11, token_name, event_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "event_description") != 0)
	{
		int_error("Extracting the event_description failed");
	}

	if(read_token_from_buffer(buffer, 12, token_name, date_time) != READ_TOKEN_SUCCESS || strcmp(token_name, "date_time") != 0)
	{
		int_error("Extracting the date_time failed");
	}

	if(read_token_from_buffer(buffer, 13, token_name, actor_ip_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "actor_ip_address") != 0)
	{
		int_error("Extracting the actor_ip_address failed");
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	actor_id         = get_user_id(db_conn, actor_name, actor_authority_name, does_actor_is_admin_flag);
	object_owner_id  = get_user_id(db_conn, object_owner_name, object_owner_authority_name, does_object_owner_is_admin_flag);
	affected_user_id = get_user_id(db_conn, affected_username, affected_user_authority_name, does_affected_user_is_admin_flag);

	if((strstr(event_description, "PHR") || strstr(event_description, "emergency")) && (strcmp(actor_authority_name, object_owner_authority_name) != 0 
		|| strcmp(actor_authority_name, affected_user_authority_name) != 0 || strcmp(object_owner_authority_name, affected_user_authority_name) != 0))
	{
		sync_flag = true;
	}
	else
	{
		sync_flag = false;
	}

	// Insert a transaction event log into the database
	sprintf(stat, "INSERT INTO %s(actor_id, object_owner_id, affected_user_id, object_description, event_description, date_time, "
		"actor_ip_address, sync_flag) VALUES(%u, %u, %u, '%%s', '%%s', '%s', '%s', '%s')", AS__EVENT_LOGS, actor_id, 
		object_owner_id, affected_user_id, date_time, actor_ip_address, (sync_flag) ? "1" : "0");
	
	// Take the escaped SQL strings
	mysql_real_escape_string(db_conn, object_description_chunk, object_description, strlen(object_description));
	mysql_real_escape_string(db_conn, event_description_chunk, event_description, strlen(event_description));

	len = snprintf(query, sizeof(query), stat, object_description_chunk, event_description_chunk);

	if(mysql_real_query(db_conn, query, len))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	disconnect_db(&db_conn);
	return true;

ERROR:

	return false;
}

static boolean record_multiple_event_logs_for_server(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         is_end_of_recording_multiple_event_logs_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      is_end_of_recording_multiple_event_logs_flag;

	char         actor_name[USER_NAME_LENGTH + 1];
	char         object_owner_name[USER_NAME_LENGTH + 1];
	char         affected_username[USER_NAME_LENGTH + 1];

	char         actor_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         object_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         affected_user_authority_name[AUTHORITY_NAME_LENGTH + 1];

	char         does_user_is_admin_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      does_actor_is_admin_flag;
	boolean      does_object_owner_is_admin_flag;
	boolean      does_affected_user_is_admin_flag;

	char         object_description[DATA_DESCRIPTION_LENGTH + 1];
	char         event_description[EVENT_DESCRIPTION_LENGTH + 1];
	char         date_time[DATETIME_STR_LENGTH + 1];
	char         actor_ip_address[IP_ADDRESS_LENGTH + 1];

	MYSQL        *db_conn = NULL;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         object_description_chunk[DATA_DESCRIPTION_LENGTH*2 + 1];
	char         event_description_chunk[EVENT_DESCRIPTION_LENGTH*2 + 1];
	char	     query[(SQL_STATEMENT_LENGTH + 1) + (DATA_DESCRIPTION_LENGTH*2 + 1) + (EVENT_DESCRIPTION_LENGTH*2 + 1)];
	unsigned int len;
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int actor_id;
	unsigned int object_owner_id;
	unsigned int affected_user_id;

	boolean      sync_flag;

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	while(1)
	{
		// Receive transaction event log information
		if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving transaction event log information failed\n");
			goto ERROR;
		}

		// Get transaction event log information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_recording_multiple_event_logs_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_recording_multiple_event_logs_flag") != 0)
		{
			int_error("Extracting the is_end_of_recording_multiple_event_logs_flag failed");
		}

		is_end_of_recording_multiple_event_logs_flag = (strcmp(is_end_of_recording_multiple_event_logs_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_recording_multiple_event_logs_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, actor_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "actor_name") != 0)
		{
			int_error("Extracting the actor_name failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, actor_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "actor_authority_name") != 0)
		{
			int_error("Extracting the actor_authority_name failed");
		}

		if(read_token_from_buffer(buffer, 4, token_name, does_user_is_admin_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "does_actor_is_admin_flag") != 0)
		{
			int_error("Extracting the does_actor_is_admin_flag failed");
		}

		does_actor_is_admin_flag = (strcmp(does_user_is_admin_flag_str_tmp, "1") == 0) ? true : false;

		if(read_token_from_buffer(buffer, 5, token_name, object_owner_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "object_owner_name") != 0)
		{
			int_error("Extracting the object_owner_name failed");
		}

		if(read_token_from_buffer(buffer, 6, token_name, object_owner_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "object_owner_authority_name") != 0)
		{
			int_error("Extracting the object_owner_authority_name failed");
		}

		if(read_token_from_buffer(buffer, 7, token_name, does_user_is_admin_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "does_object_owner_is_admin_flag") != 0)
		{
			int_error("Extracting the does_object_owner_is_admin_flag failed");
		}

		does_object_owner_is_admin_flag = (strcmp(does_user_is_admin_flag_str_tmp, "1") == 0) ? true : false;

		if(read_token_from_buffer(buffer, 8, token_name, affected_username) != READ_TOKEN_SUCCESS || strcmp(token_name, "affected_username") != 0)
		{
			int_error("Extracting the affected_username failed");
		}

		if(read_token_from_buffer(buffer, 9, token_name, affected_user_authority_name) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "affected_user_authority_name") != 0)
		{
			int_error("Extracting the affected_user_authority_name failed");
		}

		if(read_token_from_buffer(buffer, 10, token_name, does_user_is_admin_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "does_affected_user_is_admin_flag") != 0)
		{
			int_error("Extracting the does_affected_user_is_admin_flag failed");
		}

		does_affected_user_is_admin_flag = (strcmp(does_user_is_admin_flag_str_tmp, "1") == 0) ? true : false;

		if(read_token_from_buffer(buffer, 11, token_name, object_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "object_description") != 0)
		{
			int_error("Extracting the object_description failed");
		}

		if(read_token_from_buffer(buffer, 12, token_name, event_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "event_description") != 0)
		{
			int_error("Extracting the event_description failed");
		}

		if(read_token_from_buffer(buffer, 13, token_name, date_time) != READ_TOKEN_SUCCESS || strcmp(token_name, "date_time") != 0)
		{
			int_error("Extracting the date_time failed");
		}

		if(read_token_from_buffer(buffer, 14, token_name, actor_ip_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "actor_ip_address") != 0)
		{
			int_error("Extracting the actor_ip_address failed");
		}

		actor_id         = get_user_id(db_conn, actor_name, actor_authority_name, does_actor_is_admin_flag);
		object_owner_id  = get_user_id(db_conn, object_owner_name, object_owner_authority_name, does_object_owner_is_admin_flag);
		affected_user_id = get_user_id(db_conn, affected_username, affected_user_authority_name, does_affected_user_is_admin_flag);

		if((strstr(event_description, "PHR") || strstr(event_description, "emergency")) && (strcmp(actor_authority_name, object_owner_authority_name) != 0 
			|| strcmp(actor_authority_name, affected_user_authority_name) != 0 || strcmp(object_owner_authority_name, affected_user_authority_name) != 0))
		{
			sync_flag = true;
		}
		else
		{
			sync_flag = false;
		}

		// Insert a transaction event log into the database
		sprintf(stat, "INSERT INTO %s(actor_id, object_owner_id, affected_user_id, object_description, event_description, date_time, "
			"actor_ip_address, sync_flag) VALUES(%u, %u, %u, '%%s', '%%s', '%s', '%s', '%s')", AS__EVENT_LOGS, actor_id, 
			object_owner_id, affected_user_id, date_time, actor_ip_address, (sync_flag) ? "1" : "0");
	
		// Take the escaped SQL strings
		mysql_real_escape_string(db_conn, object_description_chunk, object_description, strlen(object_description));
		mysql_real_escape_string(db_conn, event_description_chunk, event_description, strlen(event_description));

		len = snprintf(query, sizeof(query), stat, object_description_chunk, event_description_chunk);

		if(mysql_real_query(db_conn, query, len))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}
	}

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

static boolean synchronize_phr_log(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         is_end_of_phr_transaction_logs_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      is_end_of_phr_transaction_logs_flag;

	char         actor_name[USER_NAME_LENGTH + 1];
	char         object_owner_name[USER_NAME_LENGTH + 1];
	char         affected_username[USER_NAME_LENGTH + 1];

	char         actor_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         object_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         affected_user_authority_name[AUTHORITY_NAME_LENGTH + 1];

	char         is_admin_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      is_actor_admin_flag;
	boolean      is_object_owner_admin_flag;
	boolean      is_affected_user_admin_flag;

	char         object_description[DATA_DESCRIPTION_LENGTH + 1];
	char         event_description[EVENT_DESCRIPTION_LENGTH + 1];
	char         date_time[DATETIME_STR_LENGTH + 1];
	char         actor_ip_address[IP_ADDRESS_LENGTH + 1];

	MYSQL        *db_conn = NULL;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         object_description_chunk[DATA_DESCRIPTION_LENGTH*2 + 1];
	char         event_description_chunk[EVENT_DESCRIPTION_LENGTH*2 + 1];
	char	     query[(SQL_STATEMENT_LENGTH + 1) + (DATA_DESCRIPTION_LENGTH*2 + 1) + (EVENT_DESCRIPTION_LENGTH*2 + 1)];
	unsigned int len;
	char	     err_msg[ERR_MSG_LENGTH + 1];


	unsigned int actor_id;
	unsigned int object_owner_id;
	unsigned int affected_user_id;

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	while(1)
	{
		// Receive PHR transaction log information
		if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving PHR transaction log information failed\n");
			goto ERROR;
		}

		// Get PHR transaction log information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_phr_transaction_logs_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_phr_transaction_logs_flag") != 0)
		{
			int_error("Extracting the is_end_of_phr_transaction_logs_flag failed");
		}

		is_end_of_phr_transaction_logs_flag = (strcmp(is_end_of_phr_transaction_logs_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_phr_transaction_logs_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, actor_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "actor_name") != 0)
		{
			int_error("Extracting the actor_name failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, actor_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "actor_authority_name") != 0)
		{
			int_error("Extracting the actor_authority_name failed");
		}

		if(read_token_from_buffer(buffer, 4, token_name, is_admin_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "is_actor_admin_flag") != 0)
		{
			int_error("Extracting the is_actor_admin_flag failed");
		}

		is_actor_admin_flag = (strcmp(is_admin_flag_str_tmp, "1") == 0) ? true : false;

		if(read_token_from_buffer(buffer, 5, token_name, object_owner_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "object_owner_name") != 0)
		{
			int_error("Extracting the object_owner_name failed");
		}

		if(read_token_from_buffer(buffer, 6, token_name, object_owner_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "object_owner_authority_name") != 0)
		{
			int_error("Extracting the object_owner_authority_name failed");
		}

		if(read_token_from_buffer(buffer, 7, token_name, is_admin_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_object_owner_admin_flag") != 0)
		{
			int_error("Extracting the is_object_owner_admin_flag failed");
		}

		is_object_owner_admin_flag = (strcmp(is_admin_flag_str_tmp, "1") == 0) ? true : false;

		if(read_token_from_buffer(buffer, 8, token_name, affected_username) != READ_TOKEN_SUCCESS || strcmp(token_name, "affected_username") != 0)
		{
			int_error("Extracting the affected_username failed");
		}

		if(read_token_from_buffer(buffer, 9, token_name, affected_user_authority_name) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "affected_user_authority_name") != 0)
		{
			int_error("Extracting the affected_user_authority_name failed");
		}

		if(read_token_from_buffer(buffer, 10, token_name, is_admin_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_affected_user_admin_flag") != 0)
		{
			int_error("Extracting the is_affected_user_admin_flag failed");
		}

		is_affected_user_admin_flag = (strcmp(is_admin_flag_str_tmp, "1") == 0) ? true : false;

		if(read_token_from_buffer(buffer, 11, token_name, object_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "object_description") != 0)
		{
			int_error("Extracting the object_description failed");
		}

		if(read_token_from_buffer(buffer, 12, token_name, event_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "event_description") != 0)
		{
			int_error("Extracting the event_description failed");
		}

		if(read_token_from_buffer(buffer, 13, token_name, date_time) != READ_TOKEN_SUCCESS || strcmp(token_name, "date_time") != 0)
		{
			int_error("Extracting the date_time failed");
		}

		if(read_token_from_buffer(buffer, 14, token_name, actor_ip_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "actor_ip_address") != 0)
		{
			int_error("Extracting the actor_ip_address failed");
		}

		actor_id         = get_user_id(db_conn, actor_name, actor_authority_name, is_actor_admin_flag);
		object_owner_id  = get_user_id(db_conn, object_owner_name, object_owner_authority_name, is_object_owner_admin_flag);
		affected_user_id = get_user_id(db_conn, affected_username, affected_user_authority_name, is_affected_user_admin_flag);

		// Insert a transaction event log into the database
		sprintf(stat, "INSERT INTO %s(actor_id, object_owner_id, affected_user_id, object_description, event_description, date_time, "
			"actor_ip_address, sync_flag) VALUES(%u, %u, %u, '%%s', '%%s', '%s', '%s', '0')", AS__EVENT_LOGS, actor_id, 
			object_owner_id, affected_user_id, date_time, actor_ip_address);
	
		// Take the escaped SQL strings
		mysql_real_escape_string(db_conn, object_description_chunk, object_description, strlen(object_description));
		mysql_real_escape_string(db_conn, event_description_chunk, event_description, strlen(event_description));

		len = snprintf(query, sizeof(query), stat, object_description_chunk, event_description_chunk);

		if(mysql_real_query(db_conn, query, len))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}
printf("sync log in\n");
	}

	disconnect_db(&db_conn);
	return true;

ERROR:

	disconnect_db(&db_conn);
	return false;
}

static boolean process_request(SSL *ssl_client)
{
	entity_type user_or_server_type;
	char        buffer[BUFFER_LENGTH + 1];
	char        token_name[TOKEN_NAME_LENGTH + 1];
	char        request_type[REQUEST_TYPE_LENGTH + 1];

	// Get a certificate's entity type
	get_cert_ownername(ssl_client, GLOBAL_authority_name, NULL, &user_or_server_type);

	// Receive request type information (either login_log or event_log)
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

	// User (including admin) can record his/her logout logs and event logs (transaction regarding PHR Database)
	if(user_or_server_type == admin || user_or_server_type == user)
	{
		if(strcmp(request_type, LOGOUT_LOG_RECORDING) == 0)
		{
			return record_logout_log_for_user(ssl_client);
		}
		else if(strcmp(request_type, EVENT_LOG_RECORDING) == 0)
		{
			return record_event_log_for_user(ssl_client);
		}
		else
		{
			fprintf(stderr, "Invalid request type\n");
			goto ERROR;
		}
	}
	else if(user_or_server_type == server)   // User Authority can record user's login logs, event logs and synchronize PHR logs; Emergency Server can record event logs
	{
		if(strcmp(request_type, LOGIN_LOG_RECORDING) == 0)
		{
			return record_login_log_for_user_authority(ssl_client);
		}
		else if(strcmp(request_type, EVENT_LOG_RECORDING) == 0)
		{
			return record_event_log_for_server(ssl_client);
		}
		else if(strcmp(request_type, MULTIPLE_EVENT_LOGS_RECORDING) == 0)
		{
			return record_multiple_event_logs_for_server(ssl_client);
		}
		else if(strcmp(request_type, PHR_LOG_SYNCHRONIZATION) == 0)
		{
			return synchronize_phr_log(ssl_client);
		}
		else
		{
			fprintf(stderr, "Invalid request type\n");
			goto ERROR;
		}
	}
	else
	{
		fprintf(stderr, "Invalid certificate's entity type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *transaction_log_recording_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[4];

    	ctx = setup_server_ctx(AS_CERTFILE_PATH, AS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(AS_TRANSACTION_LOG_RECORDING_PORT);
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
		hosts[1] = ADMIN_CN;
		hosts[2] = USER_AUTH_CN;
		hosts[3] = EMERGENCY_SERVER_CN;
    		if((err = post_connection_check(ssl_client, hosts, 4, true, GLOBAL_authority_name)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}
		
		// Process types of request
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




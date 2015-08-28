#include "AS_common.h"

// Local Function Prototypes
static void record_transaction_auditing_log(SSL *ssl_client, char *event_description);
static boolean respond_some_period_time_transaction_user_login_log(SSL *ssl_client,
	char *username, entity_type user_or_admin_type, char *start_date_time, char *end_date_time);

static boolean respond_all_transaction_user_login_log(SSL *ssl_client, char *username, entity_type user_or_admin_type);
static boolean respond_some_period_time_transaction_user_event_log(SSL *ssl_client, 
	char *username, entity_type user_or_admin_type, char *start_date_time, char *end_date_time);

static boolean respond_all_transaction_user_event_log(SSL *ssl_client, char *username, entity_type user_or_admin_type);
static boolean respond_some_period_time_transaction_system_login_log(SSL *ssl_client, char *start_date_time, char *end_date_time);
static boolean respond_all_transaction_system_login_log(SSL *ssl_client);
static boolean respond_some_period_time_transaction_system_event_log(SSL *ssl_client, char *start_date_time, char *end_date_time);
static boolean respond_all_transaction_system_event_log(SSL *ssl_client);
static boolean process_request(SSL *ssl_client);

// Implementation
static void record_transaction_auditing_log(SSL *ssl_client, char *event_description)
{
	entity_type  user_or_admin_type;
	char         cert_ownername[USER_NAME_LENGTH + 1];

	char         current_date_time[DATETIME_STR_LENGTH + 1];  // Get current date/time at server
	char         ip_address[IP_ADDRESS_LENGTH + 1];           // Get an IP address at server

	MYSQL        *db_conn = NULL;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         event_description_chunk[EVENT_DESCRIPTION_LENGTH*2 + 1];
	char	     query[(SQL_STATEMENT_LENGTH + 1) + (EVENT_DESCRIPTION_LENGTH*2 + 1)];
	unsigned int len;
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int actor_id;
	unsigned int object_owner_id;
	unsigned int affected_user_id;

	// Get certificate's ownername and entity type
	get_cert_ownername(ssl_client, GLOBAL_authority_name, cert_ownername, &user_or_admin_type);

	// Get date/time and client's IP address
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_client, ip_address, NULL);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);	

	actor_id         = get_user_id(db_conn, cert_ownername, GLOBAL_authority_name, user_or_admin_type == admin);
	object_owner_id  = GLOBAL_no_reference_user_id;
	affected_user_id = GLOBAL_no_reference_user_id;

	// Insert a transaction event log into the database
	sprintf(stat, "INSERT INTO %s(actor_id, object_owner_id, affected_user_id, object_description, event_description, date_time, "
		"actor_ip_address, sync_flag) VALUES(%u, %u, %u, '%s', '%%s', '%s', '%s', '0')", AS__EVENT_LOGS, actor_id, object_owner_id, 
		affected_user_id, NO_SPECIFIC_DATA, current_date_time, ip_address);
	
	// Take the escaped SQL string
	mysql_real_escape_string(db_conn, event_description_chunk, event_description, strlen(event_description));

	len = snprintf(query, sizeof(query), stat, event_description_chunk);
	if(mysql_real_query(db_conn, query, len))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	disconnect_db(&db_conn);
}

static boolean respond_some_period_time_transaction_user_login_log(SSL *ssl_client, char *username, entity_type user_or_admin_type, char *start_date_time, char *end_date_time)
{
	MYSQL     *db_conn = NULL;
	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	char      buffer[BUFFER_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for login logs
	sprintf(stat, "SELECT LGN.date_time, LGN.ip_address, LGN.is_logout_flag FROM %s LGN, %s USR, %s AUT WHERE LGN.user_id = USR.user_id "
		"AND USR.username LIKE '%s' COLLATE latin1_general_cs AND USR.is_admin_flag = '%u' AND USR.authority_id = AUT.authority_id "
		"AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND (LGN.date_time >= '%s' AND LGN.date_time <= '%s') ORDER BY "
		"LGN.login_log_id ASC", AS__LOGIN_LOGS, AS__USERS, AS__AUTHORITIES, username, (user_or_admin_type == admin) ? true : false, 
		GLOBAL_authority_name, start_date_time, end_date_time);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		// Send the transaction login log information
		write_token_into_buffer("is_end_of_transaction_login_logs_flag", "0", true, buffer);
		write_token_into_buffer("date_time", row[0], false, buffer);
		write_token_into_buffer("ip_address", row[1], false, buffer);
		write_token_into_buffer("is_logout_flag", row[2], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the transaction login log information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	disconnect_db(&db_conn);

	// Send the end of transaction login logs
	write_token_into_buffer("is_end_of_transaction_login_logs_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of transaction login logs failed\n");
		goto ERROR;
	}

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

static boolean respond_all_transaction_user_login_log(SSL *ssl_client, char *username, entity_type user_or_admin_type)
{
	MYSQL     *db_conn = NULL;
	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	char      buffer[BUFFER_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for login logs
	sprintf(stat, "SELECT LGN.date_time, LGN.ip_address, LGN.is_logout_flag FROM %s LGN, %s USR, %s AUT WHERE LGN.user_id = USR.user_id "
		"AND USR.username LIKE '%s' COLLATE latin1_general_cs AND USR.is_admin_flag = '%u' AND USR.authority_id = AUT.authority_id "
		"AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs ORDER BY LGN.login_log_id ASC", AS__LOGIN_LOGS, AS__USERS, AS__AUTHORITIES, username, 
		(user_or_admin_type == admin) ? true : false, GLOBAL_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		// Send the transaction login log information
		write_token_into_buffer("is_end_of_transaction_login_logs_flag", "0", true, buffer);
		write_token_into_buffer("date_time", row[0], false, buffer);
		write_token_into_buffer("ip_address", row[1], false, buffer);
		write_token_into_buffer("is_logout_flag", row[2], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the transaction login log information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	disconnect_db(&db_conn);

	// Send the end of transaction login logs
	write_token_into_buffer("is_end_of_transaction_login_logs_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of transaction login logs failed\n");
		goto ERROR;
	}

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

static boolean respond_some_period_time_transaction_user_event_log(SSL *ssl_client, char *username, entity_type user_or_admin_type, char *start_date_time, char *end_date_time)
{
	MYSQL        *db_conn = NULL;
	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int actor_id;
	char         actor_name[USER_NAME_LENGTH + 1];
	char         actor_authority_name[AUTHORITY_NAME_LENGTH + 1];
	boolean      is_actor_admin_flag;

	unsigned int object_owner_id;
	char         object_owner_name[USER_NAME_LENGTH + 1];
	char         object_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	boolean      is_object_owner_admin_flag;

	char         event_description[EVENT_DESCRIPTION_LENGTH + 1];
	char         buffer[BUFFER_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for event logs
	sprintf(stat, "SELECT EVT.actor_id, EVT.object_owner_id, EVT.object_description, EVT.event_description, EVT.date_time, EVT.actor_ip_address FROM "
		"%s EVT, %s USR, %s AUT WHERE (EVT.actor_id = USR.user_id OR EVT.object_owner_id = USR.user_id OR EVT.affected_user_id = USR.user_id) "
		"AND USR.username LIKE '%s' COLLATE latin1_general_cs AND USR.is_admin_flag = '%u' AND USR.authority_id = AUT.authority_id AND "
		"AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND (EVT.date_time >= '%s' AND EVT.date_time <= '%s') ORDER BY EVT.date_time ASC, "
		"EVT.event_log_id ASC", AS__EVENT_LOGS, AS__USERS, AS__AUTHORITIES, username, (user_or_admin_type == admin) ? true : false, GLOBAL_authority_name, 
		start_date_time, end_date_time);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		actor_id        = atoi(row[0]);
		object_owner_id = atoi(row[1]);
		strcpy(event_description, row[3]);

		// Get info of actor and object owner
		if(!get_user_info(db_conn, actor_id, actor_name, actor_authority_name, &is_actor_admin_flag))
			goto ERROR;

		if(!get_user_info(db_conn, object_owner_id, object_owner_name, object_owner_authority_name, &is_object_owner_admin_flag))
			goto ERROR;

		// Filter out
		if(is_actor_admin_flag && strcmp(actor_name, username) == 0 && strstr(event_description, "access permission"))
			continue;

		if(strcmp(object_owner_name, username) == 0 && strstr(event_description, "access permission"))
			continue;

		if(strcmp(actor_authority_name, GLOBAL_authority_name) != 0 && (strcmp(object_owner_authority_name, GLOBAL_authority_name) == 0 && 
			strcmp(object_owner_name, username) == 0) && strstr(event_description, "your emergency PHR owner's restricted-level PHR"))
		{
			continue;
		}

		// Send the transaction event log information
		write_token_into_buffer("is_end_of_transaction_event_logs_flag", "0", true, buffer);
		write_token_into_buffer("actor_name", actor_name, false, buffer);
		write_token_into_buffer("actor_authority_name", actor_authority_name, false, buffer);
		write_token_into_buffer("is_actor_admin_flag", (is_actor_admin_flag) ? "1" : "0", false, buffer);
		write_token_into_buffer("object_owner_name", object_owner_name, false, buffer);
		write_token_into_buffer("object_owner_authority_name", object_owner_authority_name, false, buffer);
		write_token_into_buffer("is_object_owner_admin_flag", (is_object_owner_admin_flag) ? "1" : "0", false, buffer);
		write_token_into_buffer("object_description", row[2], false, buffer);
		write_token_into_buffer("event_description", event_description, false, buffer);
		write_token_into_buffer("date_time", row[4], false, buffer);
		write_token_into_buffer("actor_ip_address", row[5], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the transaction event log information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	disconnect_db(&db_conn);

	// Send the end of transaction event logs
	write_token_into_buffer("is_end_of_transaction_event_logs_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of transaction event logs failed\n");
		goto ERROR;
	}

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

static boolean respond_all_transaction_user_event_log(SSL *ssl_client, char *username, entity_type user_or_admin_type)
{
	MYSQL        *db_conn = NULL;
	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int actor_id;
	char         actor_name[USER_NAME_LENGTH + 1];
	char         actor_authority_name[AUTHORITY_NAME_LENGTH + 1];
	boolean      is_actor_admin_flag;

	unsigned int object_owner_id;
	char         object_owner_name[USER_NAME_LENGTH + 1];
	char         object_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	boolean      is_object_owner_admin_flag;

	char         event_description[EVENT_DESCRIPTION_LENGTH + 1];
	char         buffer[BUFFER_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for event logs
	sprintf(stat, "SELECT EVT.actor_id, EVT.object_owner_id, EVT.object_description, EVT.event_description, EVT.date_time, EVT.actor_ip_address FROM "
		"%s EVT, %s USR, %s AUT WHERE (EVT.actor_id = USR.user_id OR EVT.object_owner_id = USR.user_id OR EVT.affected_user_id = USR.user_id) "
		"AND USR.username LIKE '%s' COLLATE latin1_general_cs AND USR.is_admin_flag = '%u' AND USR.authority_id = AUT.authority_id AND "
		"AUT.authority_name LIKE '%s' COLLATE latin1_general_cs ORDER BY EVT.date_time ASC, EVT.event_log_id ASC", AS__EVENT_LOGS, AS__USERS, AS__AUTHORITIES, 
		username, (user_or_admin_type == admin) ? true : false, GLOBAL_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		actor_id = atoi(row[0]);
		object_owner_id  = atoi(row[1]);
		strcpy(event_description, row[3]);

		// Get info of actor and object owner
		if(!get_user_info(db_conn, actor_id, actor_name, actor_authority_name, &is_actor_admin_flag))
			goto ERROR;

		if(!get_user_info(db_conn, object_owner_id, object_owner_name, object_owner_authority_name, &is_object_owner_admin_flag))
			goto ERROR;

		// Filter out
		if(is_actor_admin_flag && strcmp(actor_name, username) == 0 && strstr(event_description, "access permission"))
			continue;

		if(strcmp(object_owner_name, username) == 0 && strstr(event_description, "access permission"))
			continue;

		if(strcmp(actor_authority_name, GLOBAL_authority_name) != 0 && (strcmp(object_owner_authority_name, GLOBAL_authority_name) == 0 && 
			strcmp(object_owner_name, username) == 0) && strstr(event_description, "your emergency PHR owner's restricted-level PHR"))
		{
			continue;
		}

		// Send the transaction event log information
		write_token_into_buffer("is_end_of_transaction_event_logs_flag", "0", true, buffer);
		write_token_into_buffer("actor_name", actor_name, false, buffer);
		write_token_into_buffer("actor_authority_name", actor_authority_name, false, buffer);
		write_token_into_buffer("is_actor_admin_flag", (is_actor_admin_flag) ? "1" : "0", false, buffer);
		write_token_into_buffer("object_owner_name", object_owner_name, false, buffer);
		write_token_into_buffer("object_owner_authority_name", object_owner_authority_name, false, buffer);
		write_token_into_buffer("is_object_owner_admin_flag", (is_object_owner_admin_flag) ? "1" : "0", false, buffer);
		write_token_into_buffer("object_description", row[2], false, buffer);
		write_token_into_buffer("event_description", event_description, false, buffer);
		write_token_into_buffer("date_time", row[4], false, buffer);
		write_token_into_buffer("actor_ip_address", row[5], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the transaction event log information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	disconnect_db(&db_conn);

	// Send the end of transaction event logs
	write_token_into_buffer("is_end_of_transaction_event_logs_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of transaction event logs failed\n");
		goto ERROR;
	}

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

static boolean respond_some_period_time_transaction_system_login_log(SSL *ssl_client, char *start_date_time, char *end_date_time)
{
	MYSQL     *db_conn = NULL;
	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	char      buffer[BUFFER_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for login logs
	sprintf(stat, "SELECT LGN.date_time, LGN.ip_address, LGN.is_logout_flag, USR.username, USR.is_admin_flag FROM %s LGN, %s USR WHERE "
		"LGN.user_id = USR.user_id AND (LGN.date_time >= '%s' AND LGN.date_time <= '%s') ORDER BY LGN.login_log_id ASC", 
		AS__LOGIN_LOGS, AS__USERS, start_date_time, end_date_time);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		// Send the transaction login log information
		write_token_into_buffer("is_end_of_transaction_login_logs_flag", "0", true, buffer);
		write_token_into_buffer("date_time", row[0], false, buffer);
		write_token_into_buffer("ip_address", row[1], false, buffer);
		write_token_into_buffer("is_logout_flag", row[2], false, buffer);
		write_token_into_buffer("username", row[3], false, buffer);
		write_token_into_buffer("is_admin_flag", row[4], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the transaction login log information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	disconnect_db(&db_conn);

	// Send the end of transaction login logs
	write_token_into_buffer("is_end_of_transaction_login_logs_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of transaction login logs failed\n");
		goto ERROR;
	}

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

static boolean respond_all_transaction_system_login_log(SSL *ssl_client)
{
	MYSQL     *db_conn = NULL;
	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	char      buffer[BUFFER_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for login logs
	sprintf(stat, "SELECT LGN.date_time, LGN.ip_address, LGN.is_logout_flag, USR.username, USR.is_admin_flag FROM %s LGN, %s USR WHERE "
		"LGN.user_id = USR.user_id ORDER BY LGN.login_log_id ASC", AS__LOGIN_LOGS, AS__USERS);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		// Send the transaction login log information
		write_token_into_buffer("is_end_of_transaction_login_logs_flag", "0", true, buffer);
		write_token_into_buffer("date_time", row[0], false, buffer);
		write_token_into_buffer("ip_address", row[1], false, buffer);
		write_token_into_buffer("is_logout_flag", row[2], false, buffer);
		write_token_into_buffer("username", row[3], false, buffer);
		write_token_into_buffer("is_admin_flag", row[4], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the transaction login log information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	disconnect_db(&db_conn);

	// Send the end of transaction login logs
	write_token_into_buffer("is_end_of_transaction_login_logs_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of transaction login logs failed\n");
		goto ERROR;
	}

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

static boolean respond_some_period_time_transaction_system_event_log(SSL *ssl_client, char *start_date_time, char *end_date_time)
{
	MYSQL        *db_conn = NULL;
	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int actor_id;
	char         actor_name[USER_NAME_LENGTH + 1];
	char         actor_authority_name[AUTHORITY_NAME_LENGTH + 1];
	boolean      is_actor_admin_flag;

	unsigned int object_owner_id;
	char         object_owner_name[USER_NAME_LENGTH + 1];
	char         object_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	boolean      is_object_owner_admin_flag;

	char         event_description[EVENT_DESCRIPTION_LENGTH + 1];
	char         buffer[BUFFER_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for event logs
	sprintf(stat, "SELECT distinct EVT.actor_id, EVT.object_owner_id, EVT.object_description, EVT.event_description, EVT.date_time, EVT.actor_ip_address "
		"FROM %s EVT, %s USR WHERE ((EVT.actor_id = USR.user_id AND USR.is_admin_flag = '1' AND EVT.affected_user_id = %u) OR (EVT.affected_user_id = %u)) "
		"AND (EVT.date_time >= '%s' AND EVT.date_time <= '%s') ORDER BY EVT.date_time ASC, EVT.event_log_id ASC", AS__EVENT_LOGS, AS__USERS, 	
		GLOBAL_no_reference_user_id, GLOBAL_reference_to_all_admins_id, start_date_time, end_date_time);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		actor_id = atoi(row[0]);
		object_owner_id  = atoi(row[1]);
		strcpy(event_description, row[3]);

		// Get info of actor and object owner
		if(!get_user_info(db_conn, actor_id, actor_name, actor_authority_name, &is_actor_admin_flag))
			goto ERROR;

		if(!get_user_info(db_conn, object_owner_id, object_owner_name, object_owner_authority_name, &is_object_owner_admin_flag))
			goto ERROR;

		// Filter out
		if(strcmp(event_description, ADMIN_LOGIN_LOG_AUDITING_MSG) == 0 || strcmp(event_description, ADMIN_EVENT_LOG_AUDITING_MSG) == 0)
			continue;

		if(actor_id == object_owner_id)
			continue;

		// Send the transaction event log information
		write_token_into_buffer("is_end_of_transaction_event_logs_flag", "0", true, buffer);
		write_token_into_buffer("actor_name", actor_name, false, buffer);
		write_token_into_buffer("actor_authority_name", actor_authority_name, false, buffer);
		write_token_into_buffer("is_actor_admin_flag", (is_actor_admin_flag) ? "1" : "0", false, buffer);
		write_token_into_buffer("object_owner_name", object_owner_name, false, buffer);
		write_token_into_buffer("object_owner_authority_name", object_owner_authority_name, false, buffer);
		write_token_into_buffer("is_object_owner_admin_flag", (is_object_owner_admin_flag) ? "1" : "0", false, buffer);
		write_token_into_buffer("object_description", row[2], false, buffer);
		write_token_into_buffer("event_description", event_description, false, buffer);
		write_token_into_buffer("date_time", row[4], false, buffer);
		write_token_into_buffer("actor_ip_address", row[5], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the transaction event log information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	disconnect_db(&db_conn);

	// Send the end of transaction event logs
	write_token_into_buffer("is_end_of_transaction_event_logs_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of transaction event logs failed\n");
		goto ERROR;
	}

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

static boolean respond_all_transaction_system_event_log(SSL *ssl_client)
{
	MYSQL        *db_conn = NULL;
	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int actor_id;
	char         actor_name[USER_NAME_LENGTH + 1];
	char         actor_authority_name[AUTHORITY_NAME_LENGTH + 1];
	boolean      is_actor_admin_flag;

	unsigned int object_owner_id;
	char         object_owner_name[USER_NAME_LENGTH + 1];
	char         object_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	boolean      is_object_owner_admin_flag;

	char         event_description[EVENT_DESCRIPTION_LENGTH + 1];
	char         buffer[BUFFER_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for event logs
	sprintf(stat, "SELECT distinct EVT.actor_id, EVT.object_owner_id, EVT.object_description, EVT.event_description, EVT.date_time, EVT.actor_ip_address "
		"FROM %s EVT, %s USR WHERE (EVT.actor_id = USR.user_id AND USR.is_admin_flag = '1' AND EVT.affected_user_id = %u) OR (EVT.affected_user_id = %u) "
		"ORDER BY EVT.date_time ASC, EVT.event_log_id ASC", AS__EVENT_LOGS, AS__USERS, GLOBAL_no_reference_user_id, GLOBAL_reference_to_all_admins_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		actor_id = atoi(row[0]);
		object_owner_id  = atoi(row[1]);
		strcpy(event_description, row[3]);

		// Get info of actor and object owner
		if(!get_user_info(db_conn, actor_id, actor_name, actor_authority_name, &is_actor_admin_flag))
			goto ERROR;

		if(!get_user_info(db_conn, object_owner_id, object_owner_name, object_owner_authority_name, &is_object_owner_admin_flag))
			goto ERROR;

		// Filter out
		if(strcmp(event_description, ADMIN_LOGIN_LOG_AUDITING_MSG) == 0 || strcmp(event_description, ADMIN_EVENT_LOG_AUDITING_MSG) == 0)
			continue;

		if(actor_id == object_owner_id)
			continue;

		// Send the transaction event log information
		write_token_into_buffer("is_end_of_transaction_event_logs_flag", "0", true, buffer);
		write_token_into_buffer("actor_name", actor_name, false, buffer);
		write_token_into_buffer("actor_authority_name", actor_authority_name, false, buffer);
		write_token_into_buffer("is_actor_admin_flag", (is_actor_admin_flag) ? "1" : "0", false, buffer);
		write_token_into_buffer("object_owner_name", object_owner_name, false, buffer);
		write_token_into_buffer("object_owner_authority_name", object_owner_authority_name, false, buffer);
		write_token_into_buffer("is_object_owner_admin_flag", (is_object_owner_admin_flag) ? "1" : "0", false, buffer);
		write_token_into_buffer("object_description", row[2], false, buffer);
		write_token_into_buffer("event_description", event_description, false, buffer);
		write_token_into_buffer("date_time", row[4], false, buffer);
		write_token_into_buffer("actor_ip_address", row[5], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the transaction event log information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	disconnect_db(&db_conn);

	// Send the end of transaction event logs
	write_token_into_buffer("is_end_of_transaction_event_logs_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of transaction event logs failed\n");
		goto ERROR;
	}

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
	entity_type user_or_admin_type;
	char        cert_ownername[USER_NAME_LENGTH + 1];
	char        buffer[BUFFER_LENGTH + 1];
	char        token_name[TOKEN_NAME_LENGTH + 1];
	char        request_type[REQUEST_TYPE_LENGTH + 1];
	char        audit_all_transactions_flag_str_tmp[FLAG_LENGTH + 1];
	boolean     audit_all_transactions_flag;
	char        start_date_time[DATETIME_STR_LENGTH + 1];
	char        end_date_time[DATETIME_STR_LENGTH + 1];

	// Get certificate's ownername and entity type
	get_cert_ownername(ssl_client, GLOBAL_authority_name, cert_ownername, &user_or_admin_type);

	// Receive request type information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving request type information failed\n");
		goto ERROR;
	}

	// Get request information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, request_type) != READ_TOKEN_SUCCESS || strcmp(token_name, "request_type") != 0)
	{
		int_error("Extracting the request_type failed");
	}

	if(read_token_from_buffer(buffer, 2, token_name, audit_all_transactions_flag_str_tmp) != READ_TOKEN_SUCCESS 
		|| strcmp(token_name, "audit_all_transactions_flag") != 0)
	{
		int_error("Extracting the audit_all_transactions_flag failed");
	}

	audit_all_transactions_flag = (strcmp(audit_all_transactions_flag_str_tmp, "1") == 0) ? true : false;

	if(!audit_all_transactions_flag)  // Audit some period time
	{
		if(read_token_from_buffer(buffer, 3, token_name, start_date_time) != READ_TOKEN_SUCCESS || strcmp(token_name, "start_date_time") != 0)
		{
			int_error("Extracting the start_date_time failed");
		}

		if(read_token_from_buffer(buffer, 4, token_name, end_date_time) != READ_TOKEN_SUCCESS || strcmp(token_name, "end_date_time") != 0)
		{
			int_error("Extracting the end_date_time failed");
		}
	}

	if(strcmp(request_type, USER_LOGIN_LOG_AUDITING) == 0)
	{
		// Record a transaction auditing log
		record_transaction_auditing_log(ssl_client, USER_LOGIN_LOG_AUDITING_MSG);
	}
	else if(strcmp(request_type, ADMIN_LOGIN_LOG_AUDITING) == 0)
	{
		// Record a transaction auditing log
		record_transaction_auditing_log(ssl_client, ADMIN_LOGIN_LOG_AUDITING_MSG);
	}
	else if(strcmp(request_type, SYSTEM_LOGIN_LOG_AUDITING) == 0)
	{
		// Record a transaction auditing log
		record_transaction_auditing_log(ssl_client, SYSTEM_LOGIN_LOG_AUDITING_MSG);
	}
	else if(strcmp(request_type, USER_EVENT_LOG_AUDITING) == 0)
	{
		// Record a transaction auditing log
		record_transaction_auditing_log(ssl_client, USER_EVENT_LOG_AUDITING_MSG);
	}
	else if(strcmp(request_type, ADMIN_EVENT_LOG_AUDITING) == 0)
	{
		// Record a transaction auditing log
		record_transaction_auditing_log(ssl_client, ADMIN_EVENT_LOG_AUDITING_MSG);
	}
	else if(strcmp(request_type, SYSTEM_EVENT_LOG_AUDITING) == 0)
	{
		// Record a transaction auditing log
		record_transaction_auditing_log(ssl_client, SYSTEM_EVENT_LOG_AUDITING_MSG);
	}

	// Process a request
	if(strcmp(request_type, USER_LOGIN_LOG_AUDITING) == 0 || strcmp(request_type, ADMIN_LOGIN_LOG_AUDITING) == 0)  // User and admin
	{
		if(audit_all_transactions_flag)
		{
			return respond_all_transaction_user_login_log(ssl_client, cert_ownername, user_or_admin_type);
		}
		else
		{
			return respond_some_period_time_transaction_user_login_log(ssl_client, cert_ownername, 
				user_or_admin_type, start_date_time, end_date_time);
		}
	}
	else if(strcmp(request_type, USER_EVENT_LOG_AUDITING) == 0 || strcmp(request_type, ADMIN_EVENT_LOG_AUDITING) == 0) // User and admin
	{
		if(audit_all_transactions_flag)
		{
			return respond_all_transaction_user_event_log(ssl_client, cert_ownername, user_or_admin_type);
		}
		else
		{
			return respond_some_period_time_transaction_user_event_log(ssl_client, cert_ownername, 
				user_or_admin_type, start_date_time, end_date_time);
		}
	}
	else if(strcmp(request_type, SYSTEM_LOGIN_LOG_AUDITING) == 0)  // Admin only
	{
		if(user_or_admin_type == admin)
		{
			if(audit_all_transactions_flag)
			{
				return respond_all_transaction_system_login_log(ssl_client);
			}
			else
			{
				return respond_some_period_time_transaction_system_login_log(ssl_client, start_date_time, end_date_time);
			}
		}
		else
		{
			fprintf(stderr, "Invalid certificate's entity type\n");
			goto ERROR;
		}
	}
	else if(strcmp(request_type, SYSTEM_EVENT_LOG_AUDITING) == 0)  // Admin only
	{
		if(user_or_admin_type == admin)
		{
			if(audit_all_transactions_flag)
			{
				return respond_all_transaction_system_event_log(ssl_client);
			}
			else
			{
				return respond_some_period_time_transaction_system_event_log(ssl_client, start_date_time, end_date_time);
			}
		}
		else
		{
			fprintf(stderr, "Invalid certificate's entity type\n");
			goto ERROR;
		}
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;	
}

void *transaction_log_auditing_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[2];

    	ctx = setup_server_ctx(AS_CERTFILE_PATH, AS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(AS_TRANSACTION_LOG_AUDITING_PORT);
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
    		if((err = post_connection_check(ssl_client, hosts, 2, true, GLOBAL_authority_name)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}
		
		// Process type of request
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




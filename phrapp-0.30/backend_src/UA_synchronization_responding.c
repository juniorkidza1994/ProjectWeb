#include "UA_common.h"

// Local Function Prototypes
static void get_authority_name(SSL *ssl_client, char *authority_name_ret);
static boolean authority_exists(char *authority_name, unsigned int *authority_id_ret);
static void set_authority_join_flag(unsigned int authority_id);
static boolean send_request_result(SSL *ssl_client, char *request_result);
static boolean synchronize_authority_info(SSL *ssl_client);
static boolean synchronize_attribute(MYSQL *db_conn, SSL *ssl_client);
static boolean synchronize_user(MYSQL *db_conn, SSL *ssl_client);
static boolean get_phr_ownername(MYSQL *db_conn, unsigned int phr_owner_id, char *phr_ownername_ret);
static boolean get_assigned_username(MYSQL *db_conn, unsigned int assigned_user_id, unsigned int assigned_user_authority_id, char *assigned_username_ret);
static boolean synchronize_access_permission(MYSQL *db_conn, SSL *ssl_client, unsigned int assigned_user_authority_id);
static boolean connect_to_emergency_delegation_synchronization_service(SSL **ssl_conn_ret);
static boolean synchronize_emergency_delegation(SSL *ssl_outgoing_conn, char *peer_authority_name);
static boolean connect_to_phr_transaction_log_synchronization_service(SSL **ssl_conn_ret);
static boolean synchronize_phr_transaction_log(SSL *ssl_outgoing_conn, char *syncing_authority_name);
static boolean authority_synchronization_main(SSL *ssl_client, unsigned int authority_id, char *authority_name);
static boolean process_request(SSL *ssl_client);

// Implementation
static void get_authority_name(SSL *ssl_client, char *authority_name_ret)
{
	X509      *cert    = NULL;
	X509_NAME *subject = NULL;
	char      cert_owner_info[USER_NAME_LENGTH + AUTHORITY_NAME_LENGTH + 10];

	// Get a certificate owner info from an SSL certificate
	if(!(cert = SSL_get_peer_certificate(ssl_client)))
		int_error("Getting a client's certificate failed");

	subject = X509_get_subject_name(cert);
	X509_NAME_get_text_by_NID(subject, NID_commonName, cert_owner_info, sizeof(cert_owner_info));

	strncpy(authority_name_ret, cert_owner_info, strstr(cert_owner_info, ".") - cert_owner_info);
	authority_name_ret[strstr(cert_owner_info, ".") - cert_owner_info] = 0;
}

static boolean authority_exists(char *authority_name, unsigned int *authority_id_ret)
{
	MYSQL     *db_conn = NULL;
	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char      err_msg[ERR_MSG_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for authority info
	sprintf(stat, "SELECT authority_id FROM %s WHERE authority_name LIKE '%s' COLLATE latin1_general_cs", UA__AUTHORITIES, authority_name);

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

	*authority_id_ret = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
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

static void set_authority_join_flag(unsigned int authority_id)
{
	MYSQL *db_conn = NULL;
	char  stat[SQL_STATEMENT_LENGTH + 1];
	char  err_msg[ERR_MSG_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Set the authority join flag
	sprintf(stat, "UPDATE %s SET authority_join_flag='1' WHERE authority_id=%u", UA__AUTHORITIES, authority_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	disconnect_db(&db_conn);
}

static boolean send_request_result(SSL *ssl_client, char *request_result)
{
	char buffer[BUFFER_LENGTH + 1];

	// Send the request result
	write_token_into_buffer("request_result", request_result, true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the request result failed\n");
		return false;
	}

	return true;
}

static boolean synchronize_authority_info(SSL *ssl_client)
{
	char buffer[BUFFER_LENGTH + 1];

	// Send the authority information
	write_token_into_buffer("emergency_server_ip_addr", GLOBAL_emergency_server_ip_addr, true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the authority information failed\n");
		return false;
	}

	return true;
}

static boolean synchronize_attribute(MYSQL *db_conn, SSL *ssl_client)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char      err_msg[ERR_MSG_LENGTH + 1];
	char      buffer[BUFFER_LENGTH + 1];	

	// Query for the attribute list of current authority
	sprintf(stat, "SELECT attribute_name, is_numerical_attribute_flag FROM %s WHERE authority_id = %u", UA__ATTRIBUTES, GLOBAL_authority_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		// Send the attribute information
		write_token_into_buffer("is_end_of_attribute_list_flag", "0", true, buffer);
		write_token_into_buffer("attribute_name", row[0], false, buffer);
		write_token_into_buffer("is_numerical_attribute_flag", row[1], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the attribute information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Send the end of attribute list
	write_token_into_buffer("is_end_of_attribute_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of attribute list failed\n");
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

static boolean synchronize_user(MYSQL *db_conn, SSL *ssl_client)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char      err_msg[ERR_MSG_LENGTH + 1];
	char      buffer[LARGE_BUFFER_LENGTH + 1];	

	// Query for the user list of current authority
	sprintf(stat, "SELECT username, email_address, ssl_pub_key FROM %s", UA__USERS);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		// Send the user information
		write_token_into_buffer("is_end_of_user_list_flag", "0", true, buffer);
		write_token_into_buffer("username", row[0], false, buffer);
		write_token_into_buffer("email_address", row[1], false, buffer);
		write_token_into_buffer("ssl_pub_key", row[2], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Send the end of user list
	write_token_into_buffer("is_end_of_user_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of user list failed\n");
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

static boolean get_phr_ownername(MYSQL *db_conn, unsigned int phr_owner_id, char *phr_ownername_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Query for the PHR ownername
	sprintf(stat, "SELECT username FROM %s WHERE user_id = %u", UA__USERS, phr_owner_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		fprintf(stderr, "Getting a PHR ownername from a database failed\n");
		goto ERROR;
	}

	strcpy(phr_ownername_ret, row[0]);

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

static boolean get_assigned_username(MYSQL *db_conn, unsigned int assigned_user_id, unsigned int assigned_user_authority_id, char *assigned_username_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Query for the assigned username
	sprintf(stat, "SELECT username FROM %s WHERE user_id = %u AND authority_id = %u", UA__USERS_IN_OTHER_AUTHORITIES, assigned_user_id, assigned_user_authority_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		fprintf(stderr, "Getting an assigned username from a database failed\n");
		goto ERROR;
	}

	strcpy(assigned_username_ret, row[0]);

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

static boolean synchronize_access_permission(MYSQL *db_conn, SSL *ssl_client, unsigned int assigned_user_authority_id)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int phr_owner_id;
	unsigned int assigned_user_id;
	char         phr_ownername[USER_NAME_LENGTH + 1];
	char         assigned_username[USER_NAME_LENGTH + 1];
	char         buffer[BUFFER_LENGTH + 1];

	// Query the access permission list that assigned to desired authority's users
	sprintf(stat, "SELECT user_id, object_user_id, upload_permission_flag, download_permission_flag, delete_permission_flag FROM %s "
		"WHERE object_user_authority_id = %u", UA__PERMISSIONS_ASSIGNED_TO_OTHERS, assigned_user_authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		phr_owner_id     = atoi(row[0]);
		assigned_user_id = atoi(row[1]);

		if(!get_phr_ownername(db_conn, phr_owner_id, phr_ownername))
			continue;
		
		if(!get_assigned_username(db_conn, assigned_user_id, assigned_user_authority_id, assigned_username))
			continue;

		// Send the assigned access permission information
		write_token_into_buffer("is_end_of_assigned_access_permission_list_flag", "0", true, buffer);
		write_token_into_buffer("assigned_username", assigned_username, false, buffer);
		write_token_into_buffer("phr_ownername", phr_ownername, false, buffer);
		write_token_into_buffer("upload_permission_flag", row[2], false, buffer);
		write_token_into_buffer("download_permission_flag", row[3], false, buffer);
		write_token_into_buffer("delete_permission_flag", row[4], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the assigned access permission information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Send the end of assigned access permission list
	write_token_into_buffer("is_end_of_assigned_access_permission_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of assigned access permission list failed\n");
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

static boolean connect_to_emergency_delegation_synchronization_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    emergency_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to Emergency Server
	sprintf(emergency_server_addr, "%s:%s", GLOBAL_emergency_server_ip_addr, EMS_DELEGATION_SYNCHRONIZATION_RESPONDING_PORT);
	bio_conn = BIO_new_connect(emergency_server_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		fprintf(stderr, "Connecting to emergency server failed\n");
		goto ERROR_AT_BIO_LAYER;
	}

	ctx = setup_client_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
	if(!(*ssl_conn_ret = SSL_new(ctx)))
            	int_error("Creating SSL context failed");
 
    	SSL_set_bio(*ssl_conn_ret, bio_conn, bio_conn);
    	if(SSL_connect(*ssl_conn_ret) <= 0)
	{
        	fprintf(stderr, "Connecting SSL object failed\n");
		goto ERROR_AT_SSL_LAYER;
	}

	hosts[0] = EMERGENCY_SERVER_CN;
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, true, GLOBAL_authority_name)) != X509_V_OK)
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

static boolean synchronize_emergency_delegation(SSL *ssl_outgoing_conn, char *peer_authority_name)
{
	SSL     *ssl_incoming_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    sync_flag_str_tmp[FLAG_LENGTH + 1];
	boolean sync_flag;

	char    is_end_of_peer_phr_owner_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_peer_phr_owner_list_flag;

	char    is_end_of_peer_trusted_user_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_peer_trusted_user_list_flag;

	// Receive the sync flag
	if(SSL_recv_buffer(ssl_outgoing_conn, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the syncing flag failed\n");
		goto ERROR;
	}

	// Get the syncing flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, sync_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "sync_flag") != 0)
	{
		int_error("Extracting the sync_flag failed");
	}

	sync_flag = (strcmp(sync_flag_str_tmp, "1") == 0) ? true : false;
	if(!sync_flag)
	{
		goto ERROR;
	}

	// Connect to Emergency Server
	if(!connect_to_emergency_delegation_synchronization_service(&ssl_incoming_conn))
	{
		// Send the sync flag
		write_token_into_buffer("sync_flag", "0", true, buffer);
		if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the sync flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Send the sync flag
	write_token_into_buffer("sync_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the sync flag failed\n");
		goto ERROR;
	}

	// Send the peer authority name
	write_token_into_buffer("peer_authority_name", peer_authority_name, true, buffer);
	if(!SSL_send_buffer(ssl_incoming_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the peer authority name failed\n");
		goto ERROR;
	}

	// Peer PHR owner list
	while(1)
	{
		// Receive the peer PHR owner information
		if(SSL_recv_buffer(ssl_incoming_conn, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving the peer PHR owner information failed\n");
			goto ERROR;
		}

		// Get the "is_end_of_peer_phr_owner_list_flag" token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_peer_phr_owner_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_peer_phr_owner_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_peer_phr_owner_list_flag failed");
		}

		is_end_of_peer_phr_owner_list_flag = (strcmp(is_end_of_peer_phr_owner_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_peer_phr_owner_list_flag)
			break;

		// Forward the packet to emergency server
		if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Forwarding the peer PHR owner information failed\n");
			goto ERROR;
		}
	}

	// Forward the last packet to emergency server
	if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Forwarding the peer PHR owner information failed\n");
		goto ERROR;
	}

	// Peer trusted user list
	while(1)
	{
		// Receive the peer trusted user information
		if(SSL_recv_buffer(ssl_incoming_conn, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving the peer trusted user information failed\n");
			goto ERROR;
		}

		// Get the "is_end_of_peer_trusted_user_list_flag" token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_peer_trusted_user_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_peer_trusted_user_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_peer_trusted_user_list_flag failed");
		}

		is_end_of_peer_trusted_user_list_flag = (strcmp(is_end_of_peer_trusted_user_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_peer_trusted_user_list_flag)
			break;

		// Forward the packet to emergency server
		if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Forwarding the peer trusted user information failed\n");
			goto ERROR;
		}
	}

	// Forward the last packet to emergency server
	if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Forwarding the peer trusted user information failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_incoming_conn);
	ssl_incoming_conn = NULL;
	return true;

ERROR:

	if(ssl_incoming_conn)
	{
		SSL_cleanup(ssl_incoming_conn);
		ssl_incoming_conn = NULL;
	}

	return false;
}

static boolean connect_to_phr_transaction_log_synchronization_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    audit_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to Audit Server
	sprintf(audit_server_addr, "%s:%s", GLOBAL_audit_server_ip_addr, AS_PHR_TRANSACTION_LOG_SYNCHRONIZATION_PORT);
	bio_conn = BIO_new_connect(audit_server_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		fprintf(stderr, "Connecting to audit server failed\n");
		goto ERROR_AT_BIO_LAYER;
	}

	ctx = setup_client_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
	if(!(*ssl_conn_ret = SSL_new(ctx)))
            	int_error("Creating SSL context failed");
 
    	SSL_set_bio(*ssl_conn_ret, bio_conn, bio_conn);
    	if(SSL_connect(*ssl_conn_ret) <= 0)
	{
        	fprintf(stderr, "Connecting SSL object failed\n");
		goto ERROR_AT_SSL_LAYER;
	}

	hosts[0] = AUDIT_SERVER_CN;
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, true, GLOBAL_authority_name)) != X509_V_OK)
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

static boolean synchronize_phr_transaction_log(SSL *ssl_outgoing_conn, char *syncing_authority_name)
{
	SSL     *ssl_incoming_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    sync_flag_str_tmp[FLAG_LENGTH + 1];
	boolean sync_flag;

	char    is_end_of_phr_transaction_logs_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_phr_transaction_logs_flag;

	// Receive the sync flag
	if(SSL_recv_buffer(ssl_outgoing_conn, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the syncing flag failed\n");
		goto ERROR;
	}

	// Get the syncing flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, sync_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "sync_flag") != 0)
	{
		int_error("Extracting the sync_flag failed");
	}

	sync_flag = (strcmp(sync_flag_str_tmp, "1") == 0) ? true : false;
	if(!sync_flag)
	{
		goto ERROR;
	}

	// Connect to Audit Server
	if(!connect_to_phr_transaction_log_synchronization_service(&ssl_incoming_conn))
	{
		// Send the sync flag
		write_token_into_buffer("sync_flag", "0", true, buffer);
		if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the sync flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Send the sync flag
	write_token_into_buffer("sync_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the sync flag failed\n");
		goto ERROR;
	}

	// Send the syncing authority name
	write_token_into_buffer("syncing_authority_name", syncing_authority_name, true, buffer);
	if(!SSL_send_buffer(ssl_incoming_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the syncing authority name failed\n");
		goto ERROR;
	}

	while(1)
	{
		// Receive PHR transaction log information
		if(SSL_recv_buffer(ssl_incoming_conn, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving PHR transaction log information failed\n");
			goto ERROR;
		}

		// Get the "is_end_of_phr_transaction_logs_flag" token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_phr_transaction_logs_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_phr_transaction_logs_flag") != 0)
		{
			int_error("Extracting the is_end_of_phr_transaction_logs_flag failed");
		}

		is_end_of_phr_transaction_logs_flag = (strcmp(is_end_of_phr_transaction_logs_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_phr_transaction_logs_flag)
			break;

		// Forward the packet to the syncing user authority
		if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Forwarding the PHR transaction log information failed\n");
			goto ERROR;
		}
	}

	// Forward the last packet to the syncing user authority
	if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Forwarding the PHR transaction log information failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_incoming_conn);
	ssl_incoming_conn = NULL;
	return true;

ERROR:

	if(ssl_incoming_conn)
	{
		SSL_cleanup(ssl_incoming_conn);
		ssl_incoming_conn = NULL;
	}

	return false;
}

static boolean authority_synchronization_main(SSL *ssl_client, unsigned int authority_id, char *authority_name)
{
	MYSQL *db_conn = NULL;

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	if(!synchronize_authority_info(ssl_client))
		goto ERROR;

	if(!synchronize_attribute(db_conn, ssl_client))
		goto ERROR;

	if(!synchronize_user(db_conn, ssl_client))
		goto ERROR;

	if(!synchronize_access_permission(db_conn, ssl_client, authority_id))
		goto ERROR;

	if(!synchronize_emergency_delegation(ssl_client, authority_name))
		goto ERROR;

	if(!synchronize_phr_transaction_log(ssl_client, authority_name))
		goto ERROR;

	disconnect_db(&db_conn);
	return true;

ERROR:

	disconnect_db(&db_conn);
	return false;
}

static boolean process_request(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         request[REQUEST_TYPE_LENGTH + 1];

	char         authority_name[AUTHORITY_NAME_LENGTH + 1];
	unsigned int authority_id;

	// Receive the request information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the request information failed\n");
		return false;
	}

	if(read_token_from_buffer(buffer, 1, token_name, request) != READ_TOKEN_SUCCESS || strcmp(token_name, "request") != 0)
	{
		int_error("Extracting the request failed");
	}

	// Get the authority name
	get_authority_name(ssl_client, authority_name);
printf("[RES]auth %s\n", authority_name);

	// Process the request
	if(strcmp(request, AUTHORITY_JOINING_REQUESTING) == 0)
	{
printf("[RES]join msg");
		if(authority_exists(authority_name, &authority_id))
		{
printf(" -> join approve\n\n");
			set_authority_join_flag(authority_id);
			if(!send_request_result(ssl_client, AUTHORITY_JOINING_APPROVAL))
				goto ERROR;

			if(!authority_synchronization_main(ssl_client, authority_id, authority_name))
				goto ERROR;
		}
		else
		{
printf(" -> join not approve\n\n");
			if(!send_request_result(ssl_client, AUTHORITY_JOINING_NO_APPROVAL))
				goto ERROR;
		}
	}
	else if(strcmp(request, AUTHORITY_SYNCHRONIZATION_REQUESTING) == 0)
	{
printf("[RES]sync msg");
		if(authority_exists(authority_name, &authority_id))
		{
printf(" -> sync approve\n\n");
			if(!send_request_result(ssl_client, AUTHORITY_SYNCHRONIZATION_APPROVAL))
				goto ERROR;

			if(!authority_synchronization_main(ssl_client, authority_id, authority_name))
				goto ERROR;
		}
		else
		{
printf(" -> sync not approve\n\n");
			if(!send_request_result(ssl_client, AUTHORITY_REVOCATION))
				goto ERROR;
		}
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

	return true;

ERROR:

	return false;
}

void *synchronization_responding_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *host[1];

    	ctx = setup_server_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(UA_SYNCHRONIZATION_RESPONDING_PORT);
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

		host[0] = USER_AUTH_CN; 
    		if((err = post_connection_check(ssl_client, host, 1, false, NULL)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Process the request
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




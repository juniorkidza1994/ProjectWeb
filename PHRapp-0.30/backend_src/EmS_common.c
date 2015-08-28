#include "EmS_common.h"

// Implementation
boolean connect_to_transaction_log_recording_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    audit_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to Audit Server
	sprintf(audit_server_addr, "%s:%s", GLOBAL_audit_server_ip_addr, AS_TRANSACTION_LOG_RECORDING_PORT);
	bio_conn = BIO_new_connect(audit_server_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		fprintf(stderr, "Connecting to audit server failed\n");
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

boolean get_authority_id(MYSQL *db_conn, char *authority_name, unsigned int *authority_id_ret)
{
  	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char      err_msg[ERR_MSG_LENGTH + 1];

	// Query the authority id
	sprintf(stat, "SELECT authority_id FROM %s WHERE authority_name LIKE '%s' COLLATE latin1_general_cs", EMS__AUTHORITIES, authority_name);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	// An authority name does not exist in database
	if(!row)
	{
		goto NOT_FOUND;
	}

	*authority_id_ret = atoi(row[0]);
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

	*authority_id_ret = 0;
	return false;
}

boolean get_user_id(MYSQL *db_conn, char *username, char *authority_name, unsigned int *user_id_ret)
{
  	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int authority_id;

	if(!get_authority_id(db_conn, authority_name, &authority_id))
	{
		goto NOT_FOUND;
	}

	// Query the user id
	sprintf(stat, "SELECT user_id FROM %s WHERE authority_id = %u AND username LIKE '%s' COLLATE latin1_general_cs", EMS__USERS, authority_id, username);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	// A username does not exist in database
	if(!row)
	{
		goto NOT_FOUND;
	}

	*user_id_ret = atoi(row[0]);
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

	*user_id_ret = 0;
	return false;
}

// If authority name does not exist then add it and return its id
unsigned int get_authority_id_if_not_exist_create(MYSQL *db_conn, char *authority_name)
{
  	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int authority_id;

	// Query the authority id
	sprintf(stat, "SELECT authority_id FROM %s WHERE authority_name LIKE '%s' COLLATE latin1_general_cs", EMS__AUTHORITIES, authority_name);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	// An authority name does not exist in database then insert it and get its id
	if(!row)
	{
		if(result)
		{
			mysql_free_result(result);
			result = NULL;
		}

		// Insert authority name and get its id
		sprintf(stat, "INSERT INTO %s(authority_name) VALUES('%s')", EMS__AUTHORITIES, authority_name);
		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

		// Query the authority id
		sprintf(stat, "SELECT authority_id FROM %s WHERE authority_name LIKE '%s' COLLATE latin1_general_cs", EMS__AUTHORITIES, authority_name);
		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

	  	result = mysql_store_result(db_conn);
	  	row = mysql_fetch_row(result);

		if(!row)
			int_error("Getting an authority id from the database failed");
	}

	authority_id = atoi(row[0]);
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return authority_id;
}

// If username does not exist then add it and return its id
unsigned int get_user_id_if_not_exist_create(MYSQL *db_conn, char *username, char *authority_name)
{
  	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int authority_id;
	unsigned int user_id;

	authority_id = get_authority_id_if_not_exist_create(db_conn, authority_name);

	// Query the user id
	sprintf(stat, "SELECT user_id FROM %s WHERE authority_id = %u AND username LIKE '%s' COLLATE latin1_general_cs", EMS__USERS, authority_id, username);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	// A username does not exist in database then insert it and get its id
	if(!row)
	{
		if(result)
		{
			mysql_free_result(result);
			result = NULL;
		}

		// Insert user information and get its id
		sprintf(stat, "INSERT INTO %s(authority_id, username) VALUES(%u, '%s')", EMS__USERS, authority_id, username);
		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

		// Query the user id
		sprintf(stat, "SELECT user_id FROM %s WHERE authority_id = %u AND username LIKE '%s' COLLATE latin1_general_cs", EMS__USERS, authority_id, username);
		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

	  	result = mysql_store_result(db_conn);
	  	row = mysql_fetch_row(result);

		if(!row)
			int_error("Getting a user id from the database failed");
	}

	user_id = atoi(row[0]);
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return user_id;
}

// "user_authority_name_ret" or "username_ret" or both of them can be NULL
boolean get_user_info(MYSQL *db_conn, unsigned int user_id, char *user_authority_name_ret, char *username_ret)
{
	if(user_authority_name_ret == NULL && username_ret == NULL)
		return true;

	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char      err_msg[ERR_MSG_LENGTH + 1];

	// Query for the username and authority name
	sprintf(stat, "SELECT USR.username, AUT.authority_name FROM %s USR, %s AUT WHERE USR.user_id = %u AND USR.authority_id = AUT.authority_id", 
		EMS__USERS, EMS__AUTHORITIES, user_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		goto NOT_FOUND;
	}

	if(username_ret)
	{
		strcpy(username_ret, row[0]);
	}

	if(user_authority_name_ret)
	{
		strcpy(user_authority_name_ret, row[1]);
	}

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

boolean connect_to_emergency_address_serving_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    user_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to User Authority
	sprintf(user_auth_addr, "%s:%s", GLOBAL_user_auth_ip_addr, UA_EMERGENCY_ADDRESS_SERVING_PORT);
	bio_conn = BIO_new_connect(user_auth_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		fprintf(stderr, "Connecting to user authority failed\n");
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

	hosts[0] = USER_AUTH_CN;
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

boolean get_remote_emergency_server_ip_addr(char *phr_owner_authority_name, char *remote_emergency_server_ip_addr_ret)
{
	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    remote_emergency_server_addr_requesting_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean remote_emergency_server_addr_requesting_result_flag;

	// Connect to User Authority
	if(!connect_to_emergency_address_serving_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", REMOTE_EMERGENCY_SERVER_ADDR_REQUESTING, true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending request information failed\n");
		goto ERROR;
	}

	// Send the desired authority name
	write_token_into_buffer("desired_authority_name", phr_owner_authority_name, true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the desired authority name failed\n");
		goto ERROR;
	}

	// Receive the remote_emergency_server_addr_requesting_result_flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the remote_emergency_server_addr_requesting_result_flag failed\n");
		goto ERROR;
	}

	// Get the remote_emergency_server_addr_requesting_result_flag tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, remote_emergency_server_addr_requesting_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "remote_emergency_server_addr_requesting_result_flag") != 0)
	{
		int_error("Extracting the remote_emergency_server_addr_requesting_result_flag failed");
	}

	remote_emergency_server_addr_requesting_result_flag = atoi(remote_emergency_server_addr_requesting_result_flag_str_tmp);
	if(!remote_emergency_server_addr_requesting_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, error_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		fprintf(stderr, "%s\n", error_msg);
		goto ERROR;
	}

	if(read_token_from_buffer(buffer, 2, token_name, remote_emergency_server_ip_addr_ret) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "remote_emergency_server_ip_addr") != 0)
	{
		int_error("Extracting the remote_emergency_server_ip_addr failed");
	}

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return true;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;
}

boolean check_trusted_user_had_deduction_this_request(MYSQL *db_conn, unsigned int trusted_user_id, unsigned int phr_request_id)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char      err_msg[ERR_MSG_LENGTH + 1];

	boolean   took_deduction_flag = false;

	// Query for the approval status on the specific request
	sprintf(stat, "SELECT trusted_user_id FROM %s WHERE phr_request_id = %u AND trusted_user_id = %u", EMS__SECRET_KEY_APPROVALS, phr_request_id, trusted_user_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	took_deduction_flag = (row) ? true : false;

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return took_deduction_flag;
}

boolean get_access_request_id(MYSQL *db_conn, unsigned int remote_site_phr_id, char *emergency_staff_name, char *emergency_unit_name, unsigned int *phr_request_id_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char      err_msg[ERR_MSG_LENGTH + 1];

	boolean   found_flag = false;

	// Query for the phr_request_id of the request on the requested restricted-level PHR of the specific emergency staff
	sprintf(stat, "SELECT phr_request_id FROM %s WHERE remote_site_phr_id = %u AND emergency_unit_name LIKE '%s' COLLATE latin1_general_cs "
		"AND emergency_staff_name LIKE '%s' COLLATE latin1_general_cs", EMS__RESTRICTED_LEVEL_PHR_REQUESTS, remote_site_phr_id, 
		emergency_unit_name, emergency_staff_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(row)
	{
		*phr_request_id_ret = atoi(row[0]);
		found_flag          = true;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return found_flag;
}

boolean check_access_request_existence(MYSQL *db_conn, unsigned int remote_site_phr_id, char *emergency_staff_name, char *emergency_unit_name)
{
	unsigned int phr_request_id;
	return get_access_request_id(db_conn, remote_site_phr_id, emergency_staff_name, emergency_unit_name, &phr_request_id);
}




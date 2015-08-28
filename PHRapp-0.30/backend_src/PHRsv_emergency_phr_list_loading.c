#include "PHRsv_common.h"

// Local Function Prototypes
static boolean respond_emergency_phr_list_loading(SSL *ssl_client);
static boolean respond_requested_restricted_phr_info_loading(SSL *ssl_client);
static boolean respond_only_restricted_phr_list_loading(SSL *ssl_client);
static boolean process_request(SSL *ssl_client);

// Implementation
static boolean respond_emergency_phr_list_loading(SSL *ssl_client)
{
	char      buffer[BUFFER_LENGTH + 1];
	char      token_name[TOKEN_NAME_LENGTH + 1];
	char      phr_ownername[USER_NAME_LENGTH + 1];
	char      phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];

	MYSQL     *db_conn = NULL;
	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Receive the emergency PHR loading information
	if(!SSL_recv_buffer(ssl_client, buffer, NULL))
	{
		fprintf(stderr, "Receiving the emergency PHR loading information failed\n");
		goto ERROR;
	}

	// Get emergency PHR loading information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		int_error("Extracting the phr_ownername failed");

	if(read_token_from_buffer(buffer, 2, token_name, phr_owner_authority_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "phr_owner_authority_name") != 0)
	{
		int_error("Extracting the phr_owner_authority_name failed");
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for secure-level PHR list of desired PHR owner
	sprintf(stat, "SELECT DATA.phr_id, DATA.data_description, DATA.file_size FROM %s DATA, %s OWN, %s AUT WHERE "
		"DATA.phr_owner_id = OWN.phr_owner_id AND OWN.username LIKE '%s' COLLATE latin1_general_cs AND OWN.authority_id = AUT.authority_id "
		"AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND DATA.hidden_flag = '0' AND DATA.phr_conf_level_flag = '%s'", PHRSV__DATA, 
		PHRSV__PHR_OWNERS, PHRSV__AUTHORITIES, phr_ownername, phr_owner_authority_name, PHR_SECURE_LEVEL_FLAG);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		// Send the secure-level PHR information
		write_token_into_buffer("is_end_of_secure_phr_list_flag", "0", true, buffer);
		write_token_into_buffer("phr_id", row[0], false, buffer);
		write_token_into_buffer("data_description", row[1], false, buffer);
		write_token_into_buffer("file_size", row[2], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the secure-level PHR information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Send the end of secure-level PHR list
	write_token_into_buffer("is_end_of_secure_phr_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of secure-level PHR list failed\n");
		goto ERROR;
	}

	// Query for restricted-level PHR list of desired PHR owner
	sprintf(stat, "SELECT DATA.phr_id, DATA.data_description, DATA.file_size FROM %s DATA, %s OWN, %s AUT WHERE "
		"DATA.phr_owner_id = OWN.phr_owner_id AND OWN.username LIKE '%s' COLLATE latin1_general_cs AND OWN.authority_id = AUT.authority_id "
		"AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND DATA.hidden_flag = '0' AND DATA.phr_conf_level_flag = '%s'", PHRSV__DATA, 
		PHRSV__PHR_OWNERS, PHRSV__AUTHORITIES, phr_ownername, phr_owner_authority_name, PHR_RESTRICTED_LEVEL_FLAG);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		// Send the restricted-level PHR information
		write_token_into_buffer("is_end_of_restricted_phr_list_flag", "0", true, buffer);
		write_token_into_buffer("phr_id", row[0], false, buffer);
		write_token_into_buffer("data_description", row[1], false, buffer);
		write_token_into_buffer("file_size", row[2], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted-level PHR information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);

	// Send the end of restricted-level PHR list
	write_token_into_buffer("is_end_of_restricted_phr_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of restricted-level PHR list failed\n");
		goto ERROR;
	}

	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(db_conn)
	{
		disconnect_db(&db_conn);
		db_conn = NULL;
	}

	return false;	
}

static boolean respond_requested_restricted_phr_info_loading(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	char         is_end_of_getting_restricted_phr_information_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      is_end_of_getting_restricted_phr_information_flag;

	char         phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int phr_id;

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	while(1)
	{
		// Receive the restricted-level PHR request information
		if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving the restricted-level PHR request information failed\n");
			goto ERROR;
		}		

		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_getting_restricted_phr_information_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_getting_restricted_phr_information_flag") != 0)
		{
			int_error("Extracting the is_end_of_getting_restricted_phr_information_flag failed");
		}

		is_end_of_getting_restricted_phr_information_flag = (strcmp(is_end_of_getting_restricted_phr_information_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_getting_restricted_phr_information_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, phr_id_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_id") != 0)
		{
			int_error("Extracting the phr_id failed");
		}

		phr_id = atoi(phr_id_str_tmp);

		// Query for restricted-level PHR information corresponding to the phr_id
		sprintf(stat, "SELECT OWN.username, DATA.data_description, DATA.file_size FROM %s DATA, %s OWN WHERE "
			"DATA.phr_id = %u AND DATA.phr_owner_id = OWN.phr_owner_id", PHRSV__DATA, PHRSV__PHR_OWNERS, phr_id);

		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

	  	result = mysql_store_result(db_conn);
		row    = mysql_fetch_row(result);

		if(!row)  // Not found
		{
			// Send the restricted_phr_information_requesting_result_flag
			write_token_into_buffer("restricted_phr_information_requesting_result_flag", "0", true, buffer);

			if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
			{
				fprintf(stderr, "Sending the restricted_phr_information_requesting_result_flag failed\n");
				goto ERROR;
			}
		}
		else  // Found
		{
			// Send the restricted-level PHR information
			write_token_into_buffer("restricted_phr_information_requesting_result_flag", "1", true, buffer);
			write_token_into_buffer("phr_ownername", row[0], false, buffer);
			write_token_into_buffer("data_description", row[1], false, buffer);
			write_token_into_buffer("file_size", row[2], false, buffer);

			if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
			{
				fprintf(stderr, "Sending the restricted-level PHR information failed\n");
				goto ERROR;
			}
		}

		if(result)
		{
			mysql_free_result(result);
			result = NULL;
		}
	}

	disconnect_db(&db_conn);
	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(db_conn)
	{
		disconnect_db(&db_conn);
		db_conn = NULL;
	}

	return false;
}

static boolean respond_only_restricted_phr_list_loading(SSL *ssl_client)
{
	char      buffer[BUFFER_LENGTH + 1];
	char      token_name[TOKEN_NAME_LENGTH + 1];
	char      phr_ownername[USER_NAME_LENGTH + 1];
	char      phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];

	MYSQL     *db_conn = NULL;
	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Receive the restricted-level PHR loading information
	if(!SSL_recv_buffer(ssl_client, buffer, NULL))
	{
		fprintf(stderr, "Receiving the restricted-level PHR loading information failed\n");
		goto ERROR;
	}

	// Get restricted-level PHR loading information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		int_error("Extracting the phr_ownername failed");

	if(read_token_from_buffer(buffer, 2, token_name, phr_owner_authority_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "phr_owner_authority_name") != 0)
	{
		int_error("Extracting the phr_owner_authority_name failed");
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for restricted-level PHR list of desired PHR owner
	sprintf(stat, "SELECT DATA.phr_id, DATA.data_description, DATA.file_size FROM %s DATA, %s OWN, %s AUT WHERE "
		"DATA.phr_owner_id = OWN.phr_owner_id AND OWN.username LIKE '%s' COLLATE latin1_general_cs AND OWN.authority_id = AUT.authority_id "
		"AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND DATA.hidden_flag = '0' AND DATA.phr_conf_level_flag = '%s'", PHRSV__DATA, 
		PHRSV__PHR_OWNERS, PHRSV__AUTHORITIES, phr_ownername, phr_owner_authority_name, PHR_RESTRICTED_LEVEL_FLAG);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		// Send the restricted-level PHR information
		write_token_into_buffer("is_end_of_restricted_phr_list_flag", "0", true, buffer);
		write_token_into_buffer("phr_id", row[0], false, buffer);
		write_token_into_buffer("data_description", row[1], false, buffer);
		write_token_into_buffer("file_size", row[2], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the restricted-level PHR information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);

	// Send the end of restricted-level PHR list
	write_token_into_buffer("is_end_of_restricted_phr_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of restricted-level PHR list failed\n");
		goto ERROR;
	}

	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

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

	if(strcmp(request, EMERGENCY_PHR_LIST_LOADING) == 0)
	{
		return respond_emergency_phr_list_loading(ssl_client);
	}
	else if(strcmp(request, REQUESTED_RESTRICTED_LEVEL_PHR_INFO_LOADING) == 0)
	{
		return respond_requested_restricted_phr_info_loading(ssl_client);
	}
	else if(strcmp(request, ONLY_RESTRICTED_LEVEL_PHR_LIST_LOADING) == 0)
	{
		return respond_only_restricted_phr_list_loading(ssl_client);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *emergency_phr_list_loading_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *host[1];

    	ctx = setup_server_ctx(PHRSV_CERTFILE_PATH, PHRSV_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(PHRSV_EMERGENCY_PHR_LIST_LOADING_PORT);
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

		host[0] = EMERGENCY_SERVER_CN; 
    		if((err = post_connection_check(ssl_client, host, 1, false, NULL)) != X509_V_OK)
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




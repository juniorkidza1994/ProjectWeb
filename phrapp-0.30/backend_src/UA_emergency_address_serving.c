#include "UA_common.h"

// Local Function Prototypes
static boolean respond_remote_emergency_server_address_requesting(SSL *ssl_client);
static boolean respond_emergency_user_email_address_requesting(SSL *ssl_client);
static boolean process_request(SSL *ssl_client);

// Implementation
static boolean respond_remote_emergency_server_address_requesting(SSL *ssl_client)
{
	char      buffer[BUFFER_LENGTH + 1];
	char      token_name[TOKEN_NAME_LENGTH + 1];

	char      desired_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char      desired_emergency_server_ip_addr[IP_ADDRESS_LENGTH + 1];

	MYSQL     *db_conn = NULL;
  	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Receive the desired authority name
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the desired authority name failed\n");
		goto ERROR;
	}

	// Get the desired authority name token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, desired_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "desired_authority_name") != 0)
	{
		int_error("Extracting the desired_authority_name failed");
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query the desired IP address from database
	sprintf(stat, "SELECT emergency_server_ip_addr FROM %s WHERE authority_name LIKE '%s' COLLATE latin1_general_cs", UA__AUTHORITIES, desired_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		// Send the remote_emergency_server_addr_requesting_result_flag
		write_token_into_buffer("remote_emergency_server_addr_requesting_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Do not found the authority name", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the remote_emergency_server_addr_requesting_result_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	strcpy(desired_emergency_server_ip_addr, row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	disconnect_db(&db_conn);

	// Send the remote_emergency_server_addr_requesting_result_flag
	write_token_into_buffer("remote_emergency_server_addr_requesting_result_flag", "1", true, buffer);
	write_token_into_buffer("remote_emergency_server_ip_addr", desired_emergency_server_ip_addr, false, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the remote emergency server address failed\n");
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

static boolean respond_emergency_user_email_address_requesting(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	char         is_end_of_getting_emergency_user_email_address_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      is_end_of_getting_emergency_user_email_address_flag;

	char         desired_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         desired_username[USER_NAME_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	while(1)
	{
		// Receive the emergency user's email address request information
		if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving the emergency user's email address request information failed\n");
			goto ERROR;
		}		

		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_getting_emergency_user_email_address_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_getting_emergency_user_email_address_flag") != 0)
		{
			int_error("Extracting the is_end_of_getting_emergency_user_email_address_flag failed");
		}

		is_end_of_getting_emergency_user_email_address_flag = (strcmp(is_end_of_getting_emergency_user_email_address_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_getting_emergency_user_email_address_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, desired_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "desired_authority_name") != 0)
		{
			int_error("Extracting the desired_authority_name failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, desired_username) != READ_TOKEN_SUCCESS || strcmp(token_name, "desired_username") != 0)
		{
			int_error("Extracting the desired_username failed");
		}

		// Query for the disired user's email address
		if(strcmp(desired_authority_name, GLOBAL_authority_name) == 0)  // Current authority
		{
			sprintf(stat, "SELECT email_address FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, desired_username);
		}
		else  // Another authority
		{
			sprintf(stat, "SELECT UOA.email_address FROM %s UOA, %s AUT WHERE UOA.username LIKE '%s' COLLATE latin1_general_cs AND "
				"UOA.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs", 
				UA__USERS_IN_OTHER_AUTHORITIES, UA__AUTHORITIES, desired_username, desired_authority_name);
		}

		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

	  	result = mysql_store_result(db_conn);
		row    = mysql_fetch_row(result);

		if(!row)  // Not found
		{
			// Send the emergency_user_email_addr_requesting_result_flag
			write_token_into_buffer("emergency_user_email_addr_requesting_result_flag", "0", true, buffer);

			if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
			{
				fprintf(stderr, "Sending the emergency_user_email_addr_requesting_result_flag failed\n");
				goto ERROR;
			}
		}
		else  // Found
		{
			// Send the emergency user's email address
			write_token_into_buffer("emergency_user_email_addr_requesting_result_flag", "1", true, buffer);
			write_token_into_buffer("emergency_user_email_address", row[0], false, buffer);

			if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
			{
				fprintf(stderr, "Sending the emergency user's email address failed\n");
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
	{
		int_error("Extracting the request failed");
	}

	if(strcmp(request, REMOTE_EMERGENCY_SERVER_ADDR_REQUESTING) == 0)
	{
		return respond_remote_emergency_server_address_requesting(ssl_client);
	}
	else if(strcmp(request, EMERGENCY_USER_EMAIL_ADDR_REQUESTING) == 0)
	{
		return respond_emergency_user_email_address_requesting(ssl_client);
	}
	else
	{
		fprintf(stderr, "Invalid request\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *emergency_address_serving_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *host[1];

    	ctx = setup_server_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(UA_EMERGENCY_ADDRESS_SERVING_PORT);
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
    		if((err = post_connection_check(ssl_client, host, 1, true, GLOBAL_authority_name)) != X509_V_OK)
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




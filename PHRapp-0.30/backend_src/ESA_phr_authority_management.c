#include "ESA_common.h"

// Local Function Prototypes
static boolean register_phr_authority(SSL *ssl_client);
static boolean edit_phr_authority_ip_address(SSL *ssl_client);
static boolean remove_phr_authority(SSL *ssl_client);
static boolean process_request(SSL *ssl_client);

// Implementation
static boolean register_phr_authority(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         phr_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         ip_address[IP_ADDRESS_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	// Receive PHR authority registration information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving PHR authority registration information failed\n");
		goto ERROR;
	}

	// Get PHR authority registration information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_authority_name") != 0)
		int_error("Extracting the phr_authority_name failed");

	if(read_token_from_buffer(buffer, 2, token_name, ip_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "ip_address") != 0)
		int_error("Extracting the ip_address failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of PHR authority name
	sprintf(stat, "SELECT phr_authority_id FROM %s WHERE phr_authority_name LIKE '%s' COLLATE latin1_general_cs", ESA__PHR_AUTHORITIES, phr_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The PHR authority name exists
	if(row)
	{
		// Send the PHR authority registration result flag
		write_token_into_buffer("phr_authority_registration_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "PHR authority name exists already", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the PHR authority registration result flag failed\n");
			goto ERROR;
		}

		goto ERROR;	
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Insert a new PHR authority
	sprintf(stat, "INSERT INTO %s(phr_authority_name, emergency_server_ip_addr) VALUES('%s', '%s')", ESA__PHR_AUTHORITIES, phr_authority_name, ip_address);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
	
	disconnect_db(&db_conn);

	// Send the PHR authority registration result flag
	write_token_into_buffer("phr_authority_registration_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the PHR authority registration result flag failed\n");
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

static boolean edit_phr_authority_ip_address(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         phr_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         ip_address[IP_ADDRESS_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];	

	unsigned int phr_authority_id;

	// Receive PHR authority ip address editing information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving PHR authority ip address editing information failed\n");
		goto ERROR;
	}

	// Get PHR authority ip address editing information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_authority_name") != 0)
		int_error("Extracting the phr_authority_name failed");

	if(read_token_from_buffer(buffer, 2, token_name, ip_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "ip_address") != 0)
		int_error("Extracting the ip_address failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of PHR authority name
	sprintf(stat, "SELECT phr_authority_id FROM %s WHERE phr_authority_name LIKE '%s' COLLATE latin1_general_cs", ESA__PHR_AUTHORITIES, phr_authority_name);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The PHR authority does not exist
	if(!row)
	{
		// Send the PHR authority ip address editing result flag
		write_token_into_buffer("phr_authority_ip_address_editing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "PHR authority does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the PHR authority ip address editing result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	phr_authority_id = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Update PHR authority's IP address
	sprintf(stat, "UPDATE %s SET emergency_server_ip_addr = '%s' WHERE phr_authority_id = %u", ESA__PHR_AUTHORITIES, ip_address, phr_authority_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      	int_error(err_msg);
	}

	disconnect_db(&db_conn);

	// Send the PHR authority ip address editing result flag
	write_token_into_buffer("phr_authority_ip_address_editing_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the PHR authority ip address editing result flag failed\n");
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

static boolean remove_phr_authority(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         phr_authority_name[AUTHORITY_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int phr_authority_id;

	// Receive PHR authority removal information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving PHR authority removal information failed\n");
		goto ERROR;
	}

	// Get a PHR authority removal information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_authority_name") != 0)
		int_error("Extracting the phr_authority_name failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of PHR authority name
	sprintf(stat, "SELECT phr_authority_id FROM %s WHERE phr_authority_name LIKE '%s' COLLATE latin1_general_cs", ESA__PHR_AUTHORITIES, phr_authority_name);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The PHR authority does not exist
	if(!row)
	{
		// Send the PHR authority removal result flag
		write_token_into_buffer("phr_authority_removal_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "PHR authority does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the PHR authority removal result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	phr_authority_id = atoi(row[0]);
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Delete the PHR authority
	sprintf(stat, "DELETE FROM %s WHERE phr_authority_id = %u", ESA__PHR_AUTHORITIES, phr_authority_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}

	disconnect_db(&db_conn);

	// Send the PHR authority removal result flag
	write_token_into_buffer("phr_authority_removal_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the PHR authority removal result flag failed\n");
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

	if(strcmp(request, PHR_AUTHORITY_REGISTRATION) == 0)
	{
		return register_phr_authority(ssl_client);
	}
	else if(strcmp(request, PHR_AUTHORITY_IP_ADDRESS_EDITING) == 0)
	{
		return edit_phr_authority_ip_address(ssl_client);
	}
	else if(strcmp(request, PHR_AUTHORITY_REMOVAL) == 0)
	{
		return remove_phr_authority(ssl_client);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *phr_authority_management_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(ESA_CERTFILE_PATH, ESA_CERTFILE_PASSWD, EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(ESA_PHR_AUTHORITY_MANAGEMENT_PORT);
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




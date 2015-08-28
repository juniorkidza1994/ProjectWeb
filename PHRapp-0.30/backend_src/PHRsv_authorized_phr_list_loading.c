#include "PHRsv_common.h"

#define SGN_ACCESS_GRANTING_TICKET_PATH "PHRsv_cache/PHRsv_authorized_phr_list_loading.sgn_access_granting_ticket"
#define ACCESS_GRANTING_TICKET_PATH     "PHRsv_cache/PHRsv_authorized_phr_list_loading.access_granting_ticket"

// Local Function Prototypes
static boolean load_authorized_phr_list(SSL *ssl_client, char *phr_owner_name, char *phr_owner_authority_name);
static boolean verify_required_operation(char *required_operation);
static boolean respond_authorized_phr_list_loading(SSL *ssl_client);

// Implementation
static boolean load_authorized_phr_list(SSL *ssl_client, char *phr_owner_name, char *phr_owner_authority_name)
{
	MYSQL     *db_conn = NULL;
	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	char      buffer[BUFFER_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for PHR list of desired PHR owner
	sprintf(stat, "SELECT DATA.phr_id, DATA.data_description, DATA.file_size, DATA.phr_conf_level_flag FROM %s DATA, %s OWN, %s AUT WHERE "
		"DATA.phr_owner_id = OWN.phr_owner_id AND OWN.username LIKE '%s' COLLATE latin1_general_cs AND OWN.authority_id = AUT.authority_id "
		"AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND DATA.hidden_flag = '0'", PHRSV__DATA, PHRSV__PHR_OWNERS, 
		PHRSV__AUTHORITIES, phr_owner_name, phr_owner_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		// Send the authorized PHR information
		write_token_into_buffer("is_end_of_authorized_phr_list_flag", "0", true, buffer);
		write_token_into_buffer("phr_id", row[0], false, buffer);
		write_token_into_buffer("data_description", row[1], false, buffer);
		write_token_into_buffer("file_size", row[2], false, buffer);
		write_token_into_buffer("phr_conf_level_flag", row[3], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the authorized PHR information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);

	// Send the end of authorized PHR list
	write_token_into_buffer("is_end_of_authorized_phr_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of authorized PHR list failed\n");
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

static boolean verify_required_operation(char *required_operation)
{
	if(strcmp(required_operation, PHR_DOWNLOADING) == 0)
		return true;
	else if(strcmp(required_operation, PHR_DELETION) == 0)
		return true;
	else
		return false;
}

static boolean respond_authorized_phr_list_loading(SSL *ssl_client)
{
	char err_msg[ERR_MSG_LENGTH + 1];
	char buffer[BUFFER_LENGTH + 1];
	char access_granting_ticket_buffer[BUFFER_LENGTH + 1];

	char token_name[TOKEN_NAME_LENGTH + 1];
	char desired_phr_owner_name[USER_NAME_LENGTH + 1];
	char desired_phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char required_operation[PHR_OPERATION_NAME_LENGTH + 1];

	char requestor_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char requestor_name[USER_NAME_LENGTH + 1];

	// Receive the request information
	if(!SSL_recv_buffer(ssl_client, buffer, NULL))
	{
		fprintf(stderr, "Receiving the request information failed\n");
		goto ERROR;
	}

	// Get request information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, desired_phr_owner_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "desired_phr_owner_name") != 0)
		int_error("Extracting the desired_phr_owner_name failed");

	if(read_token_from_buffer(buffer, 2, token_name, desired_phr_owner_authority_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "desired_phr_owner_authority_name") != 0)
	{
		int_error("Extracting the desired_phr_owner_authority_name failed");
	}

	if(read_token_from_buffer(buffer, 3, token_name, required_operation) != READ_TOKEN_SUCCESS || strcmp(token_name, "required_operation") != 0)
		int_error("Extracting the required_operation failed");

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

	// Get requestor's name and authority name
	get_cert_owner_info(ssl_client, requestor_authority_name, requestor_name);

	// Verifications
	if(!verify_access_granting_ticket(access_granting_ticket_buffer, requestor_name, 
		requestor_authority_name, desired_phr_owner_name, desired_phr_owner_authority_name))
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

	if(!verify_required_operation(required_operation))
	{
		// Send the PHR access permission verification result flag
		write_token_into_buffer("phr_access_permission_verification_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Verifying the required operation failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the PHR access permission verification result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	if(!verify_access_permission(access_granting_ticket_buffer, required_operation))
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

	return load_authorized_phr_list(ssl_client, desired_phr_owner_name, desired_phr_owner_authority_name);

ERROR:

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);
	unlink(ACCESS_GRANTING_TICKET_PATH);
	return false;
}

void *authorized_phr_list_loading_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *host[1];

    	ctx = setup_server_ctx(PHRSV_CERTFILE_PATH, PHRSV_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(PHRSV_AUTHORIZED_PHR_LIST_LOADING_PORT);
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

		host[0] = USER_CN; 
    		if((err = post_connection_check(ssl_client, host, 1, false, NULL)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		if(!respond_authorized_phr_list_loading(ssl_client))
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




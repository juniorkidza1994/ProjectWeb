#include "UA_common.h"

// Local Function Prototypes
static boolean load_attribute_list_by_authority_name(SSL *ssl_client, char *expected_attribute_list_authority_name);
static boolean process_request(SSL *ssl_client);

// Implementation
static boolean load_attribute_list_by_authority_name(SSL *ssl_client, char *expected_attribute_list_authority_name)
{
	MYSQL     *db_conn = NULL;
  	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];
	char      buffer[BUFFER_LENGTH + 1];	

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query attribute information list from database
	sprintf(stat, "SELECT ATT.attribute_name, ATT.is_numerical_attribute_flag FROM %s ATT, %s AUT WHERE AUT.authority_name LIKE '%s' "
		"COLLATE latin1_general_cs AND ATT.authority_id = AUT.authority_id", UA__ATTRIBUTES, UA__AUTHORITIES, expected_attribute_list_authority_name);

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
	disconnect_db(&db_conn);

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
	disconnect_db(&db_conn);
	return false;
}

static boolean process_request(SSL *ssl_client)
{
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    is_end_of_attribute_loading_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_attribute_loading_flag;
	char    expected_attribute_list_authority_name[AUTHORITY_NAME_LENGTH + 1];

	while(1)
	{
		// Receive attribute list loading information
		if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving attribute list loading information failed\n");
			goto ERROR;
		}

		// Get attribute list loading information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_attribute_loading_flag_str_tmp) != READ_TOKEN_SUCCESS 
			|| strcmp(token_name, "is_end_of_attribute_loading_flag") != 0)
		{
			int_error("Extracting the is_end_of_attribute_loading_flag failed");
		}

		is_end_of_attribute_loading_flag = (strcmp(is_end_of_attribute_loading_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_attribute_loading_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, expected_attribute_list_authority_name) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "expected_attribute_list_authority_name") != 0)
		{
			int_error("Extracting the expected_attribute_list_authority_name failed");
		}

		if(!load_attribute_list_by_authority_name(ssl_client, expected_attribute_list_authority_name))
			goto ERROR;
	}

	return true;

ERROR:

	return false;
}

void *attribute_list_loading_main(void *arg)
{
	BIO         *bio_acc    = NULL;
	BIO         *bio_client = NULL;
    	SSL         *ssl_client = NULL;
    	SSL_CTX     *ctx        = NULL;

	int         err;
	char        *host[2];

    	ctx = setup_server_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(UA_ATTRIBUTE_LIST_LOADING_PORT);
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

		host[0] = ADMIN_CN; 
		host[1] = USER_CN; 
    		if((err = post_connection_check(ssl_client, host, 2, true, GLOBAL_authority_name)) != X509_V_OK)
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




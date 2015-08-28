#include "ESA_common.h"

// Local Function Prototypes
static boolean change_mail_server_configuration(SSL *ssl_client);
static boolean process_request(SSL *ssl_client);

// Implementation
static boolean change_mail_server_configuration(SSL *ssl_client)
{
	char  buffer[BUFFER_LENGTH + 1];
	char  token_name[TOKEN_NAME_LENGTH + 1];
	char  mail_server_url[URL_LENGTH + 1];
	char  authority_email_address[EMAIL_ADDRESS_LENGTH + 1];
	char  authority_email_passwd[PASSWD_LENGTH + 1];

	MYSQL *db_conn = NULL;
	char  stat[SQL_STATEMENT_LENGTH + 1];
	char  err_msg[ERR_MSG_LENGTH + 1];

	// Receive mail server configuration information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving mail server configuration information failed\n");
		goto ERROR;
	}

	// Get mail server configuration tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, mail_server_url) != READ_TOKEN_SUCCESS || strcmp(token_name, "mail_server_url") != 0)
	{
		int_error("Extracting the mail_server_url failed");
	}

	if(read_token_from_buffer(buffer, 2, token_name, authority_email_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "authority_email_address") != 0)
	{
		int_error("Extracting the authority_email_address failed");
	}

	if(read_token_from_buffer(buffer, 3, token_name, authority_email_passwd) != READ_TOKEN_SUCCESS || strcmp(token_name, "authority_email_passwd") != 0)
	{
		int_error("Extracting the authority_email_passwd failed");
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Update the mail server configuration
	sprintf(stat, "UPDATE %s SET mail_server_url = '%s', authority_email_address = '%s', authority_email_passwd = '%s'", 
		ESA__BASIC_AUTHORITY_INFO, mail_server_url, authority_email_address, authority_email_passwd);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	disconnect_db(&db_conn);

	// Update values on memory
	strcpy(GLOBAL_mail_server_url, mail_server_url);
	strcpy(GLOBAL_authority_email_address, authority_email_address);
	strcpy(GLOBAL_authority_email_passwd, authority_email_passwd);

	// Send the mail server configuration changing result flag
	write_token_into_buffer("mail_server_configuration_changing_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the mail server configuration changing result flag failed\n");
		goto ERROR;
	}

	return true;

ERROR:

	return false;
}

static boolean process_request(SSL *ssl_client)
{
	char buffer[BUFFER_LENGTH + 1];
	char token_name[TOKEN_NAME_LENGTH + 1];
	char request_type[REQUEST_TYPE_LENGTH + 1];

	// Receive request type information
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

	/*if(strcmp(request_type, SERVER_ADDRESSES_CONFIGURATION_CHANGING) == 0)
	{
		return change_server_addresses_configuration(ssl_client);
	}
	else */if(strcmp(request_type, MAIL_SERVER_CONFIGURATION_CHANGING) == 0)
	{
		return change_mail_server_configuration(ssl_client);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;	
}

void *server_info_management_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(ESA_CERTFILE_PATH, ESA_CERTFILE_PASSWD, EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(ESA_SERVER_INFO_MANAGEMENT_PORT);
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




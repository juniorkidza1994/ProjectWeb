#include "ESA_common.h"

// Local Function Prototypes
static boolean load_phr_authority_list(SSL *ssl_client);

// Implementation
static boolean load_phr_authority_list(SSL *ssl_client)
{
	MYSQL     *db_conn = NULL;
	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	char      buffer[BUFFER_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for PHR authority list
	sprintf(stat, "SELECT phr_authority_name, emergency_server_ip_addr FROM %s", ESA__PHR_AUTHORITIES);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		// Send the PHR authority information
		write_token_into_buffer("is_end_of_phr_authority_list_flag", "0", true, buffer);
		write_token_into_buffer("phr_authority_name", row[0], false, buffer);
		write_token_into_buffer("ip_address", row[1], false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the PHR authority information failed\n");
			goto ERROR;
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);

	// Send the end of authority list
	write_token_into_buffer("is_end_of_phr_authority_list_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the end of PHR authority list failed\n");
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

void *phr_authority_list_loading_main(void *arg)
{
	BIO         *bio_acc    = NULL;
	BIO         *bio_client = NULL;
    	SSL         *ssl_client = NULL;
    	SSL_CTX     *ctx        = NULL;

	int         err;
	char        *hosts[2];

    	ctx = setup_server_ctx(ESA_CERTFILE_PATH, ESA_CERTFILE_PASSWD, EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(ESA_PHR_AUTHORITY_LIST_LOADING_PORT);
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
		hosts[1] = USER_CN; 
    		if((err = post_connection_check(ssl_client, hosts, 2, true, GLOBAL_authority_name)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Serve the PHR authority list
		if(!load_phr_authority_list(ssl_client))
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




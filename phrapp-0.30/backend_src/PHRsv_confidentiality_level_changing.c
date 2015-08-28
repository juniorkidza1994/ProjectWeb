#include "common.h"
#include "PHRsv_common.h"

// Local Function Prototypes
static boolean change_phr_confidentiality_level(SSL *ssl_client);

// Implementation
static boolean change_phr_confidentiality_level(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int phr_id;

	char         cert_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         cert_ownername[USER_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	// Get certificate owner's name and authority name
	get_cert_owner_info(ssl_client, cert_owner_authority_name, cert_ownername);

	// Receive the PHR id
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the PHR id failed\n");
		goto ERROR;
	}

	// Get the PHR id token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_id_str) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_id") != 0)
		int_error("Extracting the phr_id failed");

	phr_id = atoi(phr_id_str);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for the existence of requested PHR and its owner
	sprintf(stat, "SELECT DATA.phr_id FROM %s DATA, %s OWN, %s AUT WHERE DATA.phr_owner_id = OWN.phr_owner_id AND OWN.username LIKE '%s' "
		"COLLATE latin1_general_cs AND OWN.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs "
		"AND DATA.phr_id = %u AND DATA.phr_conf_level_flag = '%s'", PHRSV__DATA, PHRSV__PHR_OWNERS, PHRSV__AUTHORITIES, cert_ownername, 
		cert_owner_authority_name, phr_id, PHR_RESTRICTED_LEVEL_FLAG);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		// Send the phr_confidentiality_level_changing_flag
		write_token_into_buffer("phr_confidentiality_level_changing_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "You do not have the permission to change the\n PHR confidentiality level on the requested PHR", false, buffer);
		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the phr_confidentiality_level_changing_flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Send the phr_confidentiality_level_changing_flag
	write_token_into_buffer("phr_confidentiality_level_changing_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the phr_confidentiality_level_changing_flag failed\n");
		goto ERROR;
	}

	// Change the PHR confidentiality level from the restricted level to the exclusive level
	sprintf(stat, "UPDATE %s SET phr_conf_level_flag = '%s' WHERE phr_id = %u", PHRSV__DATA, PHR_EXCLUSIVE_LEVEL_FLAG, phr_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
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

void *phr_confidentiality_level_changing_main(void *arg)
{
	BIO         *bio_acc    = NULL;
	BIO         *bio_client = NULL;
    	SSL         *ssl_client = NULL;
    	SSL_CTX     *ctx        = NULL;

	int         err;
	char        *host[1];

    	ctx = setup_server_ctx(PHRSV_CERTFILE_PATH, PHRSV_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(PHRSV_CONFIDENTIALITY_LEVEL_CHANGING_PORT);
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

		if(!change_phr_confidentiality_level(ssl_client))
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




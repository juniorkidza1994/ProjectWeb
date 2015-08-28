#include "EmS_common.h"

// Local Function Prototype
static boolean connect_to_user_existence_checking_service(SSL **ssl_conn_ret);
static boolean check_phr_owner_existence(SSL *ssl_client);

// Implementation
static boolean connect_to_user_existence_checking_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    user_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to User Authority
	sprintf(user_auth_addr, "%s:%s", GLOBAL_user_auth_ip_addr, UA_USER_EXISTENCE_CHECKING_PORT);
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

static boolean check_phr_owner_existence(SSL *ssl_client)
{
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    phr_ownername[USER_NAME_LENGTH + 1];

	SSL     *ssl_UA_conn = NULL;
	char    user_existence_checking_result_flag_str_tmp[FLAG_LENGTH + 1];    // "0" or "1"
	boolean user_existence_checking_result_flag;
	
	// Receive PHR owner existence checking information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving PHR owner existence checking information failed\n");
		goto ERROR;
	}

	// Get a PHR owner existence checking information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		int_error("Extracting the phr_ownername failed");

	// Connect to User Authority
	if(!connect_to_user_existence_checking_service(&ssl_UA_conn))
		goto ERROR;

	// Send the user existence checking information
	write_token_into_buffer("authority_name", GLOBAL_authority_name, true, buffer);
	write_token_into_buffer("username", phr_ownername, false, buffer);

	if(!SSL_send_buffer(ssl_UA_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user existence checking information failed\n");
		goto ERROR;
	}

	// Receive the user existence checking result
	if(SSL_recv_buffer(ssl_UA_conn, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the user existence checking result failed\n");
		goto ERROR;
	}

	// Get a user existence checking result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, user_existence_checking_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "user_existence_checking_result_flag") != 0)
	{
		int_error("Extracting the user_existence_checking_result_flag failed");
	}

	user_existence_checking_result_flag = (strcmp(user_existence_checking_result_flag_str_tmp, "1") == 0) ? true : false;

	// Send the PHR owner existence checking result
	write_token_into_buffer("phr_owner_existence_checking_result_flag", user_existence_checking_result_flag_str_tmp, true, buffer);
	if(!user_existence_checking_result_flag)
	{
		write_token_into_buffer("error_msg", "Do not found the PHR owner that your're looking for", false, buffer);
	}

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the PHR owner existence checking result failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_UA_conn);
	ssl_UA_conn = NULL;
	return true;

ERROR:

	if(ssl_UA_conn)
	{
		SSL_cleanup(ssl_UA_conn);
		ssl_UA_conn = NULL;
	}

	return false;
}

void *phr_owner_existence_checking_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(EMS_EMERGENCY_ACCESS_CERTFILE_PATH, EMS_EMERGENCY_ACCESS_CERTFILE_PASSWD, EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(EMS_PHR_OWNER_EXISTENCE_CHECKING_PORT);
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

		hosts[0] = USER_CN; 
    		if((err = post_connection_check(ssl_client, hosts, 1, false, NULL)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Check the PHR owner existence
		if(!check_phr_owner_existence(ssl_client))
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




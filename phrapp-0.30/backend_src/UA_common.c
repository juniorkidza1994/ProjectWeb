#include "UA_common.h"

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

	ctx = setup_client_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
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

// Generate a random 8 character salt value
void gen_random_salt_value(char *salt_value_ret)
{
	char cmd[25];
	char ret_code[100];

	sprintf(cmd, "openssl rand -base64 6");
	exec_cmd(cmd, strlen(cmd), ret_code, sizeof(ret_code));

	// Function returns an 8 character salt value with new line character
	if(strlen(ret_code) != 9)
	{
		fprintf(stderr, "err_code: \"%s\"\n", ret_code);
		int_error("Generating a random salt value failed");
	}

	strncpy(salt_value_ret, ret_code, 8);
	salt_value_ret[8] = 0;
}




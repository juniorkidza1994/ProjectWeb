#include "client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH "Client_cache/client_restricted_level_phr_access_request_responding.calculating_ssl_cert_hash"

#define ENC_THRESHOLD_SECRET_KEY_PATH  "Client_cache/client_restricted_level_phr_access_request_responding.enc_threshold_secret_key"
#define PLN_THRESHOLD_SECRET_KEY_PATH  "Client_cache/client_restricted_level_phr_access_request_responding.pln_threshold_secret_key"

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)       = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg) = NULL;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);

static boolean connect_to_restricted_level_phr_access_request_responding_service(SSL **ssl_conn_ret);

// Implementaion
static void backend_alert_msg_handler_callback(char *alert_msg)
{
	if(backend_alert_msg_callback_handler)
	{
		backend_alert_msg_callback_handler(alert_msg);
	}
	else  // NULL
	{
		int_error("backend_alert_msg_callback_handler is NULL");
	}
}

static void backend_fatal_alert_msg_handler_callback(char *alert_msg)
{
	if(backend_fatal_alert_msg_callback_handler)
	{
		backend_fatal_alert_msg_callback_handler(alert_msg);
	}
	else  // NULL
	{
		int_error("backend_fatal_alert_msg_callback_handler is NULL");
	}
}

static boolean connect_to_restricted_level_phr_access_request_responding_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    emergency_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to Emergency Server
	sprintf(emergency_server_addr, "%s:%s", GLOBAL_emergency_server_ip_addr, EMS_RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_RESPONDING_PORT);
	bio_conn = BIO_new_connect(emergency_server_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		backend_alert_msg_callback_handler("Connecting to emergency server failed");
		goto ERROR_AT_BIO_LAYER;
	}

	/* Hash value is used for verifying an SSL certificate to make sure that certificate is a latest update version, 
	   preventing a user uses a revoked certificate to feign to be a revoked one */
	if(!verify_file_integrity(SSL_CERT_PATH, GLOBAL_ssl_cert_hash, CALCULATING_SSL_CERT_HASH_PATH))
	{
		// Notify alert message to user and then terminate the application
		backend_fatal_alert_msg_handler_callback("Your SSL certificate is not verified.\nTo solve this, please contact an administrator.");
	}

	ctx = setup_client_ctx(SSL_CERT_PATH, GLOBAL_passwd, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
	if(!(*ssl_conn_ret = SSL_new(ctx)))
            	int_error("Creating SSL context failed");
 
    	SSL_set_bio(*ssl_conn_ret, bio_conn, bio_conn);
    	if(SSL_connect(*ssl_conn_ret) <= 0)
	{
        	backend_alert_msg_handler_callback("Connecting SSL object failed");
		goto ERROR_AT_SSL_LAYER;
	}

	hosts[0] = EMERGENCY_SERVER_CN;
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, true, GLOBAL_authority_name)) != X509_V_OK)
   	{
		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
		backend_alert_msg_handler_callback("Checking SSL information failed");
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

boolean approve_restricted_phr_access_request(char *phr_ownername, char *phr_owner_authority_name, unsigned int remote_site_phr_id, 
	char *phr_description, char *emergency_staff_name, char *emergency_unit_name, void (*backend_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup a callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    remote_site_phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];

	char    restricted_level_phr_access_request_params_checking_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean restricted_level_phr_access_request_params_checking_result_flag;

	char    err_msg[ERR_MSG_LENGTH + 1];

	// Connect to Emergency Server
	if(!connect_to_restricted_level_phr_access_request_responding_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", RESTRICTED_LEVEL_PHR_ACCESS_REQUEST_TRUSTED_USER_APPROVAL, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

	sprintf(remote_site_phr_id_str, "%u", remote_site_phr_id);

	// Send the restricted-level PHR access request approval information
	write_token_into_buffer("phr_ownername", phr_ownername, true, buffer);
	write_token_into_buffer("phr_owner_authority_name", phr_owner_authority_name, false, buffer);
	write_token_into_buffer("remote_site_phr_id", remote_site_phr_id_str, false, buffer);
	write_token_into_buffer("phr_description", phr_description, false, buffer);
	write_token_into_buffer("emergency_unit_name", emergency_unit_name, false, buffer);
	write_token_into_buffer("emergency_staff_name", emergency_staff_name, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

	// Receive the restricted level PHR access request params checking result
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving the restricted level PHR access request params checking result failed");
		goto ERROR;
	}

	// Get a restricted level PHR access request params checking result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, restricted_level_phr_access_request_params_checking_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "restricted_level_phr_access_request_params_checking_result_flag") != 0)
	{
		int_error("Extracting the restricted_level_phr_access_request_params_checking_result_flag failed");
	}

	restricted_level_phr_access_request_params_checking_result_flag = (strcmp(
		restricted_level_phr_access_request_params_checking_result_flag_str_tmp, "1") == 0) ? true : false;

	if(!restricted_level_phr_access_request_params_checking_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, error_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(error_msg);
		goto ERROR;
	}

	// Receive the encrypted threshold secrey key
	if(!SSL_recv_file(ssl_conn, ENC_THRESHOLD_SECRET_KEY_PATH))
	{
		backend_alert_msg_handler_callback("Receiving the encrypted threshold secrey key failed");
		goto ERROR;
	}

	// Decrypt the encrypted threshold secret key with the user's SSL certificate
	if(!smime_decrypt_with_cert(ENC_THRESHOLD_SECRET_KEY_PATH, PLN_THRESHOLD_SECRET_KEY_PATH, SSL_CERT_PATH, GLOBAL_passwd, err_msg))
	{
		fprintf(stderr, "Decrypting the encrypted threshold secret key failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Decrypting the encrypted threshold secret key failed");
		goto ERROR;
	}

	unlink(ENC_THRESHOLD_SECRET_KEY_PATH);

	// Send the unencrypted threshold secret key from file
	if(!SSL_send_file(ssl_conn, PLN_THRESHOLD_SECRET_KEY_PATH))
	{
		backend_alert_msg_handler_callback("Sending the unencrypted threshold secret key failed");
		goto ERROR;
	}

	unlink(PLN_THRESHOLD_SECRET_KEY_PATH);

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	return true;

ERROR:

	unlink(ENC_THRESHOLD_SECRET_KEY_PATH);
	unlink(PLN_THRESHOLD_SECRET_KEY_PATH);

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;
}




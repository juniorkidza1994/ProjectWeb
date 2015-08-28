#include "client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH "Client_cache/client_access_permission_management.calculating_ssl_cert_hash"

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)       = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg) = NULL;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);

static boolean connect_to_access_permission_management_service(SSL **ssl_conn_ret);

// Implementation
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

static boolean connect_to_access_permission_management_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    user_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to User Authority
	sprintf(user_auth_addr, "%s:%s", GLOBAL_user_auth_ip_addr, UA_ACCESS_PERMISSION_MANAGEMENT_PORT);
	bio_conn = BIO_new_connect(user_auth_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		backend_alert_msg_callback_handler("Connecting to user authority failed");
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

	hosts[0] = USER_AUTH_CN;
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

boolean assign_access_permission(char *desired_user_authority_name, char *desired_username, boolean upload_permission_flag, boolean download_permission_flag, 
	boolean delete_permission_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    access_permission_assignment_result_flag_str_tmp[FLAG_LENGTH + 1];    // "0" or "1"
	boolean access_permission_assignment_result_flag;

	// Connect to User Authority
	if(!connect_to_access_permission_management_service(&ssl_conn))
		goto ERROR;

	// Send access permission assignment information
	write_token_into_buffer("request", ACCESS_PERMISSION_ASSIGNMENT, true, buffer);
	write_token_into_buffer("desired_user_authority_name", desired_user_authority_name, false, buffer);
	write_token_into_buffer("desired_username", desired_username, false, buffer);
	write_token_into_buffer("upload_permission_flag", (upload_permission_flag) ? "1" : "0", false, buffer);
	write_token_into_buffer("download_permission_flag", (download_permission_flag) ? "1" : "0", false, buffer);
	write_token_into_buffer("delete_permission_flag", (delete_permission_flag) ? "1" : "0", false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending access permission assignment information failed");
		goto ERROR;
	}

	// Receive access permission assignment result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving access permission assignment result failed");
		goto ERROR;
	}

	// Get an access permission assignment result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, access_permission_assignment_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "access_permission_assignment_result_flag") != 0)
	{
		int_error("Extracting the access_permission_assignment_result_flag failed");
	}

	access_permission_assignment_result_flag = (strcmp(access_permission_assignment_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!access_permission_assignment_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, error_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(error_msg);
		goto ERROR;
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	return true;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;
}

boolean edit_access_permission(char *desired_user_authority_name, char *desired_username, boolean upload_permission_flag, boolean download_permission_flag, 
	boolean delete_permission_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    access_permission_editing_result_flag_str_tmp[FLAG_LENGTH + 1];    // "0" or "1"
	boolean access_permission_editing_result_flag;

	// Connect to User Authority
	if(!connect_to_access_permission_management_service(&ssl_conn))
		goto ERROR;

	// Send access permission editing information
	write_token_into_buffer("request", ACCESS_PERMISSION_EDITING, true, buffer);
	write_token_into_buffer("desired_user_authority_name", desired_user_authority_name, false, buffer);
	write_token_into_buffer("desired_username", desired_username, false, buffer);
	write_token_into_buffer("upload_permission_flag", (upload_permission_flag) ? "1" : "0", false, buffer);
	write_token_into_buffer("download_permission_flag", (download_permission_flag) ? "1" : "0", false, buffer);
	write_token_into_buffer("delete_permission_flag", (delete_permission_flag) ? "1" : "0", false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending access permission editing information failed");
		goto ERROR;
	}

	// Receive access permission editing result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving access permission editing result failed");
		goto ERROR;
	}

	// Get an access permission editing result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, access_permission_editing_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "access_permission_editing_result_flag") != 0)
	{
		int_error("Extracting the access_permission_editing_result_flag failed");
	}

	access_permission_editing_result_flag = (strcmp(access_permission_editing_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!access_permission_editing_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, error_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(error_msg);
		goto ERROR;
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	return true;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;
}

boolean remove_access_permission(char *desired_user_authority_name, char *desired_username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    access_permission_removal_result_flag_str_tmp[FLAG_LENGTH + 1];    // "0" or "1"
	boolean access_permission_removal_result_flag;

	// Connect to User Authority
	if(!connect_to_access_permission_management_service(&ssl_conn))
		goto ERROR;

	// Send access permission removal information
	write_token_into_buffer("request", ACCESS_PERMISSION_REMOVAL, true, buffer);
	write_token_into_buffer("desired_user_authority_name", desired_user_authority_name, false, buffer);
	write_token_into_buffer("desired_username", desired_username, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending access permission removal information failed");
		goto ERROR;
	}

	// Receive access permission removal result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving access permission removal result failed");
		goto ERROR;
	}

	// Get an access permission removal result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, access_permission_removal_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "access_permission_removal_result_flag") != 0)
	{
		int_error("Extracting the access_permission_removal_result_flag failed");
	}

	access_permission_removal_result_flag = (strcmp(access_permission_removal_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!access_permission_removal_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, error_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(error_msg);
		goto ERROR;
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	return true;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;
}




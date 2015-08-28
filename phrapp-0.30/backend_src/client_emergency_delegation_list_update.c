#include "client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH "Client_cache/client_emergency_delegation_list_update.calculating_ssl_cert_hash"

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)       						       = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg) 						       = NULL;
static void (*clear_emergency_trusted_user_table_callback_handler)()     						       = NULL;
static void (*add_emergency_trusted_user_to_table_callback_handler)(char *trusted_username, char *trusted_user_authority_name) = NULL;
static void (*clear_emergency_phr_owner_table_callback_handler)()     						 	       = NULL;
static void (*add_emergency_phr_owner_to_table_callback_handler)(char *phr_owner_name, char *phr_owner_authority_name)         = NULL;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);
static void clear_emergency_trusted_user_table_handler_callback();
static void add_emergency_trusted_user_to_table_handler_callback(char *trusted_username, char *trusted_user_authority_name);
static void clear_emergency_phr_owner_table_handler_callback();
static void add_emergency_phr_owner_to_table_handler_callback(char *phr_owner_name, char *phr_owner_authority_name);

static boolean connect_to_emergency_delegation_list_loading_service(SSL **ssl_conn_ret);

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

static void clear_emergency_trusted_user_table_handler_callback()
{
	if(clear_emergency_trusted_user_table_callback_handler)
	{
		clear_emergency_trusted_user_table_callback_handler();
	}
	else  // NULL
	{
		int_error("clear_emergency_trusted_user_table_callback_handler is NULL");
	}
}

static void add_emergency_trusted_user_to_table_handler_callback(char *trusted_username, char *trusted_user_authority_name)
{
	if(add_emergency_trusted_user_to_table_callback_handler)
	{
		add_emergency_trusted_user_to_table_callback_handler(trusted_username, trusted_user_authority_name);
	}
	else  // NULL
	{
		int_error("add_emergency_trusted_user_to_table_callback_handler is NULL");
	}
}

static void clear_emergency_phr_owner_table_handler_callback()
{
	if(clear_emergency_phr_owner_table_callback_handler)
	{
		clear_emergency_phr_owner_table_callback_handler();
	}
	else  // NULL
	{
		int_error("clear_emergency_phr_owner_table_callback_handler is NULL");
	}
}

static void add_emergency_phr_owner_to_table_handler_callback(char *phr_owner_name, char *phr_owner_authority_name)
{
	if(add_emergency_phr_owner_to_table_callback_handler)
	{
		add_emergency_phr_owner_to_table_callback_handler(phr_owner_name, phr_owner_authority_name);
	}
	else  // NULL
	{
		int_error("add_emergency_phr_owner_to_table_callback_handler is NULL");
	}
}

static boolean connect_to_emergency_delegation_list_loading_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    emergency_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to Emergency Server
	sprintf(emergency_server_addr, "%s:%s", GLOBAL_emergency_server_ip_addr, EMS_EMERGENCY_DELEGATION_LIST_LOADING_PORT);
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

void update_emergency_trusted_user_list(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*clear_emergency_trusted_user_table_callback_handler_ptr)(), void (*add_emergency_trusted_user_to_table_callback_handler_ptr)(
	char *trusted_username, char *trusted_user_authority_name))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler                   = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler             = backend_fatal_alert_msg_callback_handler_ptr;
	clear_emergency_trusted_user_table_callback_handler  = clear_emergency_trusted_user_table_callback_handler_ptr;
	add_emergency_trusted_user_to_table_callback_handler = add_emergency_trusted_user_to_table_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    is_end_of_emergency_trusted_user_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_emergency_trusted_user_list_flag;
	char    trusted_username[USER_NAME_LENGTH + 1];
	char    trusted_user_authority_name[AUTHORITY_NAME_LENGTH + 1];

	// Connect to Emergency Server
	if(!connect_to_emergency_delegation_list_loading_service(&ssl_conn))
		goto ERROR;

	// Send a request for downloading a trusted user list
	write_token_into_buffer("request_type", EMERGENCY_TRUSTED_USER_LIST_LOADING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending a request for downloading a trusted user list failed");
		goto ERROR;
	}

	// Clear emergency trusted user table
	clear_emergency_trusted_user_table_handler_callback();

	// Add emergency trusted users
	while(1)
	{
		// Receive emergency trusted user information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			backend_alert_msg_handler_callback("Receiving emergency trusted user information failed");
			goto ERROR;
		}

		// Get emergency trusted user information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_emergency_trusted_user_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_emergency_trusted_user_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_emergency_trusted_user_list_flag failed");
		}

		is_end_of_emergency_trusted_user_list_flag = (strcmp(is_end_of_emergency_trusted_user_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_emergency_trusted_user_list_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, trusted_username) != READ_TOKEN_SUCCESS || strcmp(token_name, "trusted_username") != 0)
		{
			int_error("Extracting the trusted_username failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, trusted_user_authority_name) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "trusted_user_authority_name") != 0)
		{
			int_error("Extracting the trusted_user_authority_name failed");
		}

		// Add an emergency trusted user to table
		add_emergency_trusted_user_to_table_handler_callback(trusted_username, trusted_user_authority_name);
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	return;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}
}

void update_emergency_phr_owner_list(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*clear_emergency_phr_owner_table_callback_handler_ptr)(), void (*add_emergency_phr_owner_to_table_callback_handler_ptr)(
	char *phr_owner_name, char *phr_owner_authority_name))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler                = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler          = backend_fatal_alert_msg_callback_handler_ptr;
	clear_emergency_phr_owner_table_callback_handler  = clear_emergency_phr_owner_table_callback_handler_ptr;
	add_emergency_phr_owner_to_table_callback_handler = add_emergency_phr_owner_to_table_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    is_end_of_emergency_phr_owner_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_emergency_phr_owner_list_flag;
	char    phr_owner_name[USER_NAME_LENGTH + 1];
	char    phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];

	// Connect to Emergency Server
	if(!connect_to_emergency_delegation_list_loading_service(&ssl_conn))
		goto ERROR;

	// Send a request for downloading a PHR owner list
	write_token_into_buffer("request_type", EMERGENCY_PHR_OWNER_LIST_LOADING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending a request for downloading a PHR owner list failed");
		goto ERROR;
	}

	// Clear emergency PHR owner table
	clear_emergency_phr_owner_table_handler_callback();

	// Add emergency PHR owners
	while(1)
	{
		// Receive emergency PHR owner information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			backend_alert_msg_handler_callback("Receiving emergency PHR owner information failed");
			goto ERROR;
		}

		// Get emergency PHR owner information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_emergency_phr_owner_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_emergency_phr_owner_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_emergency_phr_owner_list_flag failed");
		}

		is_end_of_emergency_phr_owner_list_flag = (strcmp(is_end_of_emergency_phr_owner_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_emergency_phr_owner_list_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, phr_owner_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_owner_name") != 0)
		{
			int_error("Extracting the phr_owner_name failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, phr_owner_authority_name) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "phr_owner_authority_name") != 0)
		{
			int_error("Extracting the phr_owner_authority_name failed");
		}

		// Add an emergency PHR owner to table
		add_emergency_phr_owner_to_table_handler_callback(phr_owner_name, phr_owner_authority_name);
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	return;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}
}




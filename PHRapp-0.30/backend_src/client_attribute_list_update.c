#include "client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH "Client_cache/client_attribute_list_update.calculating_ssl_cert_hash"

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)                                                          = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg)                                                    = NULL;
static void (*clear_attribute_table_callback_handler_for_admin)()                                                           = NULL;
static void (*add_attribute_to_table_callback_handler_for_admin)(char *attribute_name, boolean is_numerical_attribute_flag) = NULL;
static void (*clear_attribute_table_callback_handler_for_user)()                                                            = NULL;
static void (*add_attribute_to_table_callback_handler_for_user)(char *attribute_name, boolean is_numerical_attribute_flag)  = NULL;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);
static void clear_attribute_table_handler_callback_for_admin();
static void add_attribute_to_table_handler_callback_for_admin(char *attribute_name, boolean is_numerical_attribute_flag);

static void clear_attribute_table_handler_callback_for_user();
static void add_attribute_to_table_handler_callback_for_user(char *attribute_name, boolean is_numerical_attribute_flag);

static boolean connect_to_attribute_list_loading_service(SSL **ssl_conn_ret);
static boolean update_attribute_list_by_authority_for_admin(SSL *ssl_conn);
static boolean update_attribute_list_by_authority_for_user(SSL *ssl_conn);

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

static void clear_attribute_table_handler_callback_for_admin()
{
	if(clear_attribute_table_callback_handler_for_admin)
	{
		clear_attribute_table_callback_handler_for_admin();
	}
	else  // NULL
	{
		int_error("clear_attribute_table_callback_handler_for_admin is NULL");
	}
}

static void add_attribute_to_table_handler_callback_for_admin(char *attribute_name, boolean is_numerical_attribute_flag)
{
	if(add_attribute_to_table_callback_handler_for_admin)
	{
		add_attribute_to_table_callback_handler_for_admin(attribute_name, is_numerical_attribute_flag);
	}
	else  // NULL
	{
		int_error("add_attribute_to_table_callback_handler_for_admin is NULL");
	}
}

static void clear_attribute_table_handler_callback_for_user()
{
	if(clear_attribute_table_callback_handler_for_user)
	{
		clear_attribute_table_callback_handler_for_user();
	}
	else  // NULL
	{
		int_error("clear_attribute_table_callback_handler_for_user is NULL");
	}
}

static void add_attribute_to_table_handler_callback_for_user(char *attribute_name, boolean is_numerical_attribute_flag)
{
	if(add_attribute_to_table_callback_handler_for_user)
	{
		add_attribute_to_table_callback_handler_for_user(attribute_name, is_numerical_attribute_flag);
	}
	else  // NULL
	{
		int_error("add_attribute_to_table_callback_handler_for_user is NULL");
	}
}

static boolean connect_to_attribute_list_loading_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    user_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to User Authority
	sprintf(user_auth_addr, "%s:%s", GLOBAL_user_auth_ip_addr, UA_ATTRIBUTE_LIST_LOADING_PORT);
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

static boolean update_attribute_list_by_authority_for_admin(SSL *ssl_conn)
{
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    is_end_of_attribute_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_attribute_list_flag;
	char    attribute_name[ATTRIBUTE_NAME_LENGTH + 1];
	char    is_numerical_attribute_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_numerical_attribute_flag;

	while(1)
	{
		// Receive attribute information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			backend_alert_msg_handler_callback("Receiving attribute information failed");
			goto ERROR;
		}

		// Get attribute information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_attribute_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_attribute_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_attribute_list_flag failed");
		}

		is_end_of_attribute_list_flag = (strcmp(is_end_of_attribute_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_attribute_list_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, attribute_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "attribute_name") != 0)
		{
			int_error("Extracting the attribute_name failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, is_numerical_attribute_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_numerical_attribute_flag") != 0)
		{
			int_error("Extracting the is_numerical_attribute_flag failed");
		}

		is_numerical_attribute_flag = (strcmp(is_numerical_attribute_flag_str_tmp, "1") == 0) ? true : false;

		// Add attribute to table
		add_attribute_to_table_handler_callback_for_admin(attribute_name, is_numerical_attribute_flag);
	}

	return true;

ERROR:

	return false;
}

void update_attribute_list_for_admin(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg),
	void (*clear_attribute_table_callback_handler_ptr)(), void (*add_attribute_to_table_callback_handler_ptr)(char *attribute_name, boolean is_numerical_attribute_flag))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler                = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler          = backend_fatal_alert_msg_callback_handler_ptr;
	clear_attribute_table_callback_handler_for_admin  = clear_attribute_table_callback_handler_ptr;
	add_attribute_to_table_callback_handler_for_admin = add_attribute_to_table_callback_handler_ptr;

	SSL  *ssl_conn = NULL;
	char buffer[BUFFER_LENGTH + 1];

	// Connect to User Authority
	if(!connect_to_attribute_list_loading_service(&ssl_conn))
		goto ERROR;

	// Clear attribute table
	clear_attribute_table_handler_callback_for_admin();

	// Load attribute list of authority "GLOBAL_authority_name"
	write_token_into_buffer("is_end_of_attribute_loading_flag", "0", true, buffer);
	write_token_into_buffer("expected_attribute_list_authority_name", GLOBAL_authority_name, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending attribute list update information failed");
		goto ERROR;
	}

	if(!update_attribute_list_by_authority_for_admin(ssl_conn))
		goto ERROR;

	// Send end of attribute list update
	write_token_into_buffer("is_end_of_attribute_loading_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending attribute list update information failed");
		goto ERROR;
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

static boolean update_attribute_list_by_authority_for_user(SSL *ssl_conn)
{
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    is_end_of_attribute_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_attribute_list_flag;
	char    attribute_name[ATTRIBUTE_NAME_LENGTH + 1];
	char    is_numerical_attribute_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_numerical_attribute_flag;

	boolean no_any_attribute_flag = true;

	while(1)
	{
		// Receive attribute information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			backend_alert_msg_handler_callback("Receiving attribute information failed");
			goto ERROR;
		}

		// Get attribute information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_attribute_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_attribute_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_attribute_list_flag failed");
		}

		is_end_of_attribute_list_flag = (strcmp(is_end_of_attribute_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_attribute_list_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, attribute_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "attribute_name") != 0)
		{
			int_error("Extracting the attribute_name failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, is_numerical_attribute_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_numerical_attribute_flag") != 0)
		{
			int_error("Extracting the is_numerical_attribute_flag failed");
		}

		is_numerical_attribute_flag = (strcmp(is_numerical_attribute_flag_str_tmp, "1") == 0) ? true : false;

		// Add attribute to table
		add_attribute_to_table_handler_callback_for_user(attribute_name, is_numerical_attribute_flag);
		no_any_attribute_flag = false;
	}

	if(no_any_attribute_flag)
		backend_alert_msg_handler_callback("No any attribute for this authority");

	return true;

ERROR:

	return false;
}

void update_attribute_list_for_user(char *authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*clear_attribute_table_callback_handler_ptr)(), 
	void (*add_attribute_to_table_callback_handler_ptr)(char *attribute_name, boolean is_numerical_attribute_flag))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler               = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler         = backend_fatal_alert_msg_callback_handler_ptr;
	clear_attribute_table_callback_handler_for_user  = clear_attribute_table_callback_handler_ptr;
	add_attribute_to_table_callback_handler_for_user = add_attribute_to_table_callback_handler_ptr;

	SSL  *ssl_conn = NULL;
	char buffer[BUFFER_LENGTH + 1];

	// Connect to User Authority
	if(!connect_to_attribute_list_loading_service(&ssl_conn))
		goto ERROR;

	// Clear attribute table
	clear_attribute_table_handler_callback_for_user();

	// Load attribute list of the selected authority
	write_token_into_buffer("is_end_of_attribute_loading_flag", "0", true, buffer);
	write_token_into_buffer("expected_attribute_list_authority_name", authority_name, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending attribute list update information failed");
		goto ERROR;
	}

	if(!update_attribute_list_by_authority_for_user(ssl_conn))
		goto ERROR;

	// Send end of attribute list update
	write_token_into_buffer("is_end_of_attribute_loading_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending attribute list update information failed");
		goto ERROR;
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




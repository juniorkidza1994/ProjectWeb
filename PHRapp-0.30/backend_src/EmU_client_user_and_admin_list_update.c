#include "EmU_client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH "EmU_client_cache/EmU_client_user_and_admin_list_update.calculating_ssl_cert_hash"

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)                      = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg)                = NULL;
static void (*clear_user_table_callback_handler)()                                     = NULL;
static void (*add_user_to_table_callback_handler)(char *username, char *email_address) = NULL;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);
static void clear_user_table_handler_callback();
static void add_user_to_table_handler_callback(char *username, char *email_address);

static boolean connect_to_user_list_loading_service(SSL **ssl_conn_ret);

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

static void clear_user_table_handler_callback()
{
	if(clear_user_table_callback_handler)
	{
		clear_user_table_callback_handler();
	}
	else  // NULL
	{
		int_error("clear_user_table_callback_handler is NULL");
	}
}

static void add_user_to_table_handler_callback(char *username, char *email_address)
{
	if(add_user_to_table_callback_handler)
	{
		add_user_to_table_callback_handler(username, email_address);
	}
	else  // NULL
	{
		int_error("add_user_to_table_callback_handler is NULL");
	}
}

static boolean connect_to_user_list_loading_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    emergency_staff_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to Emergency Staff Authority
	sprintf(emergency_staff_auth_addr, "%s:%s", GLOBAL_emergency_staff_auth_ip_addr, ESA_USER_LIST_LOADING_PORT);
	bio_conn = BIO_new_connect(emergency_staff_auth_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		backend_alert_msg_callback_handler("Connecting to emergency staff authority failed");
		goto ERROR_AT_BIO_LAYER;
	}

	/* Hash value is used for verifying an SSL certificate to make sure that certificate is a latest update version, 
	   preventing a user uses a revoked certificate to feign to be a revoked one */
	if(!verify_file_integrity(SSL_CERT_PATH, GLOBAL_ssl_cert_hash, CALCULATING_SSL_CERT_HASH_PATH))
	{
		// Notify alert message to user and then terminate the application
		backend_fatal_alert_msg_handler_callback("Your SSL certificate is not verified.\nTo solve this, please contact an administrator.");
	}

	ctx = setup_client_ctx(SSL_CERT_PATH, GLOBAL_passwd, EMU_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
	if(!(*ssl_conn_ret = SSL_new(ctx)))
            	int_error("Creating SSL context failed");
 
    	SSL_set_bio(*ssl_conn_ret, bio_conn, bio_conn);
    	if(SSL_connect(*ssl_conn_ret) <= 0)
	{
        	backend_alert_msg_handler_callback("Connecting SSL object failed");
		goto ERROR_AT_SSL_LAYER;
	}

	hosts[0] = EMERGENCY_STAFF_AUTH_CN;
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

void update_emu_user_list(boolean is_admin_flag, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*clear_user_table_callback_handler_ptr)(), void (*add_user_to_table_callback_handler_ptr)(char *username, char *email_address))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;
	clear_user_table_callback_handler       = clear_user_table_callback_handler_ptr;
	add_user_to_table_callback_handler      = add_user_to_table_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    is_end_of_user_or_admin_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_user_or_admin_list_flag;
	char    username[USER_NAME_LENGTH + 1];
	char    email_address[EMAIL_ADDRESS_LENGTH + 1];

	// Connect to Emergency Staff Authority
	if(!connect_to_user_list_loading_service(&ssl_conn))
		goto ERROR;

	// Load user/admin list
	write_token_into_buffer("load_admin_list_flag", (is_admin_flag == true) ? "1" : "0", true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending user loading information failed");
		goto ERROR;
	}

	// Clear user/admin table
	clear_user_table_handler_callback();

	// Add users/admins
	while(1)
	{
		// Receive user information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			backend_alert_msg_handler_callback("Receiving user information failed");
			goto ERROR;
		}

		// Get user information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_user_or_admin_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_user_or_admin_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_user_or_admin_list_flag failed");
		}

		is_end_of_user_or_admin_list_flag = (strcmp(is_end_of_user_or_admin_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_user_or_admin_list_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		{
			int_error("Extracting the username failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, email_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "email_address") != 0)
		{
			int_error("Extracting the email_address failed");
		}

		// Add user/admin to table
		add_user_to_table_handler_callback(username, email_address);
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




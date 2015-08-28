#include "client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH "Client_cache/client_user_management.calculating_ssl_cert_hash"

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)                                               = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg)                                         = NULL;
static void (*get_user_attribute_by_index_callback_handler)(unsigned int index, char *user_attribute_buffer_ret) = NULL;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);
static void get_user_attribute_by_index_handler_callback(unsigned int index, char *user_attribute_buffer_ret);

static boolean connect_to_user_management_service(SSL **ssl_conn_ret);
static boolean edit_user_email_address(SSL *ssl_conn, char *username, char *email_address);
static boolean edit_user_attribute_list(SSL *ssl_conn, char *username);

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

static void get_user_attribute_by_index_handler_callback(unsigned int index, char *user_attribute_buffer_ret)
{
	if(get_user_attribute_by_index_callback_handler)
	{
		get_user_attribute_by_index_callback_handler(index, user_attribute_buffer_ret);
	}
	else  // NULL
	{
		int_error("get_user_attribute_by_index_callback_handler is NULL");
	}
}

static boolean connect_to_user_management_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    user_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to User Authority
	sprintf(user_auth_addr, "%s:%s", GLOBAL_user_auth_ip_addr, UA_USER_MANAGEMENT_PORT);
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

boolean register_user(char *username, char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*get_user_attribute_by_index_callback_handler_ptr)
	(unsigned int index, char *user_attribute_buffer_ret))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler           = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler     = backend_fatal_alert_msg_callback_handler_ptr;
	get_user_attribute_by_index_callback_handler = get_user_attribute_by_index_callback_handler_ptr;

	SSL          *ssl_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         user_registration_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      user_registration_result_flag;

	unsigned int index;
	char         end_of_user_attribute_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      end_of_user_attribute_list_flag;

	char         user_attribute_registration_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      user_attribute_registration_result_flag;

	char         key_and_permission_generating_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      key_and_permission_generating_result_flag;

	// Connect to User Authority
	if(!connect_to_user_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", USER_REGISTRATION, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

	// Send user registration information
	write_token_into_buffer("username", username, true, buffer);
	write_token_into_buffer("email_address", email_address, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending user registration information failed");
		goto ERROR;
	}

	// Receive a user registration result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a user registration result failed");
		goto ERROR;
	}

	// Get a user registration result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, user_registration_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "user_registration_result_flag") != 0)
	{
		int_error("Extracting the user_registration_result_flag failed");
	}

	user_registration_result_flag = (strcmp(user_registration_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!user_registration_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, error_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(error_msg);
		goto ERROR;
	}

	index = 1;
	while(1)
	{
		get_user_attribute_by_index_handler_callback(index++, buffer);

		// Get an end of user attribute list flag token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, end_of_user_attribute_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "end_of_user_attribute_list_flag") != 0)
		{
			int_error("Extracting the end_of_user_attribute_list_flag failed");
		}

		end_of_user_attribute_list_flag = (strcmp(end_of_user_attribute_list_flag_str_tmp, "1") == 0) ? true : false;
		if(end_of_user_attribute_list_flag)
			break;

		// Send user attribute information
		if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
		{
			backend_alert_msg_handler_callback("Sending user attribute information failed");
			goto ERROR;
		}
	}

	// Send the end of user attribute information
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending the end of user attribute information failed");
		goto ERROR;
	}

	// Receive a user attribute registration result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a user attribute registration result failed");
		goto ERROR;
	}

	// Get a user attribute registration result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, user_attribute_registration_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "user_attribute_registration_result_flag") != 0)
	{
		int_error("Extracting the user_attribute_registration_result_flag failed");
	}

	user_attribute_registration_result_flag = (strcmp(user_attribute_registration_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!user_attribute_registration_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, error_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(error_msg);
		goto ERROR;
	}

	// Receive a key and permission generating result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a key and permission generating result flag failed");
		goto ERROR;
	}

	// Get a key and permission generating result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, key_and_permission_generating_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "key_and_permission_generating_result_flag") != 0)
	{
		int_error("Extracting the key_and_permission_generating_result_flag failed");
	}

	key_and_permission_generating_result_flag = (strcmp(key_and_permission_generating_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!key_and_permission_generating_result_flag)
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

static boolean edit_user_email_address(SSL *ssl_conn, char *username, char *email_address)
{
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    user_email_address_editing_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean user_email_address_editing_result_flag;

	// Send user's e-mail address editing information
	write_token_into_buffer("username", username, true, buffer);
	write_token_into_buffer("email_address", email_address, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending user's e-mail address editing information failed");
		goto ERROR;
	}

	// Receive a user email address editing result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a user email address editing result failed");
		goto ERROR;
	}

	// Get a user email address editing result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, user_email_address_editing_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "user_email_address_editing_result_flag") != 0)
	{
		int_error("Extracting the user_email_address_editing_result_flag failed");
	}

	user_email_address_editing_result_flag = (strcmp(user_email_address_editing_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!user_email_address_editing_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, error_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(error_msg);
		goto ERROR;
	}

	return true;

ERROR:
	return false;
}

static boolean edit_user_attribute_list(SSL *ssl_conn, char *username)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         user_attribute_list_editing_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      user_attribute_list_editing_result_flag;

	unsigned int index;
	char         end_of_user_attribute_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      end_of_user_attribute_list_flag;

	char         user_attribute_editing_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      user_attribute_editing_result_flag;

	char         key_and_permission_generating_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      key_and_permission_generating_result_flag;

	// Send username information
	write_token_into_buffer("username", username, true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending username information failed");
		goto ERROR;
	}

	// Receive a user attribute list editing result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a user attribute list editing result failed");
		goto ERROR;
	}

	// Get a user attribute list editing result flagtoken from buffer
	if(read_token_from_buffer(buffer, 1, token_name, user_attribute_list_editing_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "user_attribute_list_editing_result_flag") != 0)
	{
		int_error("Extracting the user_attribute_list_editing_result_flag failed");
	}

	user_attribute_list_editing_result_flag = (strcmp(user_attribute_list_editing_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!user_attribute_list_editing_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, error_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(error_msg);
		goto ERROR;
	}

	index = 1;
	while(1)
	{
		get_user_attribute_by_index_handler_callback(index++, buffer);

		// Get an end of user attribute list flag token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, end_of_user_attribute_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "end_of_user_attribute_list_flag") != 0)
		{
			int_error("Extracting the end_of_user_attribute_list_flag failed");
		}

		end_of_user_attribute_list_flag = (strcmp(end_of_user_attribute_list_flag_str_tmp, "1") == 0) ? true : false;
		if(end_of_user_attribute_list_flag)
			break;

		// Send user attribute information
		if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
		{
			backend_alert_msg_handler_callback("Sending user attribute information failed");
			goto ERROR;
		}
	}

	// Send the end of user attribute information
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending the end of user attribute information failed");
		goto ERROR;
	}

	// Receive a user attribute editing result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a user attribute editing result failed");
		goto ERROR;
	}

	// Get a user attribute editing result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, user_attribute_editing_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "user_attribute_editing_result_flag") != 0)
	{
		int_error("Extracting the user_attribute_editing_result_flag failed");
	}

	user_attribute_editing_result_flag = (strcmp(user_attribute_editing_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!user_attribute_editing_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, error_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(error_msg);
		goto ERROR;
	}

	// Receive a key and permission generating result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a key and permission generating result flag failed");
		goto ERROR;
	}

	// Get a key and permission generating result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, key_and_permission_generating_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "key_and_permission_generating_result_flag") != 0)
	{
		int_error("Extracting the key_and_permission_generating_result_flag failed");
	}

	key_and_permission_generating_result_flag = (strcmp(key_and_permission_generating_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!key_and_permission_generating_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, error_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(error_msg);
		goto ERROR;
	}

	return true;

ERROR:

	return false;
}

boolean edit_user_email_address_and_attribute_list(char *username, char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*get_user_attribute_by_index_callback_handler_ptr)
	(unsigned int index, char *user_attribute_buffer_ret))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler           = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler     = backend_fatal_alert_msg_callback_handler_ptr;
	get_user_attribute_by_index_callback_handler = get_user_attribute_by_index_callback_handler_ptr;

	SSL  *ssl_conn = NULL;
	char buffer[BUFFER_LENGTH + 1];

	// Connect to User Authority
	if(!connect_to_user_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", USER_EMAIL_ADDRESS_AND_ATTRIBUTE_LIST_EDITING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

	if(!edit_user_email_address(ssl_conn, username, email_address))
		goto ERROR;

	if(!edit_user_attribute_list(ssl_conn, username))
		goto ERROR;
	
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

boolean edit_user_email_address_only(char *username, char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL  *ssl_conn = NULL;
	char buffer[BUFFER_LENGTH + 1];

	// Connect to User Authority
	if(!connect_to_user_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", USER_EMAIL_ADDRESS_EDITING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

	if(!edit_user_email_address(ssl_conn, username, email_address))
		goto ERROR;
	
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

boolean edit_user_attribute_list_only(char *username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)
	(char *alert_msg), void (*get_user_attribute_by_index_callback_handler_ptr)(unsigned int index, char *user_attribute_buffer_ret))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler           = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler     = backend_fatal_alert_msg_callback_handler_ptr;
	get_user_attribute_by_index_callback_handler = get_user_attribute_by_index_callback_handler_ptr;

	SSL  *ssl_conn = NULL;
	char buffer[BUFFER_LENGTH + 1];

	// Connect to User Authority
	if(!connect_to_user_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", USER_ATTRIBUTE_LIST_EDITING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

	if(!edit_user_attribute_list(ssl_conn, username))
		goto ERROR;
	
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

boolean edit_user_attribute_value(char *username, char *attribute_name, char *attribute_authority_name, char *attribute_value, void (*backend_alert_msg_callback_handler_ptr)
	(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    user_attribute_value_editing_result_flag_str_tmp[FLAG_LENGTH + 1];        // "0" or "1"
	boolean user_attribute_value_editing_result_flag;

	// Connect to User Authority
	if(!connect_to_user_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", USER_ATTRIBUTE_VALUE_EDITING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}	

	// Send user's attribute value editing information
	write_token_into_buffer("username", username, true, buffer);
	write_token_into_buffer("attribute_name", attribute_name, false, buffer);
	write_token_into_buffer("attribute_authority_name", attribute_authority_name, false, buffer);
	write_token_into_buffer("attribute_value", attribute_value, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending user's attribute value editing information failed");
		goto ERROR;
	}

	// Receive a user attribute value editing result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a user attribute value editing result failed");
		goto ERROR;
	}

	// Get a user attribute value editing result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, user_attribute_value_editing_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "user_attribute_value_editing_result_flag") != 0)
	{
		int_error("Extracting the user_attribute_value_editing_result_flag failed");
	}

	user_attribute_value_editing_result_flag = (strcmp(user_attribute_value_editing_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!user_attribute_value_editing_result_flag)
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

boolean reset_user_passwd(char *username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    user_passwd_resetting_result_flag_str_tmp[FLAG_LENGTH + 1];    // "0" or "1"
	boolean user_passwd_resetting_result_flag;

	// Connect to User Authority
	if(!connect_to_user_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", USER_PASSWD_RESETTING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

	// Send user password resetting information
	write_token_into_buffer("username", username, true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending user password resetting information failed");
		goto ERROR;
	}

	// Receive a user password resetting result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a user password resetting result failed");
		goto ERROR;
	}

	// Get a user password resetting result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, user_passwd_resetting_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "user_passwd_resetting_result_flag") != 0)
	{
		int_error("Extracting the user_passwd_resetting_result_flag failed");
	}

	user_passwd_resetting_result_flag = (strcmp(user_passwd_resetting_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!user_passwd_resetting_result_flag)
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

boolean remove_user(char *username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    user_removal_result_flag_str_tmp[FLAG_LENGTH + 1];    // "0" or "1"
	boolean user_removal_result_flag;

	// Connect to User Authority
	if(!connect_to_user_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", USER_REMOVAL, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}	

	// Send user removal information
	write_token_into_buffer("username", username, true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending user removal information failed");
		goto ERROR;
	}

	// Receive a user removal result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a user removal result failed");
		goto ERROR;
	}

	// Get a user removal result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, user_removal_result_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "user_removal_result_flag") != 0)
	{
		int_error("Extracting the user_removal_result_flag failed");
	}

	user_removal_result_flag = (strcmp(user_removal_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!user_removal_result_flag)
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

boolean remove_user_attribute(char *username, char *attribute_name, char *attribute_authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    user_attribute_removal_result_flag_str_tmp[FLAG_LENGTH + 1];    // "0" or "1"
	boolean user_attribute_removal_result_flag;

	// Connect to User Authority
	if(!connect_to_user_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", USER_ATTRIBUTE_REMOVAL, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}	

	// Send user attribute removal information
	write_token_into_buffer("username", username, true, buffer);
	write_token_into_buffer("attribute_name", attribute_name, false, buffer);
	write_token_into_buffer("attribute_authority_name", attribute_authority_name, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending user attribute removal information failed");
		goto ERROR;
	}

	// Receive a user attribute removal result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a user attribute removal result failed");
		goto ERROR;
	}

	// Get a user attribute removal result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, user_attribute_removal_result_flag_str_tmp) != READ_TOKEN_SUCCESS 
		|| strcmp(token_name, "user_attribute_removal_result_flag") != 0)
	{
		int_error("Extracting the user_attribute_removal_result_flag failed");
	}

	user_attribute_removal_result_flag = (strcmp(user_attribute_removal_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!user_attribute_removal_result_flag)
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

boolean register_admin(char *username, char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler           = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler     = backend_fatal_alert_msg_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    admin_registration_result_flag_str_tmp[FLAG_LENGTH + 1];     // "0" or "1"
	boolean admin_registration_result_flag;

	// Connect to User Authority
	if(!connect_to_user_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", ADMIN_REGISTRATION, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

	// Send admin registration information
	write_token_into_buffer("username", username, true, buffer);
	write_token_into_buffer("email_address", email_address, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending admin registration information failed");
		goto ERROR;
	}

	// Receive an admin registration result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving an admin registration result failed");
		goto ERROR;
	}

	// Get an admin registration result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, admin_registration_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "admin_registration_result_flag") != 0)
	{
		int_error("Extracting the admin_registration_result_flag failed");
	}

	admin_registration_result_flag = (strcmp(admin_registration_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!admin_registration_result_flag)
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

boolean edit_admin_email_address(char *username, char *email_address, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler           = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler     = backend_fatal_alert_msg_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    admin_email_address_editing_result_flag_str_tmp[FLAG_LENGTH + 1];     // "0" or "1"
	boolean admin_email_address_editing_result_flag;

	// Connect to User Authority
	if(!connect_to_user_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", ADMIN_EMAIL_ADDRESS_EDITING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

	// Send admin's e-mail address editing information
	write_token_into_buffer("username", username, true, buffer);
	write_token_into_buffer("email_address", email_address, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending admin's e-mail address editing information failed");
		goto ERROR;
	}

	// Receive an admin's e-mail address editing result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving an admin's e-mail address editing result failed");
		goto ERROR;
	}

	// Get an admin's e-mail address editing result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, admin_email_address_editing_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "admin_email_address_editing_result_flag") != 0)
	{
		int_error("Extracting the admin_email_address_editing_result_flag failed");
	}

	admin_email_address_editing_result_flag = (strcmp(admin_email_address_editing_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!admin_email_address_editing_result_flag)
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

boolean reset_admin_passwd(char *username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    admin_passwd_resetting_result_flag_str_tmp[FLAG_LENGTH + 1];    // "0" or "1"
	boolean admin_passwd_resetting_result_flag;

	// Connect to User Authority
	if(!connect_to_user_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", ADMIN_PASSWD_RESETTING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}	

	// Send admin password resetting information
	write_token_into_buffer("username", username, true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending admin password resetting information failed");
		goto ERROR;
	}

	// Receive an admin password resetting result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving an admin password resetting result failed");
		goto ERROR;
	}

	// Get an admin password resetting result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, admin_passwd_resetting_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "admin_passwd_resetting_result_flag") != 0)
	{
		int_error("Extracting the admin_passwd_resetting_result_flag failed");
	}

	admin_passwd_resetting_result_flag = (strcmp(admin_passwd_resetting_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!admin_passwd_resetting_result_flag)
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

boolean remove_admin(char *username, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    admin_removal_result_flag_str_tmp[FLAG_LENGTH + 1];    // "0" or "1"
	boolean admin_removal_result_flag;

	// Connect to User Authority
	if(!connect_to_user_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", ADMIN_REMOVAL, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}	

	// Send admin removal information
	write_token_into_buffer("username", username, true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending admin removal information failed");
		goto ERROR;
	}

	// Receive an admin removal result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving an admin removal result failed");
		goto ERROR;
	}

	// Get an admin removal result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, admin_removal_result_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "admin_removal_result_flag") != 0)
	{
		int_error("Extracting the admin_removal_result_flag failed");
	}

	admin_removal_result_flag = (strcmp(admin_removal_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!admin_removal_result_flag)
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




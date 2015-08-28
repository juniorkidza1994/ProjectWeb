#include "client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH "Client_cache/client_user_transaction_auditing.calculating_ssl_cert_hash"

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)             = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg)       = NULL;

static void (*add_transaction_login_log_to_table_callback_handler)(
	char *date_time, char *ip_address, boolean is_logout_flag)             = NULL;

static void (*add_transaction_event_log_to_table_callback_handler)(
	char *date_time, char *actor_name, char *actor_authority_name, 
	boolean is_actor_admin_flag, char *object_description, 
	char *event_description, char *object_owner_name, 
	char *object_owner_authority_name, boolean is_object_owner_admin_flag, 
	char *actor_ip_address)           				       = NULL;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);
static void add_transaction_login_log_to_table_handler_callback(char *date_time, char *ip_address, boolean is_logout_flag);
static void add_transaction_event_log_to_table_handler_callback(char *date_time, char *actor_name, char *actor_authority_name, 
	boolean is_actor_admin_flag, char *object_description, char *event_description, char *object_owner_name, char *object_owner_authority_name, 
	boolean is_object_owner_admin_flag, char *actor_ip_address);

static boolean connect_to_transaction_log_auditing_service(SSL **ssl_conn_ret);
static void audit_transaction_user_login_log(char *request);
static void audit_transaction_user_event_log(char *request);

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

static void add_transaction_login_log_to_table_handler_callback(char *date_time, char *ip_address, boolean is_logout_flag)
{
	if(add_transaction_login_log_to_table_callback_handler)
	{
		add_transaction_login_log_to_table_callback_handler(date_time, ip_address, is_logout_flag);
	}
	else  // NULL
	{
		int_error("add_transaction_login_log_to_table_callback_handler is NULL");
	}
}

static void add_transaction_event_log_to_table_handler_callback(char *date_time, char *actor_name, char *actor_authority_name, 
	boolean is_actor_admin_flag, char *object_description, char *event_description, char *object_owner_name, char *object_owner_authority_name, 
	boolean is_object_owner_admin_flag, char *actor_ip_address)
{
	if(add_transaction_event_log_to_table_callback_handler)
	{
		add_transaction_event_log_to_table_callback_handler(date_time, actor_name, actor_authority_name, is_actor_admin_flag, object_description, 
			event_description, object_owner_name, object_owner_authority_name, is_object_owner_admin_flag, actor_ip_address);
	}
	else  // NULL
	{
		int_error("add_transaction_event_log_to_table_callback_handler is NULL");
	}
}

static boolean connect_to_transaction_log_auditing_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    audit_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to Audit Server
	sprintf(audit_server_addr, "%s:%s", GLOBAL_audit_server_ip_addr, AS_TRANSACTION_LOG_AUDITING_PORT);
	bio_conn = BIO_new_connect(audit_server_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		backend_alert_msg_callback_handler("Connecting to audit server failed");
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

	hosts[0] = AUDIT_SERVER_CN;
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

static void audit_transaction_user_login_log(char *request)
{
	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    is_end_of_transaction_login_logs_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_transaction_login_logs_flag;
	char    date_time[DATETIME_STR_LENGTH + 1];
	char    ip_address[IP_ADDRESS_LENGTH + 1];
	char    is_logout_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_logout_flag;

	boolean found_log_flag = false; 

	// Connect to Audit Server
	if(!connect_to_transaction_log_auditing_service(&ssl_conn))
		goto ERROR;

	// Send transaction log auditing request information
	strcpy(buffer, request);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending transaction log auditing request information failed");
		goto ERROR;
	}

	while(1)
	{
		// Receive transaction login log information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			backend_alert_msg_handler_callback("Receiving transaction login log information failed");
			goto ERROR;
		}

		// Get transaction login log information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_transaction_login_logs_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_transaction_login_logs_flag") != 0)
		{
			int_error("Extracting the is_end_of_transaction_login_logs_flag failed");
		}

		is_end_of_transaction_login_logs_flag = (strcmp(is_end_of_transaction_login_logs_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_transaction_login_logs_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, date_time) != READ_TOKEN_SUCCESS || strcmp(token_name, "date_time") != 0)
		{
			int_error("Extracting the date_time failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, ip_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "ip_address") != 0)
		{
			int_error("Extracting the ip_address failed");
		}

		if(read_token_from_buffer(buffer, 4, token_name, is_logout_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "is_logout_flag") != 0)
		{
			int_error("Extracting the is_logout_flag failed");
		}

		is_logout_flag = (strcmp(is_logout_flag_str_tmp, "1") == 0) ? true : false;

		// Add a transaction login log to a table
		add_transaction_login_log_to_table_handler_callback(date_time, ip_address, is_logout_flag);

		found_log_flag = true;
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;

	if(!found_log_flag)
	{
		backend_alert_msg_handler_callback("Transaction log does not found");
	}

	return;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return;
}

void audit_all_transaction_user_login_log(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*add_transaction_login_log_to_table_callback_handler_ptr)(char *date_time, char *ip_address, boolean is_logout_flag))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler                  = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler            = backend_fatal_alert_msg_callback_handler_ptr;
	add_transaction_login_log_to_table_callback_handler = add_transaction_login_log_to_table_callback_handler_ptr;

	char request[BUFFER_LENGTH + 1];

	// Transaction log auditing request information
	write_token_into_buffer("request_type", USER_LOGIN_LOG_AUDITING, true, request);
	write_token_into_buffer("audit_all_transactions_flag", "1", false, request);

	audit_transaction_user_login_log(request);
}

void audit_some_period_time_transaction_user_login_log(char *start_date_time, char *end_date_time, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*add_transaction_login_log_to_table_callback_handler_ptr)(char *date_time, 
	char *ip_address, boolean is_logout_flag))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler                  = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler            = backend_fatal_alert_msg_callback_handler_ptr;
	add_transaction_login_log_to_table_callback_handler = add_transaction_login_log_to_table_callback_handler_ptr;

	char request[BUFFER_LENGTH + 1];

	// Transaction log auditing request information
	write_token_into_buffer("request_type", USER_LOGIN_LOG_AUDITING, true, request);
	write_token_into_buffer("audit_all_transactions_flag", "0", false, request);
	write_token_into_buffer("start_date_time", start_date_time, false, request);
	write_token_into_buffer("end_date_time", end_date_time, false, request);

	audit_transaction_user_login_log(request);
}

static void audit_transaction_user_event_log(char *request)
{
	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    is_end_of_transaction_event_logs_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_transaction_event_logs_flag;
	char    actor_name[USER_NAME_LENGTH + 1];
	char    actor_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char    is_actor_admin_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_actor_admin_flag;
	char    object_owner_name[USER_NAME_LENGTH + 1];
	char    object_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char    is_object_owner_admin_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_object_owner_admin_flag;
	char    object_description[DATA_DESCRIPTION_LENGTH + 1];
	char    event_description[EVENT_DESCRIPTION_LENGTH + 1];
	char    date_time[DATETIME_STR_LENGTH + 1];
	char    actor_ip_address[IP_ADDRESS_LENGTH + 1];

	boolean found_log_flag = false;

	// Connect to Audit Server
	if(!connect_to_transaction_log_auditing_service(&ssl_conn))
		goto ERROR;

	// Send transaction log auditing request information
	strcpy(buffer, request);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending transaction log auditing request information failed");
		goto ERROR;
	}

	while(1)
	{
		// Receive transaction event log information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			backend_alert_msg_handler_callback("Receiving transaction event log information failed");
			goto ERROR;
		}

		// Get transaction event log information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_transaction_event_logs_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_transaction_event_logs_flag") != 0)
		{
			int_error("Extracting the is_end_of_transaction_event_logs_flag failed");
		}

		is_end_of_transaction_event_logs_flag = (strcmp(is_end_of_transaction_event_logs_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_transaction_event_logs_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, actor_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "actor_name") != 0)
		{
			int_error("Extracting the actor_name failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, actor_authority_name) != READ_TOKEN_SUCCESS 
			|| strcmp(token_name, "actor_authority_name") != 0)
		{
			int_error("Extracting the actor_authority_name failed");
		}

		if(read_token_from_buffer(buffer, 4, token_name, is_actor_admin_flag_str_tmp) != READ_TOKEN_SUCCESS 
			|| strcmp(token_name, "is_actor_admin_flag") != 0)
		{
			int_error("Extracting the is_actor_admin_flag failed");
		}

		is_actor_admin_flag = (strcmp(is_actor_admin_flag_str_tmp, "1") == 0) ? true : false;

		if(read_token_from_buffer(buffer, 5, token_name, object_owner_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "object_owner_name") != 0)
		{
			int_error("Extracting the object_owner_name failed");
		}

		if(read_token_from_buffer(buffer, 6, token_name, object_owner_authority_name) != READ_TOKEN_SUCCESS 
			|| strcmp(token_name, "object_owner_authority_name") != 0)
		{
			int_error("Extracting the object_owner_authority_name failed");
		}

		if(read_token_from_buffer(buffer, 7, token_name, is_object_owner_admin_flag_str_tmp) != READ_TOKEN_SUCCESS 
			|| strcmp(token_name, "is_object_owner_admin_flag") != 0)
		{
			int_error("Extracting the is_object_owner_admin_flag failed");
		}

		is_object_owner_admin_flag = (strcmp(is_object_owner_admin_flag_str_tmp, "1") == 0) ? true : false;

		if(read_token_from_buffer(buffer, 8, token_name, object_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "object_description") != 0)
		{
			int_error("Extracting the object_description failed");
		}

		if(read_token_from_buffer(buffer, 9, token_name, event_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "event_description") != 0)
		{
			int_error("Extracting the event_description failed");
		}

		if(read_token_from_buffer(buffer, 10, token_name, date_time) != READ_TOKEN_SUCCESS || strcmp(token_name, "date_time") != 0)
		{
			int_error("Extracting the date_time failed");
		}

		if(read_token_from_buffer(buffer, 11, token_name, actor_ip_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "actor_ip_address") != 0)
		{
			int_error("Extracting the actor_ip_address failed");
		}

		// Add a transaction event log to a table
		add_transaction_event_log_to_table_handler_callback(date_time, actor_name, actor_authority_name, is_actor_admin_flag, object_description, 
			event_description, object_owner_name, object_owner_authority_name, is_object_owner_admin_flag, actor_ip_address);

		found_log_flag = true;
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;

	if(!found_log_flag)
	{
		backend_alert_msg_handler_callback("Transaction log does not found");
	}

	return;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return;
}

void audit_all_transaction_user_event_log(void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*add_transaction_event_log_to_table_callback_handler_ptr)(char *date_time, char *actor_name, char *actor_authority_name, 
	boolean is_actor_admin_flag, char *object_description, char *event_description, char *object_owner_name, char *object_owner_authority_name, 
	boolean is_object_owner_admin_flag, char *actor_ip_address))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler                  = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler            = backend_fatal_alert_msg_callback_handler_ptr;
	add_transaction_event_log_to_table_callback_handler = add_transaction_event_log_to_table_callback_handler_ptr;

	char request[BUFFER_LENGTH + 1];

	// Transaction log auditing request information
	write_token_into_buffer("request_type", USER_EVENT_LOG_AUDITING, true, request);
	write_token_into_buffer("audit_all_transactions_flag", "1", false, request);

	audit_transaction_user_event_log(request);
}

void audit_some_period_time_transaction_user_event_log(char *start_date_time, char *end_date_time, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*add_transaction_event_log_to_table_callback_handler_ptr)(char *date_time, 
	char *actor_name, char *actor_authority_name, boolean is_actor_admin_flag, char *object_description, char *event_description, char *object_owner_name, 
	char *object_owner_authority_name, boolean is_object_owner_admin_flag, char *actor_ip_address))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler                  = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler            = backend_fatal_alert_msg_callback_handler_ptr;
	add_transaction_event_log_to_table_callback_handler = add_transaction_event_log_to_table_callback_handler_ptr;

	char request[BUFFER_LENGTH + 1];

	// Transaction log auditing request information
	write_token_into_buffer("request_type", USER_EVENT_LOG_AUDITING, true, request);
	write_token_into_buffer("audit_all_transactions_flag", "0", false, request);
	write_token_into_buffer("start_date_time", start_date_time, false, request);
	write_token_into_buffer("end_date_time", end_date_time, false, request);	

	audit_transaction_user_event_log(request);
}




#include "client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH "Client_cache/client_phr_transaction_log_recording.calculating_ssl_cert_hash"

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)       = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg) = NULL;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);

static boolean connect_to_transaction_log_recording_service(SSL **ssl_conn_ret);
static boolean record_phr_transaction_log(char *phr_owner_name, char *phr_owner_authority_name, char *object_description, char *event_description);

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

static boolean connect_to_transaction_log_recording_service(SSL **ssl_conn_ret)
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

static boolean record_phr_transaction_log(char *phr_owner_name, char *phr_owner_authority_name, char *object_description, char *event_description)
{
	SSL  *ssl_conn = NULL;
	char buffer[BUFFER_LENGTH + 1];

	// Connect to Audit Server
	if(!connect_to_transaction_log_recording_service(&ssl_conn))
		goto ERROR;

	// Send a request type
	write_token_into_buffer("request_type", EVENT_LOG_RECORDING, true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending a request type failed");
		goto ERROR;
	}

	// Send a transaction log
	write_token_into_buffer("actor_name", GLOBAL_username, true, buffer);
	write_token_into_buffer("actor_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_owner_name", phr_owner_name, false, buffer);
	write_token_into_buffer("object_owner_authority_name", phr_owner_authority_name, false, buffer);
	write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("affected_username", NO_REFERENCE_USERNAME, false, buffer);
	write_token_into_buffer("affected_user_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_description", object_description, false, buffer);
	write_token_into_buffer("event_description", event_description, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending a transaction log failed\n");
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

boolean record_phr_encrypting_transaction_log(char *phr_owner_name, char *phr_owner_authority_name, char *phr_description, boolean success_flag, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	if(success_flag)
	{
		return record_phr_transaction_log(phr_owner_name, phr_owner_authority_name, phr_description, PHR_ENCRYPTION_SUCCEEDED);
	}
	else
	{
		return record_phr_transaction_log(phr_owner_name, phr_owner_authority_name, phr_description, PHR_ENCRYPTION_FAILED);
	}
}

boolean record_phr_uploading_transaction_log(char *phr_owner_name, char *phr_owner_authority_name, char *phr_description, boolean success_flag, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	if(success_flag)
	{
		return record_phr_transaction_log(phr_owner_name, phr_owner_authority_name, phr_description, PHR_UPLOAD_SUCCEEDED);
	}
	else
	{
		return record_phr_transaction_log(phr_owner_name, phr_owner_authority_name, phr_description, PHR_UPLOAD_FAILED);
	}
}

boolean record_phr_downloading_transaction_log(char *phr_owner_name, char *phr_owner_authority_name, char *phr_description, boolean success_flag, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	if(success_flag)
	{
		return record_phr_transaction_log(phr_owner_name, phr_owner_authority_name, phr_description, PHR_DOWNLOAD_SUCCEEDED);
	}
	else
	{
		return record_phr_transaction_log(phr_owner_name, phr_owner_authority_name, phr_description, PHR_DOWNLOAD_FAILED);
	}
}

boolean record_phr_decrypting_transaction_log(char *phr_owner_name, char *phr_owner_authority_name, char *phr_description, boolean success_flag, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	if(success_flag)
	{
		return record_phr_transaction_log(phr_owner_name, phr_owner_authority_name, phr_description, PHR_DECRYPTION_SUCCEEDED);
	}
	else
	{
		return record_phr_transaction_log(phr_owner_name, phr_owner_authority_name, phr_description, PHR_DECRYPTION_FAILED);
	}
}

boolean record_phr_deletion_transaction_log(char *phr_owner_name, char *phr_owner_authority_name, char *phr_description, boolean success_flag, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	if(success_flag)
	{
		return record_phr_transaction_log(phr_owner_name, phr_owner_authority_name, phr_description, PHR_DELETION_SUCCEEDED);
	}
	else
	{
		return record_phr_transaction_log(phr_owner_name, phr_owner_authority_name, phr_description, PHR_DELETION_FAILED);
	}
}

boolean record_failed_uploading_emergency_key_params_transaction_log(char *phr_owner_name, char *phr_owner_authority_name, char *phr_description, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	return record_phr_transaction_log(phr_owner_name, phr_owner_authority_name, phr_description, EMERGENCY_KEY_PARAMS_UPLOADING_FAILED);
}




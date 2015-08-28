#include "client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH            "Client_cache/client_access_permission_verification.calculating_ssl_cert_hash"
#define CALCULATING_FULL_PHR_OWNER_NAME_HASH_PATH "Client_cache/client_access_permission_verification.calculating_full_phr_owner_name_hash"
#define SGN_ACCESS_GRANTING_TICKET_PATH           "Client_cache/client_access_permission_verification.sgn_access_granting_ticket"
#define ACCESS_GRANTING_TICKET_PATH               "Client_cache/client_access_permission_verification.access_granting_ticket"

#define REMAINING_ACCESS_GRANTING_TICKET_LIFETIME 3 // in minute unit

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)       = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg) = NULL;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);

static boolean verify_access_granting_ticket(char *access_granting_ticket_buffer, char *phr_owner_name_cmp, char *phr_owner_authority_name_cmp);
static boolean verify_access_granting_ticket_lifetime(char *access_granting_ticket_buffer);
static boolean has_upload_permission(char *access_granting_ticket_buffer);
static boolean has_download_permission(char *access_granting_ticket_buffer);
static boolean has_delete_permission(char *access_granting_ticket_buffer);
static boolean connect_to_access_granting_ticket_requesting_service(SSL **ssl_conn_ret);
static boolean request_access_granting_ticket(char *access_granting_ticket_path, char *phr_owner_name, char *phr_owner_authority_name);

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

static boolean verify_access_granting_ticket(char *access_granting_ticket_buffer, char *phr_owner_name_cmp, char *phr_owner_authority_name_cmp)
{
	char token_name[TOKEN_NAME_LENGTH + 1];
	char ticket_owner_name[USER_NAME_LENGTH + 1];
	char ticket_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char phr_owner_name[USER_NAME_LENGTH + 1];
	char phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];

	// Get the access granting ticket info tokens from buffer
	if(read_token_from_buffer(access_granting_ticket_buffer, 1, token_name, ticket_owner_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "ticket_owner_name") != 0)
	{
		int_error("Extracting the ticket_owner_name failed");
	}

	if(strcmp(ticket_owner_name, GLOBAL_username) != 0)
		return false;

	if(read_token_from_buffer(access_granting_ticket_buffer, 2, token_name, ticket_owner_authority_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "ticket_owner_authority_name") != 0)
	{
		int_error("Extracting the ticket_owner_authority_name failed");
	}

	if(strcmp(ticket_owner_authority_name, GLOBAL_authority_name) != 0)
		return false;

	if(read_token_from_buffer(access_granting_ticket_buffer, 3, token_name, phr_owner_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "phr_owner_name") != 0)
	{
		int_error("Extracting the phr_owner_name failed");
	}

	if(strcmp(phr_owner_name, phr_owner_name_cmp) != 0)
		return false;

	if(read_token_from_buffer(access_granting_ticket_buffer, 4, token_name, phr_owner_authority_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "phr_owner_authority_name") != 0)
	{
		int_error("Extracting the phr_owner_authority_name failed");
	}

	if(strcmp(phr_owner_authority_name, phr_owner_authority_name_cmp) != 0)
		return false;

	return true;
}

static boolean verify_access_granting_ticket_lifetime(char *access_granting_ticket_buffer)
{
	char      token_name[TOKEN_NAME_LENGTH + 1];
	char      expired_date_time_str[DATETIME_STR_LENGTH + 1];      // Format is "YYYY-MM-DD.HH:mm:ss"

	int       diff_time;   // In second unit
	time_t    now, expired_date_time;
	struct tm tm_expired_date_time;

	// Get the access granting ticket lifetime token from buffer
	if(read_token_from_buffer(access_granting_ticket_buffer, 8, token_name, expired_date_time_str) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "expired_date_time") != 0)
	{
		int_error("Extracting the expired_date_time failed");
	}

	// Construct ticket expired date and time from string format to time_t format
	memset(&tm_expired_date_time, 0, sizeof(struct tm));
	strptime(expired_date_time_str, "%Y-%m-%d.%X", &tm_expired_date_time); 
	expired_date_time = mktime(&tm_expired_date_time);

	// Get current date and time
	now = time(NULL);

	// Find different time
	diff_time = (int)difftime(expired_date_time, now);
	if(diff_time >= REMAINING_ACCESS_GRANTING_TICKET_LIFETIME*60)
		return true;
	else
		return false;
}

static boolean has_upload_permission(char *access_granting_ticket_buffer)
{
	char token_name[TOKEN_NAME_LENGTH + 1];
	char upload_permission_flag_str[FLAG_LENGTH + 1];     // "0" or "1"
	
	// Get the upload permission flag token from buffer
	if(read_token_from_buffer(access_granting_ticket_buffer, 5, token_name, upload_permission_flag_str) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "upload_permission_flag") != 0)
	{
		int_error("Extracting the upload_permission_flag failed");
	}
	
	if(strcmp(upload_permission_flag_str, "1") == 0)
		return true;
	else
		return false;
}

static boolean has_download_permission(char *access_granting_ticket_buffer)
{
	char token_name[TOKEN_NAME_LENGTH + 1];
	char download_permission_flag_str[FLAG_LENGTH + 1];     // "0" or "1"
	
	// Get the download permission flag token from buffer
	if(read_token_from_buffer(access_granting_ticket_buffer, 6, token_name, download_permission_flag_str) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "download_permission_flag") != 0)
	{
		int_error("Extracting the download_permission_flag failed");
	}
	
	if(strcmp(download_permission_flag_str, "1") == 0)
		return true;
	else
		return false;
}

static boolean has_delete_permission(char *access_granting_ticket_buffer)
{
	char token_name[TOKEN_NAME_LENGTH + 1];
	char delete_permission_flag_str[FLAG_LENGTH + 1];     // "0" or "1"
	
	// Get the delete permission flag token from buffer
	if(read_token_from_buffer(access_granting_ticket_buffer, 7, token_name, delete_permission_flag_str) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "delete_permission_flag") != 0)
	{
		int_error("Extracting the delete_permission_flag failed");
	}
	
	if(strcmp(delete_permission_flag_str, "1") == 0)
		return true;
	else
		return false;
}

static boolean connect_to_access_granting_ticket_requesting_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    user_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to User Authority
	sprintf(user_auth_addr, "%s:%s", GLOBAL_user_auth_ip_addr, UA_ACCESS_GRANTING_TICKET_RESPONDING_PORT);
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

static boolean request_access_granting_ticket(char *access_granting_ticket_path, char *phr_owner_name, char *phr_owner_authority_name)
{
	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    access_granting_ticket_requesting_result_flag_str_tmp[FLAG_LENGTH + 1];    // "0" or "1"
	boolean access_granting_ticket_requesting_result_flag;

	// Connect to User Authority
	if(!connect_to_access_granting_ticket_requesting_service(&ssl_conn))
		goto ERROR;

	// Send the access granting ticket requesting information
	write_token_into_buffer("desired_phr_owner_name", phr_owner_name, true, buffer);
	write_token_into_buffer("desired_phr_owner_authority_name", phr_owner_authority_name, false, buffer);
	write_token_into_buffer("ticket_passwd", GLOBAL_passwd, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending access granting ticket requesting information failed");
		goto ERROR;
	}

	// Receive access granting ticket requesting result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving access granting ticket requesting failed");
		goto ERROR;
	}

	// Get an access granting ticket requesting result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, access_granting_ticket_requesting_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "access_granting_ticket_requesting_result_flag") != 0)
	{
		int_error("Extracting the access_granting_ticket_requesting_result_flag failed");
	}

	access_granting_ticket_requesting_result_flag = (strcmp(access_granting_ticket_requesting_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!access_granting_ticket_requesting_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, error_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(error_msg);
		goto ERROR;
	}

	// Receive the access granting ticket
	if(!SSL_recv_file(ssl_conn, access_granting_ticket_path))
	{
		backend_alert_msg_handler_callback("Receiving an access granting ticket failed");
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

boolean verify_upload_permission(char *phr_owner_name, char *phr_owner_authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	char err_msg[ERR_MSG_LENGTH + 1];
	char full_phr_owner_name[AUTHORITY_NAME_LENGTH + USER_NAME_LENGTH + 1];
	char full_phr_owner_name_hash[SHA1_DIGEST_LENGTH + 1];
	char access_granting_ticket_path[PATH_LENGTH + 1];
	char access_granting_ticket_buffer[BUFFER_LENGTH + 1];

	// Generate an access granting ticket path
	sprintf(full_phr_owner_name, "%s%s", phr_owner_authority_name, phr_owner_name);
	sum_sha1_from_string(full_phr_owner_name, strlen(full_phr_owner_name), full_phr_owner_name_hash, CALCULATING_FULL_PHR_OWNER_NAME_HASH_PATH);
	sprintf(access_granting_ticket_path, "%s/%s", CACHE_DIRECTORY_PATH, full_phr_owner_name_hash);

	if(!file_exists(access_granting_ticket_path))
	{
		// Request for an access granting ticket
		if(!request_access_granting_ticket(access_granting_ticket_path, phr_owner_name, phr_owner_authority_name))
		{
			goto ERROR;
		}
	}

	// Decrypt the access granting ticket with the user's password
	if(!des3_decrypt(access_granting_ticket_path, SGN_ACCESS_GRANTING_TICKET_PATH, GLOBAL_passwd, err_msg))
	{
		fprintf(stderr, "Decrypting the access granting ticket failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Decrypting the access granting ticket failed");
		goto ERROR;
	}

	// Verify the access granting ticket with the user authority's public key
	if(!smime_verify_with_cert(SGN_ACCESS_GRANTING_TICKET_PATH, ACCESS_GRANTING_TICKET_PATH, UA_PUB_CERTFILE_PATH, err_msg))
	{
		fprintf(stderr, "Verifying the access granting ticket signature failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Verifying the access granting ticket signature failed");
		goto ERROR;
	}

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

	// Read the access granting ticket info into a buffer
	if(!read_bin_file(ACCESS_GRANTING_TICKET_PATH, access_granting_ticket_buffer, sizeof(access_granting_ticket_buffer), NULL))
	{
		backend_alert_msg_handler_callback("Reading the access granting ticket info failed");
		goto ERROR;
	}

	unlink(ACCESS_GRANTING_TICKET_PATH);

	if(!verify_access_granting_ticket(access_granting_ticket_buffer, phr_owner_name, phr_owner_authority_name))
	{
		backend_fatal_alert_msg_handler_callback("Verifying the access granting ticket failed");
		goto ERROR;
	}

	if(!verify_access_granting_ticket_lifetime(access_granting_ticket_buffer))
	{
		// Request for an access granting ticket
		if(!request_access_granting_ticket(access_granting_ticket_path, phr_owner_name, phr_owner_authority_name))
		{
			goto ERROR;
		}

		// Decrypt the access granting ticket with the user's password
		if(!des3_decrypt(access_granting_ticket_path, SGN_ACCESS_GRANTING_TICKET_PATH, GLOBAL_passwd, err_msg))
		{
			fprintf(stderr, "Decrypting the access granting ticket failed\n\"%s\"\n", err_msg);
			backend_alert_msg_handler_callback("Decrypting the access granting ticket failed");
			goto ERROR;
		}

		// Verify the access granting ticket with the user authority's public key
		if(!smime_verify_with_cert(SGN_ACCESS_GRANTING_TICKET_PATH, ACCESS_GRANTING_TICKET_PATH, UA_PUB_CERTFILE_PATH, err_msg))
		{
			fprintf(stderr, "Verifying the access granting ticket failed\n\"%s\"\n", err_msg);
			backend_alert_msg_handler_callback("Verifying the access granting ticket failed");
			goto ERROR;
		}

		unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

		// Read the access granting ticket info into a buffer
		if(!read_bin_file(ACCESS_GRANTING_TICKET_PATH, access_granting_ticket_buffer, sizeof(access_granting_ticket_buffer), NULL))
		{
			backend_alert_msg_handler_callback("Reading the access granting ticket info failed");
			goto ERROR;
		}

		unlink(ACCESS_GRANTING_TICKET_PATH);

		if(!verify_access_granting_ticket(access_granting_ticket_buffer, phr_owner_name, phr_owner_authority_name))
		{
			backend_fatal_alert_msg_handler_callback("Verifying the access granting ticket failed");
			goto ERROR;
		}

		if(!verify_access_granting_ticket_lifetime(access_granting_ticket_buffer))
		{
			backend_fatal_alert_msg_handler_callback("Verifying the access granting ticket lifetime failed");
			goto ERROR;
		}
	}

	if(!has_upload_permission(access_granting_ticket_buffer))
	{
		backend_alert_msg_handler_callback("You do not have the access permission");
		goto ERROR;
	}

	return true;

ERROR:

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);
	unlink(ACCESS_GRANTING_TICKET_PATH);
	return false;
}

boolean verify_download_permission(char *phr_owner_name, char *phr_owner_authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	char err_msg[ERR_MSG_LENGTH + 1];
	char full_phr_owner_name[AUTHORITY_NAME_LENGTH + USER_NAME_LENGTH + 1];
	char full_phr_owner_name_hash[SHA1_DIGEST_LENGTH + 1];
	char access_granting_ticket_path[PATH_LENGTH + 1];
	char access_granting_ticket_buffer[BUFFER_LENGTH + 1];

	// Generate an access granting ticket path
	sprintf(full_phr_owner_name, "%s%s", phr_owner_authority_name, phr_owner_name);
	sum_sha1_from_string(full_phr_owner_name, strlen(full_phr_owner_name), full_phr_owner_name_hash, CALCULATING_FULL_PHR_OWNER_NAME_HASH_PATH);
	sprintf(access_granting_ticket_path, "%s/%s", CACHE_DIRECTORY_PATH, full_phr_owner_name_hash);

	if(!file_exists(access_granting_ticket_path))
	{
		// Request for an access granting ticket
		if(!request_access_granting_ticket(access_granting_ticket_path, phr_owner_name, phr_owner_authority_name))
		{
			goto ERROR;
		}
	}

	// Decrypt the access granting ticket with the user's password
	if(!des3_decrypt(access_granting_ticket_path, SGN_ACCESS_GRANTING_TICKET_PATH, GLOBAL_passwd, err_msg))
	{
		fprintf(stderr, "Decrypting the access granting ticket failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Decrypting the access granting ticket failed");
		goto ERROR;
	}

	// Verify the access granting ticket with the user authority's public key
	if(!smime_verify_with_cert(SGN_ACCESS_GRANTING_TICKET_PATH, ACCESS_GRANTING_TICKET_PATH, UA_PUB_CERTFILE_PATH, err_msg))
	{
		fprintf(stderr, "Verifying the access granting ticket signature failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Verifying the access granting ticket signature failed");
		goto ERROR;
	}

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

	// Read the access granting ticket info into a buffer
	if(!read_bin_file(ACCESS_GRANTING_TICKET_PATH, access_granting_ticket_buffer, sizeof(access_granting_ticket_buffer), NULL))
	{
		backend_alert_msg_handler_callback("Reading the access granting ticket info failed");
		goto ERROR;
	}

	unlink(ACCESS_GRANTING_TICKET_PATH);

	if(!verify_access_granting_ticket(access_granting_ticket_buffer, phr_owner_name, phr_owner_authority_name))
	{
		backend_fatal_alert_msg_handler_callback("Verifying the access granting ticket failed");
		goto ERROR;
	}

	if(!verify_access_granting_ticket_lifetime(access_granting_ticket_buffer))
	{
		// Request for an access granting ticket
		if(!request_access_granting_ticket(access_granting_ticket_path, phr_owner_name, phr_owner_authority_name))
		{
			goto ERROR;
		}

		// Decrypt the access granting ticket with the user's password
		if(!des3_decrypt(access_granting_ticket_path, SGN_ACCESS_GRANTING_TICKET_PATH, GLOBAL_passwd, err_msg))
		{
			fprintf(stderr, "Decrypting the access granting ticket failed\n\"%s\"\n", err_msg);
			backend_alert_msg_handler_callback("Decrypting the access granting ticket failed");
			goto ERROR;
		}

		// Verify the access granting ticket with the user authority's public key
		if(!smime_verify_with_cert(SGN_ACCESS_GRANTING_TICKET_PATH, ACCESS_GRANTING_TICKET_PATH, UA_PUB_CERTFILE_PATH, err_msg))
		{
			fprintf(stderr, "Verifying the access granting ticket failed\n\"%s\"\n", err_msg);
			backend_alert_msg_handler_callback("Verifying the access granting ticket failed");
			goto ERROR;
		}

		unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

		// Read the access granting ticket info into a buffer
		if(!read_bin_file(ACCESS_GRANTING_TICKET_PATH, access_granting_ticket_buffer, sizeof(access_granting_ticket_buffer), NULL))
		{
			backend_alert_msg_handler_callback("Reading the access granting ticket info failed");
			goto ERROR;
		}

		unlink(ACCESS_GRANTING_TICKET_PATH);

		if(!verify_access_granting_ticket(access_granting_ticket_buffer, phr_owner_name, phr_owner_authority_name))
		{
			backend_fatal_alert_msg_handler_callback("Verifying the access granting ticket failed");
			goto ERROR;
		}

		if(!verify_access_granting_ticket_lifetime(access_granting_ticket_buffer))
		{
			backend_fatal_alert_msg_handler_callback("Verifying the access granting ticket lifetime failed");
			goto ERROR;
		}
	}

	if(!has_download_permission(access_granting_ticket_buffer))
	{
		backend_alert_msg_handler_callback("You do not have the access permission");
		goto ERROR;
	}

	return true;

ERROR:

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);
	unlink(ACCESS_GRANTING_TICKET_PATH);
	return false;
}

boolean verify_delete_permission(char *phr_owner_name, char *phr_owner_authority_name, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	char err_msg[ERR_MSG_LENGTH + 1];
	char full_phr_owner_name[AUTHORITY_NAME_LENGTH + USER_NAME_LENGTH + 1];
	char full_phr_owner_name_hash[SHA1_DIGEST_LENGTH + 1];
	char access_granting_ticket_path[PATH_LENGTH + 1];
	char access_granting_ticket_buffer[BUFFER_LENGTH + 1];

	// Generate an access granting ticket path
	sprintf(full_phr_owner_name, "%s%s", phr_owner_authority_name, phr_owner_name);
	sum_sha1_from_string(full_phr_owner_name, strlen(full_phr_owner_name), full_phr_owner_name_hash, CALCULATING_FULL_PHR_OWNER_NAME_HASH_PATH);
	sprintf(access_granting_ticket_path, "%s/%s", CACHE_DIRECTORY_PATH, full_phr_owner_name_hash);

	if(!file_exists(access_granting_ticket_path))
	{
		// Request for an access granting ticket
		if(!request_access_granting_ticket(access_granting_ticket_path, phr_owner_name, phr_owner_authority_name))
		{
			goto ERROR;
		}
	}

	// Decrypt the access granting ticket with the user's password
	if(!des3_decrypt(access_granting_ticket_path, SGN_ACCESS_GRANTING_TICKET_PATH, GLOBAL_passwd, err_msg))
	{
		fprintf(stderr, "Decrypting the access granting ticket failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Decrypting the access granting ticket failed");
		goto ERROR;
	}

	// Verify the access granting ticket with the user authority's public key
	if(!smime_verify_with_cert(SGN_ACCESS_GRANTING_TICKET_PATH, ACCESS_GRANTING_TICKET_PATH, UA_PUB_CERTFILE_PATH, err_msg))
	{
		fprintf(stderr, "Verifying the access granting ticket signature failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Verifying the access granting ticket signature failed");
		goto ERROR;
	}

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

	// Read the access granting ticket info into a buffer
	if(!read_bin_file(ACCESS_GRANTING_TICKET_PATH, access_granting_ticket_buffer, sizeof(access_granting_ticket_buffer), NULL))
	{
		backend_alert_msg_handler_callback("Reading the access granting ticket info failed");
		goto ERROR;
	}

	unlink(ACCESS_GRANTING_TICKET_PATH);

	if(!verify_access_granting_ticket(access_granting_ticket_buffer, phr_owner_name, phr_owner_authority_name))
	{
		backend_fatal_alert_msg_handler_callback("Verifying the access granting ticket failed");
		goto ERROR;
	}

	if(!verify_access_granting_ticket_lifetime(access_granting_ticket_buffer))
	{
		// Request for an access granting ticket
		if(!request_access_granting_ticket(access_granting_ticket_path, phr_owner_name, phr_owner_authority_name))
		{
			goto ERROR;
		}

		// Decrypt the access granting ticket with the user's password
		if(!des3_decrypt(access_granting_ticket_path, SGN_ACCESS_GRANTING_TICKET_PATH, GLOBAL_passwd, err_msg))
		{
			fprintf(stderr, "Decrypting the access granting ticket failed\n\"%s\"\n", err_msg);
			backend_alert_msg_handler_callback("Decrypting the access granting ticket failed");
			goto ERROR;
		}

		// Verify the access granting ticket with the user authority's public key
		if(!smime_verify_with_cert(SGN_ACCESS_GRANTING_TICKET_PATH, ACCESS_GRANTING_TICKET_PATH, UA_PUB_CERTFILE_PATH, err_msg))
		{
			fprintf(stderr, "Verifying the access granting ticket failed\n\"%s\"\n", err_msg);
			backend_alert_msg_handler_callback("Verifying the access granting ticket failed");
			goto ERROR;
		}

		unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

		// Read the access granting ticket info into a buffer
		if(!read_bin_file(ACCESS_GRANTING_TICKET_PATH, access_granting_ticket_buffer, sizeof(access_granting_ticket_buffer), NULL))
		{
			backend_alert_msg_handler_callback("Reading the access granting ticket info failed");
			goto ERROR;
		}

		unlink(ACCESS_GRANTING_TICKET_PATH);

		if(!verify_access_granting_ticket(access_granting_ticket_buffer, phr_owner_name, phr_owner_authority_name))
		{
			backend_fatal_alert_msg_handler_callback("Verifying the access granting ticket failed");
			goto ERROR;
		}

		if(!verify_access_granting_ticket_lifetime(access_granting_ticket_buffer))
		{
			backend_fatal_alert_msg_handler_callback("Verifying the access granting ticket lifetime failed");
			goto ERROR;
		}
	}

	if(!has_delete_permission(access_granting_ticket_buffer))
	{
		backend_alert_msg_handler_callback("You do not have the access permission");
		goto ERROR;
	}

	return true;

ERROR:

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);
	unlink(ACCESS_GRANTING_TICKET_PATH);
	return false;
}




#include "client_common.h"

#define CALCULATING_SSL_CERT_HASH_PATH    	   "Client_cache/client_emergency_key_management.calculating_ssl_cert_hash"

#define EMERGENCY_CPABE_PRIV_KEY_PATH     	   "Client_cache/client_emergency_key_management.emergency_cpabe_priv_key"
#define ENC_EMERGENCY_CPABE_PRIV_KEY_PATH 	   "Client_cache/client_emergency_key_management.enc_emergency_cpabe_priv_key"
#define ENC_RECOVERY_EMERGENCY_CPABE_PRIV_KEY_PATH "Client_cache/client_emergency_key_management.enc_recovery_emergency_cpabe_priv_key"

#define EMERGENCY_TRUSTED_USER_SSL_CERT_PATH	   "Client_cache/client_emergency_key_management.emergency_trusted_user_cert"
#define CACHE_DIRECTORY_NAME			   "Client_cache"
#define PTHRESHOLD_PREFIX_NAME               	   "pthreshold"
#define ENC_PTHRESHOLD_PREFIX_NAME                 "enc_pthreshold"
#define SERIALIZABLE_OBJ_EXTENSION           	   ".ser"
#define ENC_THRESHOLD_MSG_PATH		   	   "Client_cache/enc_threshold_msg.ser"

#define CALCULATING_FULL_PHR_OWNER_NAME_HASH_PATH  "Client_cache/client_emergency_key_management.calculating_full_phr_owner_name_hash"
#define SGN_ACCESS_GRANTING_TICKET_PATH            "Client_cache/client_emergency_key_management.sgn_access_granting_ticket"

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)       = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg) = NULL;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);

static boolean connect_to_emergency_key_management_service(SSL **ssl_conn_ret);   // User Authority
static void extract_user_info(char *full_username, char *username_ret, char *authority_name_ret);
static boolean connect_to_emergency_key_params_management_service(SSL **ssl_conn_ret);    // Emergency Server
static boolean connect_to_phr_confidentiality_level_changing_service(SSL **ssl_conn_ret);   // PHR Server

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

static boolean connect_to_emergency_key_management_service(SSL **ssl_conn_ret)   // User Authority
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    user_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to User Authority
	sprintf(user_auth_addr, "%s:%s", GLOBAL_user_auth_ip_addr, UA_EMERGENCY_KEY_MANAGEMENT_PORT);
	bio_conn = BIO_new_connect(user_auth_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		backend_alert_msg_callback_handler("Connecting to the user authority failed");
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

boolean generate_unique_emergency_key(char *unique_emergency_key_attribute, char *unique_emergency_key_passwd, void (*backend_alert_msg_callback_handler_ptr)(
	char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL  *ssl_conn = NULL;
	char buffer[BUFFER_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Connect to User Authority
	if(!connect_to_emergency_key_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", EMERGENCY_KEY_GENERATING, true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

	// Send emergency key attribute information
	write_token_into_buffer("emergency_key_attribute", unique_emergency_key_attribute, true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending emergency key attribute information failed");
		goto ERROR;
	}

	// Receive the emergency key 
	if(!SSL_recv_file(ssl_conn, EMERGENCY_CPABE_PRIV_KEY_PATH))
	{
		backend_alert_msg_handler_callback("Receiving emergency key failed");
		goto ERROR;
	}

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;

	// Encrypt the emergency key using 3DES
	if(!des3_encrypt(EMERGENCY_CPABE_PRIV_KEY_PATH, ENC_EMERGENCY_CPABE_PRIV_KEY_PATH, unique_emergency_key_passwd, err_msg))
	{
		fprintf(stderr, "Encrypting the emergency key failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Encrypting the emergency key failed");
		goto ERROR;
	}

	// Encrypt the emergency key with the user's SSL public key for recovering when a set of trusted users is changed (add or remove)
	if(!smime_encrypt_with_cert(EMERGENCY_CPABE_PRIV_KEY_PATH, ENC_RECOVERY_EMERGENCY_CPABE_PRIV_KEY_PATH, SSL_CERT_PATH, err_msg))
	{
		fprintf(stderr, "Encrypting the recovery emergency key failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Encrypting the recovery emergency key failed");
		goto ERROR;
	}

	unlink(EMERGENCY_CPABE_PRIV_KEY_PATH);
	return true;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	unlink(EMERGENCY_CPABE_PRIV_KEY_PATH);
	unlink(ENC_EMERGENCY_CPABE_PRIV_KEY_PATH);
	unlink(ENC_RECOVERY_EMERGENCY_CPABE_PRIV_KEY_PATH);
	return false;
}

static void extract_user_info(char *full_username, char *username_ret, char *authority_name_ret)
{
	strncpy(authority_name_ret, full_username, strchr(full_username, '.') - full_username);
	authority_name_ret[strchr(full_username, '.') - full_username] = 0;

	strcpy(username_ret, strchr(full_username, '.') + 1);
	username_ret[strlen(full_username) - strlen(authority_name_ret) - 1] = 0;
}

boolean encrypt_threshold_secret_keys(unsigned int no_trusted_users, char **ea_trusted_user_list, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL          *ssl_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	unsigned int i;
	char         username[USER_NAME_LENGTH + 1];
	char         authority_name[AUTHORITY_NAME_LENGTH + 1];

	char         user_pub_key_requesting_result_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      user_pub_key_requesting_result_flag;

	char         threshold_secret_key_path[PATH_LENGTH + 1];
	char         enc_threshold_secret_key_path[PATH_LENGTH + 1];

	// Connect to User Authority
	if(!connect_to_emergency_key_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", EMERGENCY_TRUSTED_USER_PUB_KEY_LIST_REQUESTING, true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

	for(i=0; i<no_trusted_users; i++)
	{
		extract_user_info(ea_trusted_user_list[i], username, authority_name);

		// Send the user's public key requesting information
		write_token_into_buffer("is_end_of_user_pub_key_requesting_flag", "0", true, buffer);
		write_token_into_buffer("username", username, false, buffer);
		write_token_into_buffer("authority_name", authority_name, false, buffer);

		if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
		{
			backend_alert_msg_handler_callback("Sending the emergency trusted user's public key requesting information failed");
			goto ERROR;
		}

		// Receive the user's public key requesting result flag information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			backend_alert_msg_handler_callback("Receiving the emergency trusted user's public key requesting result flag information failed");
			goto ERROR;
		}

		// Get the user's public key requesting result flag token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, user_pub_key_requesting_result_flag_str_tmp) != READ_TOKEN_SUCCESS 
			|| strcmp(token_name, "user_pub_key_requesting_result_flag") != 0)
		{
			int_error("Extracting the user_pub_key_requesting_result_flag failed");
		}

		user_pub_key_requesting_result_flag = (strcmp(user_pub_key_requesting_result_flag_str_tmp, "1") == 0) ? true : false;
		if(!user_pub_key_requesting_result_flag)
		{
			// Get an error message token from buffer
			if(read_token_from_buffer(buffer, 2, token_name, err_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
				int_error("Extracting the error_msg failed");
		
			backend_alert_msg_handler_callback(err_msg);
			goto ERROR;
		}

		// Receive the user's public key
		if(!SSL_recv_file(ssl_conn, EMERGENCY_TRUSTED_USER_SSL_CERT_PATH))
		{
			backend_alert_msg_handler_callback("Receiving the emergency trusted user's public key failed");
			goto ERROR;
		}

		sprintf(threshold_secret_key_path, "%s/%s%u%s", CACHE_DIRECTORY_NAME, PTHRESHOLD_PREFIX_NAME, i, SERIALIZABLE_OBJ_EXTENSION);
		sprintf(enc_threshold_secret_key_path, "%s/%s%u%s", CACHE_DIRECTORY_NAME, ENC_PTHRESHOLD_PREFIX_NAME, i, SERIALIZABLE_OBJ_EXTENSION);

		// Encrypt the threshold secret key with the corresponding trusted user's SSL public key
		if(!smime_encrypt_with_cert(threshold_secret_key_path, enc_threshold_secret_key_path, EMERGENCY_TRUSTED_USER_SSL_CERT_PATH, err_msg))
		{
			fprintf(stderr, "Encrypting the threshold secret key failed\n\"%s\"\n", err_msg);
			backend_alert_msg_handler_callback("Encrypting the threshold secret key failed");
			goto ERROR;
		}

		unlink(EMERGENCY_TRUSTED_USER_SSL_CERT_PATH);
		unlink(threshold_secret_key_path);
	}

	// Send the user's public key requesting information
	write_token_into_buffer("is_end_of_user_pub_key_requesting_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending the emergency trusted user's public key requesting information failed");
		goto ERROR;
	}

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return true;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	unlink(EMERGENCY_TRUSTED_USER_SSL_CERT_PATH);
	for(i=0; i<no_trusted_users; i++)
	{
		sprintf(threshold_secret_key_path, "%s/%s%u%s", CACHE_DIRECTORY_NAME, PTHRESHOLD_PREFIX_NAME, i, SERIALIZABLE_OBJ_EXTENSION);
		unlink(threshold_secret_key_path);
	}

	return false;
}

static boolean connect_to_emergency_key_params_management_service(SSL **ssl_conn_ret)   // Emergency Server
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    emergency_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to Emergency Server
	sprintf(emergency_server_addr, "%s:%s", GLOBAL_emergency_server_ip_addr, EMS_RESTRICTED_LEVEL_PHR_KEY_MANAGEMENT_PORT);
	bio_conn = BIO_new_connect(emergency_server_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		backend_alert_msg_callback_handler("Connecting to the emergency server failed");
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

boolean upload_unique_emergency_key_params(unsigned int remote_site_phr_id, unsigned int threshold_value, unsigned int no_trusted_users, char **ea_trusted_user_list, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL          *ssl_conn = NULL;
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	unsigned int i;
	char         remote_site_phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];
	char         threshold_value_str[INT_TO_STR_DIGITS_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];
	char         authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         enc_threshold_secret_key_path[PATH_LENGTH + 1];

	char         found_phr_owner_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      found_phr_owner_flag;

	char         found_delegation_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      found_delegation_flag;

	char         err_msg[ERR_MSG_LENGTH + 1];

	// Connect to Emergency Server
	if(!connect_to_emergency_key_params_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", RESTRICTED_LEVEL_PHR_KEY_PARAMS_UPLOADING, true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}

	sprintf(remote_site_phr_id_str, "%u", remote_site_phr_id);
	sprintf(threshold_value_str, "%u", threshold_value);

	// Send the PHR requesting information
	write_token_into_buffer("remote_site_phr_id", remote_site_phr_id_str, true, buffer);
	write_token_into_buffer("threshold_value",threshold_value_str, false, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending the PHR requesting information failed");
		goto ERROR;
	}

	// Send the encrypted emergency key from file
	if(!SSL_send_file(ssl_conn, ENC_EMERGENCY_CPABE_PRIV_KEY_PATH))
	{
		backend_alert_msg_handler_callback("Sending the emergency key failed");
		goto ERROR;
	}

	unlink(ENC_EMERGENCY_CPABE_PRIV_KEY_PATH);

	// Send the encrypted recovery emergency key from file
	if(!SSL_send_file(ssl_conn, ENC_RECOVERY_EMERGENCY_CPABE_PRIV_KEY_PATH))
	{
		backend_alert_msg_handler_callback("Sending the recovery emergency key failed");
		goto ERROR;
	}

	unlink(ENC_RECOVERY_EMERGENCY_CPABE_PRIV_KEY_PATH);

	// Send the encrypted threshold message from file
	if(!SSL_send_file(ssl_conn, ENC_THRESHOLD_MSG_PATH))
	{
		backend_alert_msg_handler_callback("Sending the threshold message failed");
		goto ERROR;
	}

	unlink(ENC_THRESHOLD_MSG_PATH);

	// Receive the found_phr_owner_flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving the found_phr_owner_flag failed");
		goto ERROR;
	}

	// Get the found_phr_owner_flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, found_phr_owner_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "found_phr_owner_flag") != 0)
	{
		int_error("Extracting the found_phr_owner_flag failed");
	}

	found_phr_owner_flag = (strcmp(found_phr_owner_flag_str_tmp, "1") == 0) ? true : false;
	if(!found_phr_owner_flag)
	{
		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, err_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(err_msg);
		goto ERROR;
	}

	for(i=0; i<no_trusted_users; i++)
	{
		extract_user_info(ea_trusted_user_list[i], username, authority_name);

		// Send the threshold secret key uploading information
		write_token_into_buffer("is_end_of_threshold_secret_key_uploading_flag", "0", true, buffer);
		write_token_into_buffer("trusted_username", username, false, buffer);
		write_token_into_buffer("trusted_user_authority_name", authority_name, false, buffer);

		if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
		{
			backend_alert_msg_handler_callback("Sending the threshold secret key uploading information failed");
			goto ERROR;
		}

		// Receive the found_delegation_flag
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			backend_alert_msg_handler_callback("Receiving the found_delegation_flag failed");
			goto ERROR;
		}

		// Get the found_delegation_flag token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, found_delegation_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "found_delegation_flag") != 0)
		{
			int_error("Extracting the found_delegation_flag failed");
		}

		found_delegation_flag = (strcmp(found_delegation_flag_str_tmp, "1") == 0) ? true : false;
		if(!found_delegation_flag)
		{
			// Get an error message token from buffer
			if(read_token_from_buffer(buffer, 2, token_name, err_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
				int_error("Extracting the error_msg failed");
		
			backend_alert_msg_handler_callback(err_msg);
			goto ERROR;
		}

		sprintf(enc_threshold_secret_key_path, "%s/%s%u%s", CACHE_DIRECTORY_NAME, ENC_PTHRESHOLD_PREFIX_NAME, i, SERIALIZABLE_OBJ_EXTENSION);

		// Send the encrypted threshold secret key from file
		if(!SSL_send_file(ssl_conn, enc_threshold_secret_key_path))
		{
			backend_alert_msg_handler_callback("Sending the threshold secret key failed");
			goto ERROR;
		}

		unlink(enc_threshold_secret_key_path);
	}

	// Send the threshold secret key uploading information
	write_token_into_buffer("is_end_of_threshold_secret_key_uploading_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending the threshold secret key uploading information failed");
		goto ERROR;
	}

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return true;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	unlink(ENC_EMERGENCY_CPABE_PRIV_KEY_PATH);
	unlink(ENC_RECOVERY_EMERGENCY_CPABE_PRIV_KEY_PATH);
	unlink(ENC_THRESHOLD_MSG_PATH);

	for(i=0; i<no_trusted_users; i++)
	{
		sprintf(enc_threshold_secret_key_path, "%s/%s%u%s", CACHE_DIRECTORY_NAME, ENC_PTHRESHOLD_PREFIX_NAME, i, SERIALIZABLE_OBJ_EXTENSION);
		unlink(enc_threshold_secret_key_path);
	}

	return false;
}

static boolean connect_to_phr_confidentiality_level_changing_service(SSL **ssl_conn_ret)   // PHR Server
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    phr_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to PHR Server
	sprintf(phr_server_addr, "%s:%s", GLOBAL_phr_server_ip_addr, PHRSV_CONFIDENTIALITY_LEVEL_CHANGING_PORT);
	bio_conn = BIO_new_connect(phr_server_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		backend_alert_msg_callback_handler("Connecting to the PHR server failed");
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

	hosts[0] = PHR_SERVER_CN;
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, false, GLOBAL_authority_name)) != X509_V_OK)
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

boolean change_restricted_level_phr_to_excusive_level_phr(unsigned int remote_site_phr_id, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    err_msg[ERR_MSG_LENGTH + 1];

	char    remote_site_phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];

	char    phr_confidentiality_level_changing_flag_str_tmp[FLAG_LENGTH + 1];
	boolean phr_confidentiality_level_changing_flag;

	// Connect to PHR server
	if(!connect_to_phr_confidentiality_level_changing_service(&ssl_conn))
		goto ERROR;

	// Send the remote site PHR id
	sprintf(remote_site_phr_id_str, "%u", remote_site_phr_id);
	write_token_into_buffer("phr_id", remote_site_phr_id_str, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending the remote site PHR id failed");
		goto ERROR;
	}

	// Receive the phr_confidentiality_level_changing_flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving the phr_confidentiality_level_changing_flag failed");
		goto ERROR;
	}

	// Get the phr_confidentiality_level_changing_flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_confidentiality_level_changing_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "phr_confidentiality_level_changing_flag") != 0)
	{
		int_error("Extracting the phr_confidentiality_level_changing_flag failed");
	}

	phr_confidentiality_level_changing_flag = (strcmp(phr_confidentiality_level_changing_flag_str_tmp, "1") == 0) ? true : false;
	if(!phr_confidentiality_level_changing_flag)
	{
		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, err_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(err_msg);
		goto ERROR;
	}

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return true;

ERROR:

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;
}

boolean remove_restricted_level_phr_key_params(char *phr_owner_name, char *phr_owner_authority_name, unsigned int remote_site_phr_id, 
	void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;

	SSL     *ssl_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    remote_site_phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];

	char    phr_access_permission_verification_result_flag_str_tmp[FLAG_LENGTH + 1];     // "0" or "1"
	boolean phr_access_permission_verification_result_flag;

	char    err_msg[ERR_MSG_LENGTH + 1];
	char    full_phr_owner_name[AUTHORITY_NAME_LENGTH + USER_NAME_LENGTH + 1];
	char    full_phr_owner_name_hash[SHA1_DIGEST_LENGTH + 1];
	char    access_granting_ticket_path[PATH_LENGTH + 1];

	// Connect to Emergency Server
	if(!connect_to_emergency_key_params_management_service(&ssl_conn))
		goto ERROR;

	// Send request information
	write_token_into_buffer("request", RESTRICTED_LEVEL_PHR_KEY_PARAMS_REMOVAL, true, buffer);
	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending request information failed");
		goto ERROR;
	}
	
	sprintf(remote_site_phr_id_str, "%u", remote_site_phr_id);

	// Send the PHR requesting information
	write_token_into_buffer("phr_owner_name", phr_owner_name, true, buffer);
	write_token_into_buffer("phr_owner_authority_name", phr_owner_authority_name, false, buffer);
	write_token_into_buffer("remote_site_phr_id", remote_site_phr_id_str, false, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		backend_alert_msg_handler_callback("Sending the PHR requesting information failed");
		goto ERROR;
	}

	// Generate an access granting ticket path
	sprintf(full_phr_owner_name, "%s%s", phr_owner_authority_name, phr_owner_name);
	sum_sha1_from_string(full_phr_owner_name, strlen(full_phr_owner_name), full_phr_owner_name_hash, CALCULATING_FULL_PHR_OWNER_NAME_HASH_PATH);
	sprintf(access_granting_ticket_path, "%s/%s", CACHE_DIRECTORY_PATH, full_phr_owner_name_hash);

	if(!file_exists(access_granting_ticket_path))
	{
		backend_fatal_alert_msg_handler_callback("The access granting ticket does not exist");
		goto ERROR;
	}

	// Decrypt the access granting ticket with the user's password
	if(!des3_decrypt(access_granting_ticket_path, SGN_ACCESS_GRANTING_TICKET_PATH, GLOBAL_passwd, err_msg))
	{
		fprintf(stderr, "Decrypting the access granting ticket failed\n\"%s\"\n", err_msg);
		backend_fatal_alert_msg_handler_callback("Decrypting the access granting ticket failed");
		goto ERROR;
	}

	// Send the access granting ticket
	if(!SSL_send_file(ssl_conn, SGN_ACCESS_GRANTING_TICKET_PATH))
	{
		backend_alert_msg_handler_callback("Sending the access granting ticket failed");
		goto ERROR;
	}

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

	// Receive a PHR access permission verification result flag
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving a PHR access permission verification result failed");
		goto ERROR;
	}

	// Get a PHR access permission verification result flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, phr_access_permission_verification_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "phr_access_permission_verification_result_flag") != 0)
	{
		int_error("Extracting the phr_access_permission_verification_result_flag failed");
	}

	phr_access_permission_verification_result_flag = (strcmp(phr_access_permission_verification_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!phr_access_permission_verification_result_flag)
	{
		// Get an error message token from buffer
		if(read_token_from_buffer(buffer, 2, token_name, err_msg) != READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
			int_error("Extracting the error_msg failed");
		
		backend_alert_msg_handler_callback(err_msg);
		goto ERROR;
	}

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return true;

ERROR:

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

	if(ssl_conn)
	{
		SSL_cleanup(ssl_conn);
		ssl_conn = NULL;
	}

	return false;
}

void remove_all_threshold_parameters_in_cache(unsigned int no_trusted_users)
{
	unsigned int i;
	char         threshold_secret_key_path[PATH_LENGTH + 1];
	char         enc_threshold_secret_key_path[PATH_LENGTH + 1];

	unlink(EMERGENCY_CPABE_PRIV_KEY_PATH);
	unlink(ENC_EMERGENCY_CPABE_PRIV_KEY_PATH);
	unlink(ENC_RECOVERY_EMERGENCY_CPABE_PRIV_KEY_PATH);
	unlink(ENC_THRESHOLD_MSG_PATH);
	unlink(EMERGENCY_TRUSTED_USER_SSL_CERT_PATH);

	for(i=0; i<no_trusted_users; i++)
	{
		sprintf(threshold_secret_key_path, "%s/%s%u%s", CACHE_DIRECTORY_NAME, PTHRESHOLD_PREFIX_NAME, i, SERIALIZABLE_OBJ_EXTENSION);
		unlink(threshold_secret_key_path);
	}

	for(i=0; i<no_trusted_users; i++)
	{
		sprintf(enc_threshold_secret_key_path, "%s/%s%u%s", CACHE_DIRECTORY_NAME, ENC_PTHRESHOLD_PREFIX_NAME, i, SERIALIZABLE_OBJ_EXTENSION);
		unlink(enc_threshold_secret_key_path);
	}
}




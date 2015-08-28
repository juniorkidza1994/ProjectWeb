#include "client_common.h"

#define VERIFICATION_INFO_CIPHERTEXT_PATH   "Client_cache/client_login_authentication.verification_info_ciphertext"
#define VERIFICATION_INFO_PLAINTEXT_PATH    "Client_cache/client_login_authentication.verification_info_plaintext"
#define VERIFICATION_RESULT_CIPHERTEXT_PATH "Client_cache/client_login_authentication.verification_result_ciphertext"
#define VERIFICATION_RESULT_PLAINTEXT_PATH  "Client_cache/client_login_authentication.verification_result_plaintext"

#define SSL_CERT_CIPHERTEXT_PATH            "Client_cache/client_login_authentication.ssl_cert_ciphertext"
#define SSL_CERT_HASH_CIPHERTEXT_PATH       "Client_cache/client_login_authentication.ssl_cert_hash_ciphertext"
#define SSL_CERT_HASH_PLAINTEXT_PATH        "Client_cache/client_login_authentication.ssl_cert_hash_plaintext"
#define CALCULATING_SSL_CERT_HASH_PATH      "Client_cache/client_login_authentication.calculating_ssl_cert_hash"

// Local Variables
static void (*backend_alert_msg_callback_handler)(char *alert_msg)                               = NULL;
static void (*backend_fatal_alert_msg_callback_handler)(char *alert_msg)                         = NULL;
static void (*basic_info_ret_callback_handler)(char *email_address, char *authority_name, 
	char *audit_server_ip_addr, char *phr_server_ip_addr, char *emergency_server_ip_addr)    = NULL;

static void (*mail_server_configuration_ret_callback_handler)(char *mail_server_url, 
	char *authority_email_address, char *authority_email_passwd)                             = NULL;

static void (*ssl_cert_hash_ret_callback_handler)(char *ssl_cert_hash)                           = NULL;
static void (*cpabe_priv_key_hash_ret_callback_handler)(char *cpabe_priv_key_hash)               = NULL;

// Local Function Prototypes
static void backend_alert_msg_handler_callback(char *alert_msg);
static void backend_fatal_alert_msg_handler_callback(char *alert_msg);
static void basic_info_ret_handler_callback(char *email_address, char *authority_name, char *audit_server_ip_addr, char *phr_server_ip_addr, char *emergency_server_ip_addr);
static void mail_server_configuration_ret_handler_callback(char *mail_server_url, char *authority_email_address, char *authority_email_passwd);
static void ssl_cert_hash_ret_handler_callback(char *ssl_cert_hash);
static void cpabe_priv_key_hash_ret_handler_callback(char *cpabe_priv_key_hash);

static boolean send_authentication_request(BIO *bio_conn, boolean is_admin_flag, char *username, char *passwd, char *key_exchange_passwd);
static boolean obtain_ssl_cert(BIO *bio_conn, char *passwd, char *key_exchange_passwd, char *ssl_cert_hash_ret);
static boolean obtain_basic_info_for_user(SSL *ssl_conn, char *email_address_ret, char *authority_name_ret, 
	char *audit_server_ip_addr_ret, char *phr_server_ip_addr_ret, char *emergency_server_ip_addr_ret);
static boolean obtain_basic_info_for_admin(SSL *ssl_conn, char *email_address_ret, char *authority_name_ret, 
	char *audit_server_ip_addr_ret, char *phr_server_ip_addr_ret, char *emergency_server_ip_addr_ret, 
	char *mail_server_url_ret, char *authority_email_address_ret, char *authority_email_passwd_ret);

static boolean obtain_cpabe_private_key(SSL *ssl_conn, char *cpabe_priv_key_hash_ret);

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

static void basic_info_ret_handler_callback(char *email_address, char *authority_name, char *audit_server_ip_addr, char *phr_server_ip_addr, char *emergency_server_ip_addr)
{
	if(basic_info_ret_callback_handler)
	{
		basic_info_ret_callback_handler(email_address, authority_name, audit_server_ip_addr, phr_server_ip_addr, emergency_server_ip_addr);
	}
	else  // NULL
	{
		int_error("basic_info_ret_callback_handler is NULL");
	}
}

static void mail_server_configuration_ret_handler_callback(char *mail_server_url, char *authority_email_address, char *authority_email_passwd)
{
	if(mail_server_configuration_ret_callback_handler)
	{
		mail_server_configuration_ret_callback_handler(mail_server_url, authority_email_address, authority_email_passwd);
	}
	else  // NULL
	{
		int_error("mail_server_configuration_ret_callback_handler is NULL");
	}
}

static void ssl_cert_hash_ret_handler_callback(char *ssl_cert_hash)
{
	if(ssl_cert_hash_ret_callback_handler)
	{
		ssl_cert_hash_ret_callback_handler(ssl_cert_hash);
	}
	else  // NULL
	{
		int_error("ssl_cert_hash_ret_callback_handler is NULL");
	}
}

static void cpabe_priv_key_hash_ret_handler_callback(char *cpabe_priv_key_hash)
{
	if(cpabe_priv_key_hash_ret_callback_handler)
	{
		cpabe_priv_key_hash_ret_callback_handler(cpabe_priv_key_hash);
	}
	else  // NULL
	{
		int_error("cpabe_priv_key_hash_ret_callback_handler is NULL");
	}
}

static boolean send_authentication_request(BIO *bio_conn, boolean is_admin_flag, char *username, char *passwd, char *key_exchange_passwd)
{
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    err_msg[ERR_MSG_LENGTH + 1];
	char    verification_result_flag_str_tmp[FLAG_LENGTH + 1];  // "0" or "1"
	boolean verification_result_flag;
	
	if(!write_token_into_file("is_admin_flag", (is_admin_flag) ? "1" : "0", true, VERIFICATION_INFO_PLAINTEXT_PATH))
		int_error("Writing the is_admin_flag failed");

	if(!write_token_into_file("username", username, false, VERIFICATION_INFO_PLAINTEXT_PATH))
		int_error("Writing the username failed");

	if(!write_token_into_file("passwd", passwd, false, VERIFICATION_INFO_PLAINTEXT_PATH))
		int_error("Writing the passwd failed");

	if(!write_token_into_file("key_exchange_passwd", key_exchange_passwd, false, VERIFICATION_INFO_PLAINTEXT_PATH))
		int_error("Writing the key_exchange_passwd failed");

	// Encrypt the verification information with the User Authority's public key
	if(!smime_encrypt_with_cert(VERIFICATION_INFO_PLAINTEXT_PATH, VERIFICATION_INFO_CIPHERTEXT_PATH, UA_PUB_CERTFILE_PATH, err_msg))
	{
		fprintf(stderr, "Encrypting the verification information failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Encrypting the verification information failed");
		goto ERROR;
	}

	unlink(VERIFICATION_INFO_PLAINTEXT_PATH);

	// Send the verification information
	if(!BIO_send_file(bio_conn, VERIFICATION_INFO_CIPHERTEXT_PATH))
	{
		backend_alert_msg_handler_callback("Sending the verification information failed");
		goto ERROR;
	}

	unlink(VERIFICATION_INFO_CIPHERTEXT_PATH);

	// Receive the verification result
	if(!BIO_recv_file(bio_conn, VERIFICATION_RESULT_CIPHERTEXT_PATH))
	{
		backend_alert_msg_handler_callback("Receiving verification result failed");
		goto ERROR;
	}

	// Decrypt the verification result with the key_exchange_passwd
	if(!des3_decrypt(VERIFICATION_RESULT_CIPHERTEXT_PATH, VERIFICATION_RESULT_PLAINTEXT_PATH, key_exchange_passwd, err_msg))
	{
		fprintf(stderr, "Decrypting the verification result failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Decrypting the verification result failed");
		goto ERROR;
	}

	unlink(VERIFICATION_RESULT_CIPHERTEXT_PATH);

	// Get the verification result from file
	if(read_token_from_file(VERIFICATION_RESULT_PLAINTEXT_PATH, 1, token_name, verification_result_flag_str_tmp) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "verification_result_flag") != 0)
	{
		int_error("Extracting the verification_result_flag failed");
	}

	verification_result_flag = (strcmp(verification_result_flag_str_tmp, "1") == 0) ? true : false;
	if(!verification_result_flag)
	{
		char error_msg[ERR_MSG_LENGTH + 1];

		// Get an error message token from file
		if(read_token_from_file(VERIFICATION_RESULT_PLAINTEXT_PATH, 2, token_name, error_msg) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "error_msg") != 0)
		{
			int_error("Extracting the error_msg failed");
		}
		
		backend_alert_msg_handler_callback(error_msg);

		unlink(VERIFICATION_RESULT_PLAINTEXT_PATH);
		goto ERROR;
	}

	unlink(VERIFICATION_RESULT_PLAINTEXT_PATH);
	return verification_result_flag;

ERROR:

	unlink(VERIFICATION_INFO_PLAINTEXT_PATH);
	unlink(VERIFICATION_INFO_CIPHERTEXT_PATH);
	unlink(VERIFICATION_RESULT_CIPHERTEXT_PATH);
	unlink(VERIFICATION_RESULT_PLAINTEXT_PATH);
	return false;
}

static boolean obtain_ssl_cert(BIO *bio_conn, char *passwd, char *key_exchange_passwd, char *ssl_cert_hash_ret)
{
	char err_msg[ERR_MSG_LENGTH + 1];

	// Receive the SSL certificate (the SSL certificate was encrypted 2 times with the user's passwd and random key_exchange_passwd)
	if(!BIO_recv_file(bio_conn, SSL_CERT_CIPHERTEXT_PATH))
	{
		backend_alert_msg_handler_callback("Receiving an SSL certificate failed");
		goto ERROR;
	}

	// Decrypt the SSL certificate with the key_exchange_passwd (however, it's still in encrypted form with Tripple-DES)
	if(!des3_decrypt(SSL_CERT_CIPHERTEXT_PATH, SSL_CERT_PATH, key_exchange_passwd, err_msg))
	{
		fprintf(stderr, "Decrypting the SSL certificate failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Decrypting the SSL certificate failed");
		goto ERROR;
	}

	unlink(SSL_CERT_CIPHERTEXT_PATH);

	// Receive the SSL certificate hash
	if(!BIO_recv_file(bio_conn, SSL_CERT_HASH_CIPHERTEXT_PATH))
	{
		backend_alert_msg_handler_callback("Receiving an SSL certificate hash failed");
		goto ERROR;
	}

	// Decrypt the SSL certificate hash with the key_exchange_passwd
	if(!des3_decrypt(SSL_CERT_HASH_CIPHERTEXT_PATH, SSL_CERT_HASH_PLAINTEXT_PATH, key_exchange_passwd, err_msg))
	{
		fprintf(stderr, "Decrypting an SSL certificate hash failed\n\"%s\"\n", err_msg);
		backend_alert_msg_handler_callback("Decrypting an SSL certificate hash failed");
		goto ERROR;
	}

	unlink(SSL_CERT_HASH_CIPHERTEXT_PATH);

	// Read the SSL certificate hash value from file
	if(!read_bin_file(SSL_CERT_HASH_PLAINTEXT_PATH, ssl_cert_hash_ret, SHA1_DIGEST_LENGTH, NULL))
	{
		backend_alert_msg_handler_callback("Reading an SSL certificate hash failed");
		goto ERROR;
	}

	unlink(SSL_CERT_HASH_PLAINTEXT_PATH);
	return true;

ERROR:

	unlink(SSL_CERT_CIPHERTEXT_PATH);
	unlink(SSL_CERT_HASH_CIPHERTEXT_PATH);
	unlink(SSL_CERT_HASH_PLAINTEXT_PATH);
	return false;
}

static boolean obtain_basic_info_for_user(SSL *ssl_conn, char *email_address_ret, char *authority_name_ret, 
	char *audit_server_ip_addr_ret, char *phr_server_ip_addr_ret, char *emergency_server_ip_addr_ret)
{
	char buffer[BUFFER_LENGTH + 1];
	char token_name[TOKEN_NAME_LENGTH + 1];

	// Receive basic information
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving basic information failed");
		goto ERROR;
	}

	// Get basic information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, email_address_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "email_address") != 0)
		int_error("Extracting the email_address failed");

	if(read_token_from_buffer(buffer, 2, token_name, authority_name_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "authority_name") != 0)
		int_error("Extracting the authority_name failed");

	if(read_token_from_buffer(buffer, 3, token_name, audit_server_ip_addr_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "audit_server_ip_addr") != 0)
		int_error("Extracting the audit_server_ip_addr failed");

	if(read_token_from_buffer(buffer, 4, token_name, phr_server_ip_addr_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_server_ip_addr") != 0)
		int_error("Extracting the phr_server_ip_addr failed");

	if(read_token_from_buffer(buffer, 5, token_name, emergency_server_ip_addr_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_server_ip_addr") != 0)
		int_error("Extracting the emergency_server_ip_addr failed");

	return true;

ERROR:
	return false;
}

static boolean obtain_basic_info_for_admin(SSL *ssl_conn, char *email_address_ret, char *authority_name_ret, char *audit_server_ip_addr_ret, char *phr_server_ip_addr_ret, 
	char *emergency_server_ip_addr_ret, char *mail_server_url_ret, char *authority_email_address_ret, char *authority_email_passwd_ret)
{
	char buffer[BUFFER_LENGTH + 1];
	char token_name[TOKEN_NAME_LENGTH + 1];

	// Receive basic information
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		backend_alert_msg_handler_callback("Receiving basic information failed");
		goto ERROR;
	}

	// Get basic information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, email_address_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "email_address") != 0)
		int_error("Extracting the email_address failed");

	if(read_token_from_buffer(buffer, 2, token_name, authority_name_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "authority_name") != 0)
		int_error("Extracting the authority_name failed");

	if(read_token_from_buffer(buffer, 3, token_name, audit_server_ip_addr_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "audit_server_ip_addr") != 0)
		int_error("Extracting the audit_server_ip_addr failed");

	if(read_token_from_buffer(buffer, 4, token_name, phr_server_ip_addr_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_server_ip_addr") != 0)
		int_error("Extracting the phr_server_ip_addr failed");

	if(read_token_from_buffer(buffer, 5, token_name, emergency_server_ip_addr_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_server_ip_addr") != 0)
		int_error("Extracting the emergency_server_ip_addr failed");

	if(read_token_from_buffer(buffer, 6, token_name, mail_server_url_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "mail_server_url") != 0)
		int_error("Extracting the mail_server_url failed");

	if(read_token_from_buffer(buffer, 7, token_name, authority_email_address_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "authority_email_address") != 0)
		int_error("Extracting the authority_email_address failed");

	if(read_token_from_buffer(buffer, 8, token_name, authority_email_passwd_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "authority_email_passwd") != 0)
		int_error("Extracting the authority_email_passwd failed");

	return true;

ERROR:
	return false;
}

static boolean obtain_cpabe_private_key(SSL *ssl_conn, char *cpabe_priv_key_hash_ret)
{
	// Receive the CP-ABE private key and its hash
	if(!SSL_recv_file(ssl_conn, CPABE_PRIV_KEY_PATH))
	{
		backend_alert_msg_handler_callback("Receiving CP-ABE private key failed");
		goto ERROR;
	}

	if(!SSL_recv_buffer(ssl_conn, cpabe_priv_key_hash_ret, NULL))
	{
		backend_alert_msg_handler_callback("Receiving CP-ABE private key hash failed");
		goto ERROR;
	}	

	return true;

ERROR:

	return false;
}

boolean authenticate_user(char *user_auth_ip_addr, char *username, char *passwd, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*basic_info_ret_callback_handler_ptr)(char *email_address, char *authority_name, 
	char *audit_server_ip_addr, char *phr_server_ip_addr, char *emergency_server_ip_addr), void (*ssl_cert_hash_ret_callback_handler_ptr)(char *ssl_cert_hash), 
	void (*cpabe_priv_key_hash_ret_callback_handler_ptr)(char *cpabe_priv_key_hash))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler       = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler = backend_fatal_alert_msg_callback_handler_ptr;
	basic_info_ret_callback_handler          = basic_info_ret_callback_handler_ptr;
	ssl_cert_hash_ret_callback_handler       = ssl_cert_hash_ret_callback_handler_ptr;
	cpabe_priv_key_hash_ret_callback_handler = cpabe_priv_key_hash_ret_callback_handler_ptr;

	BIO     *bio_conn = NULL;
    	SSL     *ssl_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *host[1];

	char    user_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];
	char    key_exchange_passwd[PASSWD_LENGTH + 1];  // Temporary random password for for exchanging information in a BIO channel

	char    ssl_cert_hash[SHA1_DIGEST_LENGTH + 1];
	char    cpabe_priv_key_hash[SHA1_DIGEST_LENGTH + 1];

	char    email_address[EMAIL_ADDRESS_LENGTH + 1];
	char    authority_name[AUTHORITY_NAME_LENGTH + 1];
	char    audit_server_ip_addr[IP_ADDRESS_LENGTH + 1];
	char    phr_server_ip_addr[IP_ADDRESS_LENGTH + 1];
	char    emergency_server_ip_addr[IP_ADDRESS_LENGTH + 1];

	// Connect to User Authority
	sprintf(user_auth_addr, "%s:%s", user_auth_ip_addr, UA_USER_AUTHENTICATION_PORT);
	bio_conn = BIO_new_connect(user_auth_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		backend_alert_msg_callback_handler("Connecting to user authority failed");
		goto ERROR_AT_BIO_LAYER;
	}

	// Generate a temporary random 8 character password for exchanging information in a BIO channel
	gen_random_password(key_exchange_passwd);

	// Authenticate user
	if(!send_authentication_request(bio_conn, false, username, passwd, key_exchange_passwd))
		goto ERROR_AT_BIO_LAYER;

	// Obtain SSL certificate and its hash
	if(!obtain_ssl_cert(bio_conn, passwd, key_exchange_passwd, ssl_cert_hash))
		goto ERROR_AT_BIO_LAYER;

	ssl_cert_hash_ret_handler_callback(ssl_cert_hash);

	/* Hash value is used for verifying an SSL certificate to make sure that certificate is a latest update version, 
	   preventing a user uses a revoked certificate to feign to be a revoked one */
	if(!verify_file_integrity(SSL_CERT_PATH, ssl_cert_hash, CALCULATING_SSL_CERT_HASH_PATH))
	{
		// Notify alert message to user and then terminate the application
		backend_fatal_alert_msg_handler_callback("Your SSL certificate is not verified.\nTo solve this, please contact an administrator.");
	}

	ctx = setup_client_ctx(SSL_CERT_PATH, passwd, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
	if(!(ssl_conn = SSL_new(ctx)))
            	int_error("Creating SSL context failed");
 
    	SSL_set_bio(ssl_conn, bio_conn, bio_conn);
    	if(SSL_connect(ssl_conn) <= 0)
	{
        	backend_alert_msg_handler_callback("Connecting SSL object failed");
		goto ERROR_AT_SSL_LAYER;
	}
    
	host[0] = USER_AUTH_CN;
	if((err = post_connection_check(ssl_conn, host, 1, false, NULL)) != X509_V_OK)
   	{
		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
		backend_alert_msg_handler_callback("Checking SSL information failed");
        	goto ERROR_AT_SSL_LAYER;
    	}

	// Obtain basic information
	if(!obtain_basic_info_for_user(ssl_conn, email_address, authority_name, audit_server_ip_addr, phr_server_ip_addr, emergency_server_ip_addr))
        	goto ERROR_AT_SSL_LAYER;

	basic_info_ret_handler_callback(email_address, authority_name, audit_server_ip_addr, phr_server_ip_addr, emergency_server_ip_addr);

	// Obtain CP-ABE private key and its hash
	if(!obtain_cpabe_private_key(ssl_conn, cpabe_priv_key_hash))
		goto ERROR_AT_SSL_LAYER;

	cpabe_priv_key_hash_ret_handler_callback(cpabe_priv_key_hash);

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	SSL_CTX_free(ctx);
    	ERR_remove_state(0);
	return true;

ERROR_AT_BIO_LAYER:

	BIO_free(bio_conn);
	bio_conn = NULL;
	ERR_remove_state(0);	
	return false;

ERROR_AT_SSL_LAYER:

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	SSL_CTX_free(ctx);
    	ERR_remove_state(0);
	return false;
}

boolean authenticate_admin(char *user_auth_ip_addr, char *username, char *passwd, void (*backend_alert_msg_callback_handler_ptr)(char *alert_msg), 
	void (*backend_fatal_alert_msg_callback_handler_ptr)(char *alert_msg), void (*basic_info_ret_callback_handler_ptr)(char *email_address, char *authority_name, 
	char *audit_server_ip_addr, char *phr_server_ip_addr, char *emergency_server_ip_addr), void (*mail_server_configuration_ret_callback_handler_ptr)(
	char *mail_server_url, char *authority_email_address, char *authority_email_passwd), void (*ssl_cert_hash_ret_callback_handler_ptr)(char *ssl_cert_hash))
{
	// Setup callback handlers
	backend_alert_msg_callback_handler             = backend_alert_msg_callback_handler_ptr;
	backend_fatal_alert_msg_callback_handler       = backend_fatal_alert_msg_callback_handler_ptr;
	basic_info_ret_callback_handler                = basic_info_ret_callback_handler_ptr;
	mail_server_configuration_ret_callback_handler = mail_server_configuration_ret_callback_handler_ptr;
	ssl_cert_hash_ret_callback_handler             = ssl_cert_hash_ret_callback_handler_ptr;

	BIO     *bio_conn = NULL;
    	SSL     *ssl_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];

	char    user_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];
	char    key_exchange_passwd[PASSWD_LENGTH + 1];  // Temporary random password for for exchanging information in a BIO channel

	char    ssl_cert_hash[SHA1_DIGEST_LENGTH + 1];

	char    email_address[EMAIL_ADDRESS_LENGTH + 1];
	char    authority_name[AUTHORITY_NAME_LENGTH + 1];
	char    audit_server_ip_addr[IP_ADDRESS_LENGTH + 1];
	char    phr_server_ip_addr[IP_ADDRESS_LENGTH + 1];
	char    emergency_server_ip_addr[IP_ADDRESS_LENGTH + 1];

	char    mail_server_url[URL_LENGTH + 1];
	char    authority_email_address[EMAIL_ADDRESS_LENGTH + 1];
	char    authority_email_passwd[PASSWD_LENGTH + 1];

	// Connect to User Authority
	sprintf(user_auth_addr, "%s:%s", user_auth_ip_addr, UA_USER_AUTHENTICATION_PORT);
	bio_conn = BIO_new_connect(user_auth_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		backend_alert_msg_callback_handler("Connecting to user authority failed");
		goto ERROR_AT_BIO_LAYER;
	}

	// Generate a temporary random 8 character password for exchanging information in a BIO channel
	gen_random_password(key_exchange_passwd);

	// Authenticate user
	if(!send_authentication_request(bio_conn, true, username, passwd, key_exchange_passwd))
		goto ERROR_AT_BIO_LAYER;

	// Obtain SSL certificate and its hash
	if(!obtain_ssl_cert(bio_conn, passwd, key_exchange_passwd, ssl_cert_hash))
		goto ERROR_AT_BIO_LAYER;

	ssl_cert_hash_ret_handler_callback(ssl_cert_hash);

	/* Hash value is used for verifying an SSL certificate to make sure that certificate is a latest update version, 
	   preventing a user uses a revoked certificate to feign to be a revoked one */
	if(!verify_file_integrity(SSL_CERT_PATH, ssl_cert_hash, CALCULATING_SSL_CERT_HASH_PATH))
	{
		// Notify alert message to user and then terminate the application
		backend_fatal_alert_msg_handler_callback("Your SSL certificate is not verified.\nTo solve this, please contact an administrator.");
	}

	ctx = setup_client_ctx(SSL_CERT_PATH, passwd, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
	if(!(ssl_conn = SSL_new(ctx)))
            	int_error("Creating SSL context failed");
 
    	SSL_set_bio(ssl_conn, bio_conn, bio_conn);
    	if(SSL_connect(ssl_conn) <= 0)
	{
        	backend_alert_msg_handler_callback("Connecting SSL object failed");
		goto ERROR_AT_SSL_LAYER;
	}
    
	hosts[0] = USER_AUTH_CN;
	if((err = post_connection_check(ssl_conn, hosts, 1, false, NULL)) != X509_V_OK)
   	{
		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
		backend_alert_msg_handler_callback("Checking SSL information failed");
        	goto ERROR_AT_SSL_LAYER;
    	}

	// Obtain basic information
	if(!obtain_basic_info_for_admin(ssl_conn, email_address, authority_name, audit_server_ip_addr, 
		phr_server_ip_addr, emergency_server_ip_addr, mail_server_url, authority_email_address, authority_email_passwd))
	{
        	goto ERROR_AT_SSL_LAYER;
	}

	basic_info_ret_handler_callback(email_address, authority_name, audit_server_ip_addr, phr_server_ip_addr, emergency_server_ip_addr);
	mail_server_configuration_ret_handler_callback(mail_server_url, authority_email_address, authority_email_passwd);

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	SSL_CTX_free(ctx);
    	ERR_remove_state(0);
	return true;

ERROR_AT_BIO_LAYER:

	BIO_free(bio_conn);
	bio_conn = NULL;
	ERR_remove_state(0);	
	return false;

ERROR_AT_SSL_LAYER:

	SSL_cleanup(ssl_conn);
	ssl_conn = NULL;
	SSL_CTX_free(ctx);
    	ERR_remove_state(0);
	return false;
}




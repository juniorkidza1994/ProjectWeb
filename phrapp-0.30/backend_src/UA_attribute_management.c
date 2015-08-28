#include "UA_common.h"

#define SALTED_PASSWD_HASH_PATH      "UA_cache/UA_attribute_management.salted_passwd_hash"

#define SSL_CERT_PRIV_KEY_PATH       "UA_cache/UA_attribute_management.ssl_cert_priv_key"
#define SSL_CERT_REQ_PATH            "UA_cache/UA_attribute_management.ssl_cert_req"
#define ENC_SSL_CERT_PATH            "UA_cache/UA_attribute_management.enc_ssl_cert"
#define FULL_ENC_SSL_CERT_PATH       "UA_cache/UA_attribute_management.full_enc_ssl_cert"
#define FULL_ENC_SSL_CERT_HASH_PATH  "UA_cache/UA_attribute_management.full_enc_ssl_cert_hash"

#define CPABE_PRIV_KEY_PATH          "UA_cache/UA_attribute_management.cpabe_priv_key"
#define ENC_CPABE_PRIV_KEY_PATH      "UA_cache/UA_attribute_management.cpabe_priv_key_ciphertext"
#define ENC_CPABE_PRIV_KEY_HASH_PATH "UA_cache/UA_attribute_management.cpabe_priv_key_ciphertext_hash"

// Local Function Prototypes
static boolean record_transaction_log(SSL *ssl_client, char *attribute_name, boolean is_numerical_attribute_flag, char *event_description);

static boolean register_attribute(SSL *ssl_client);
static boolean record_transaction_log_on_user(SSL *ssl_client, char *username, boolean is_admin_flag, char *object_description, char *event_description);
static boolean remove_revoked_user_attribute(SSL *ssl_client, MYSQL *db_conn, unsigned int user_attribute_id, char *user_attribute_name, unsigned int user_id, 
	const char *salted_passwd_hash_path, const char *ssl_cert_priv_key_path, const char *ssl_cert_req_path, const char *enc_ssl_cert_path, 
	const char *full_enc_ssl_cert_path, const char *full_enc_ssl_cert_hash_path, const char *cpabe_priv_key_path, const char *enc_cpabe_priv_key_path, 
	const char *enc_cpabe_priv_key_hash_path);

static boolean remove_attribute(SSL *ssl_client);
static boolean process_request(SSL *ssl_client);

// Implementation
static boolean record_transaction_log(SSL *ssl_client, char *attribute_name, boolean is_numerical_attribute_flag, char *event_description)
{
	SSL  *ssl_conn_AS = NULL;
	char buffer[BUFFER_LENGTH + 1];
	char username[USER_NAME_LENGTH + 1];
	char object_description[DATA_DESCRIPTION_LENGTH + 1];
	char current_date_time[DATETIME_STR_LENGTH  + 1];
	char client_ip_address[IP_ADDRESS_LENGTH + 1];

	// Get certificate owner's name, current date/time and client's IP address
	get_cert_ownername(ssl_client, GLOBAL_authority_name, username, NULL);
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_client, client_ip_address, NULL);

	sprintf(object_description, "Attribute: %s.%s (%s)", GLOBAL_authority_name, attribute_name, 
		(is_numerical_attribute_flag) ? "<numerical attribute>" : "<non-numerical attribute>");

	// Connect to Audit Server
	if(!connect_to_transaction_log_recording_service(&ssl_conn_AS))
		goto ERROR;

	// Send a request type
	write_token_into_buffer("request_type", EVENT_LOG_RECORDING, true, buffer);
	if(!SSL_send_buffer(ssl_conn_AS, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a request type failed\n");
		goto ERROR;
	}

	// Send a transaction log
	write_token_into_buffer("actor_name", username, true, buffer);
	write_token_into_buffer("actor_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", "1", false, buffer);
	write_token_into_buffer("object_owner_name", NO_REFERENCE_USERNAME, false, buffer);
	write_token_into_buffer("object_owner_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("affected_username", NO_REFERENCE_USERNAME, false, buffer);
	write_token_into_buffer("affected_user_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_description", object_description, false, buffer);
	write_token_into_buffer("event_description", event_description, false, buffer);
	write_token_into_buffer("date_time", current_date_time, false, buffer);
	write_token_into_buffer("actor_ip_address", client_ip_address, false, buffer);

	if(!SSL_send_buffer(ssl_conn_AS, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a transaction log failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_conn_AS);
	ssl_conn_AS = NULL;
	return true;

ERROR:

	if(ssl_conn_AS)
	{
		SSL_cleanup(ssl_conn_AS);
		ssl_conn_AS = NULL;
	}

	return false;
}

static boolean register_attribute(SSL *ssl_client)
{
	char      buffer[BUFFER_LENGTH + 1];
	char      token_name[TOKEN_NAME_LENGTH + 1];
	char      attribute_name[ATTRIBUTE_NAME_LENGTH + 1];
	char      is_numerical_attribute_flag_str[FLAG_LENGTH + 1];     // "0" or "1"

	MYSQL     *db_conn = NULL;
  	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Receive attribute registration information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving attribute registration information failed\n");
		goto ERROR;
	}

	// Get attribute registration information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, attribute_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "attribute_name") != 0)
		int_error("Extracting the attribute_name failed");

	if(read_token_from_buffer(buffer, 2, token_name, is_numerical_attribute_flag_str) != READ_TOKEN_SUCCESS || strcmp(token_name, "is_numerical_attribute_flag") != 0)
		int_error("Extracting the is_numerical_attribute_flag failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of attribute name. If the attribute name does not exist then add it into the database
	sprintf(stat, "SELECT attribute_id FROM %s WHERE attribute_name LIKE '%s' COLLATE latin1_general_cs "
		"AND authority_id = %u", UA__ATTRIBUTES, attribute_name, GLOBAL_authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The attribute name exists
	if(row)
	{
		// Send the attribute registration result flag
		write_token_into_buffer("attribute_registration_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Attribute name exists already", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the attribute registration result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Insert a new attribute if its name does not exist
	sprintf(stat, "INSERT INTO %s(attribute_name, is_numerical_attribute_flag, authority_id) VALUES('%s', '%s', '%u')", 
		UA__ATTRIBUTES, attribute_name, is_numerical_attribute_flag_str, GLOBAL_authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
	disconnect_db(&db_conn);

	// Send the attribute registration result flag
	write_token_into_buffer("attribute_registration_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the attribute registration result flag failed\n");
		goto ERROR;
	}

	// Record a transaction log
	record_transaction_log(ssl_client, attribute_name, (strcmp(is_numerical_attribute_flag_str, "1") == 0) ? true : false, ATTRIBUTE_REGISTRATION_MSG);
	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
	return false;
}

static boolean record_transaction_log_on_user(SSL *ssl_client, char *username, boolean is_admin_flag, char *object_description, char *event_description)
{
	SSL         *ssl_conn_AS = NULL;
	char        buffer[BUFFER_LENGTH + 1];
	char        actor_name[USER_NAME_LENGTH + 1];
	entity_type actor_type;
	char        current_date_time[DATETIME_STR_LENGTH  + 1];
	char        client_ip_address[IP_ADDRESS_LENGTH + 1];

	// Get certificate owner's name, current date/time and client's IP address
	get_cert_ownername(ssl_client, GLOBAL_authority_name, actor_name, &actor_type);
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_client, client_ip_address, NULL);

	// Connect to Audit Server
	if(!connect_to_transaction_log_recording_service(&ssl_conn_AS))
		goto ERROR;

	// Send a request type
	write_token_into_buffer("request_type", EVENT_LOG_RECORDING, true, buffer);
	if(!SSL_send_buffer(ssl_conn_AS, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a request type failed\n");
		goto ERROR;
	}

	// Send a transaction information
	write_token_into_buffer("actor_name", actor_name, true, buffer);
	write_token_into_buffer("actor_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", (actor_type == admin) ? "1" : "0", false, buffer);
	write_token_into_buffer("object_owner_name", username, false, buffer);
	write_token_into_buffer("object_owner_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_object_owner_is_admin_flag", (is_admin_flag) ? "1" : "0", false, buffer);
	write_token_into_buffer("affected_username", NO_REFERENCE_USERNAME, false, buffer);
	write_token_into_buffer("affected_user_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_description", object_description, false, buffer);
	write_token_into_buffer("event_description", event_description, false, buffer);
	write_token_into_buffer("date_time", current_date_time, false, buffer);
	write_token_into_buffer("actor_ip_address", client_ip_address, false, buffer);

	if(!SSL_send_buffer(ssl_conn_AS, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending a transaction log failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_conn_AS);
	ssl_conn_AS = NULL;
	return true;

ERROR:

	if(ssl_conn_AS)
	{
		SSL_cleanup(ssl_conn_AS);
		ssl_conn_AS = NULL;
	}

	return false;
}

static boolean remove_revoked_user_attribute(SSL *ssl_client, MYSQL *db_conn, unsigned int user_attribute_id, char *user_attribute_name, unsigned int user_id, 
	const char *salted_passwd_hash_path, const char *ssl_cert_priv_key_path, const char *ssl_cert_req_path, const char *enc_ssl_cert_path, 
	const char *full_enc_ssl_cert_path, const char *full_enc_ssl_cert_hash_path, const char *cpabe_priv_key_path, const char *enc_cpabe_priv_key_path, 
	const char *enc_cpabe_priv_key_hash_path)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	char      username[USER_NAME_LENGTH + 1];
	char      email_address[EMAIL_ADDRESS_LENGTH + 1];
	boolean   has_user_attribute_left;

	char      object_description[DATA_DESCRIPTION_LENGTH + 1];

	// Query for the user
	sprintf(stat, "SELECT username, email_address FROM %s WHERE user_id = %u", UA__USERS, user_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	if(!row)
	{
		fprintf(stderr, "User does not exist, he/she may be removed already\n");
		goto ERROR;
	}

	strcpy(username, row[0]);
	strcpy(email_address, row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Delete the user's attribute
	sprintf(stat, "DELETE FROM %s WHERE user_attribute_id = %u", UA__USER_ATTRIBUTES, user_attribute_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      	int_error(err_msg);
	}

	// Record a transaction log
	sprintf(object_description, "Attribute: %s.%s", GLOBAL_authority_name, user_attribute_name);
	record_transaction_log_on_user(ssl_client, username, false, object_description, ATTRIBUTE_ASSINGED_TO_USER_WAS_REMOVED);

	// Check for the remaining of user attributes
	sprintf(stat, "SELECT user_attribute_id FROM %s WHERE user_id = %u", UA__USER_ATTRIBUTES, user_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	has_user_attribute_left = (row) ? true : false;
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(has_user_attribute_left)
	{
		char random_passwd[PASSWD_LENGTH + 1];
		char random_salt_value[SALT_VALUE_LENGTH + 1];
		char random_passwd_with_salt_value[PASSWD_LENGTH + SALT_VALUE_LENGTH + 1];
		char salted_passwd_hash[SHA1_DIGEST_LENGTH + 1];

		// Generate a random 8 character password
		gen_random_password(random_passwd);

		// Generate a random 8 character salt value
		gen_random_salt_value(random_salt_value);

		// Get the salted password hash
		sprintf(random_passwd_with_salt_value, "%s%s", random_passwd, random_salt_value);
		sum_sha1_from_string(random_passwd_with_salt_value, strlen(random_passwd_with_salt_value), salted_passwd_hash, salted_passwd_hash_path);

		// Update the password hash information
		sprintf(stat, "UPDATE %s SET salted_passwd_hash = '%s', salt_value = '%s' WHERE user_id = %u", UA__USERS, salted_passwd_hash, random_salt_value, user_id);
		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

		// Generate an SSL certificate
		generate_ssl_cert(db_conn, user_id, username, false, random_passwd, email_address, ssl_cert_priv_key_path, ssl_cert_req_path, enc_ssl_cert_path, 
			full_enc_ssl_cert_path, full_enc_ssl_cert_hash_path);

		// Generate a CP-ABE private key
		generate_cpabe_priv_key(db_conn, user_id, username, random_passwd, cpabe_priv_key_path, enc_cpabe_priv_key_path, enc_cpabe_priv_key_hash_path);

		// Lock an e-mail sending
		if(sem_wait(&email_sending_lock_mutex) != 0)
			int_error("Locking the mutex failed");

		// Send a password to a user's e-mail address
		send_passwd_to_user_email_address(email_address, username, false, random_passwd);

		// Unlock an e-mail sending
		if(sem_post(&email_sending_lock_mutex) != 0)
			int_error("Unlocking the mutex failed");
	}
	else
	{
		// If the user doesn't have attribute left then delete the user
		if(!remove_all_user_info(ssl_client, db_conn, user_id, username, false, NULL))
			goto ERROR;
	}

	return true;

ERROR:
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return false;
}

static boolean remove_attribute(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         attribute_name[ATTRIBUTE_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int attribute_id;
	boolean      is_numerical_attribute_flag;

	// Receive attribute removal information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving attribute removal information failed\n");
		goto ERROR;
	}

	// Get attribute removal information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, attribute_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "attribute_name") != 0)
		int_error("Extracting the attribute_name failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of attribute name
	sprintf(stat, "SELECT attribute_id, is_numerical_attribute_flag FROM %s WHERE attribute_name LIKE '%s' "
		"COLLATE latin1_general_cs AND authority_id = %u", UA__ATTRIBUTES, attribute_name, GLOBAL_authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The attribute does not exist
	if(!row)
	{
		// Send the attribute registration result flag
		write_token_into_buffer("attribute_removal_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Attribute doest not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the attribute removal result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	attribute_id                = atoi(row[0]);
	is_numerical_attribute_flag = (strcmp(row[1], "1") == 0) ? true : false;

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Delete the attribute
	sprintf(stat, "DELETE FROM %s WHERE attribute_id = %u", UA__ATTRIBUTES, attribute_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      	int_error(err_msg);
	}

	// Record a transaction log
	record_transaction_log(ssl_client, attribute_name, is_numerical_attribute_flag, ATTRIBUTE_REMOVAL_MSG);

	// Query for users who were supposed to have the revoked attribute
	sprintf(stat, "SELECT user_attribute_id, user_id FROM %s WHERE attribute_id = %u", UA__USER_ATTRIBUTES, attribute_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		unsigned int user_attribute_id;
		unsigned int user_id;

		user_attribute_id = atoi(row[0]);	
		user_id           = atoi(row[1]);

		// Remove revoked attribute from the user
		remove_revoked_user_attribute(ssl_client, db_conn, user_attribute_id, attribute_name, user_id, SALTED_PASSWD_HASH_PATH, SSL_CERT_PRIV_KEY_PATH, 
			SSL_CERT_REQ_PATH, ENC_SSL_CERT_PATH, FULL_ENC_SSL_CERT_PATH, FULL_ENC_SSL_CERT_HASH_PATH, CPABE_PRIV_KEY_PATH, ENC_CPABE_PRIV_KEY_PATH, 
			ENC_CPABE_PRIV_KEY_HASH_PATH);   // Ignore any error
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);

	// Send the attribute removal result flag
	write_token_into_buffer("attribute_removal_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the attribute removal result flag failed\n");
		goto ERROR;
	}

	return true;

ERROR:

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
	return false;
}

static boolean process_request(SSL *ssl_client)
{
	char buffer[BUFFER_LENGTH + 1];
	char token_name[TOKEN_NAME_LENGTH + 1];
	char request[REQUEST_TYPE_LENGTH + 1];
	
	// Receive request information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving request information failed\n");
		goto ERROR;
	}

	// Get a request information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, request) != READ_TOKEN_SUCCESS || strcmp(token_name, "request") != 0)
		int_error("Extracting the request failed");

	if(strcmp(request, ATTRIBUTE_REGISTRATION) == 0)
	{
		return register_attribute(ssl_client);
	}
	else if(strcmp(request, ATTRIBUTE_REMOVAL) == 0)
	{
		return remove_attribute(ssl_client);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

void *attribute_management_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

    	ctx = setup_server_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(UA_ATTRIBUTE_MANAGEMENT_PORT);
    	if(!bio_acc)
        	int_error("Creating server socket failed");
  
    	if(BIO_do_accept(bio_acc) <= 0)
        	int_error("Binding server socket failed");
  
    	for(;;)
    	{
        	if(BIO_do_accept(bio_acc) <= 0)
            		int_error("Accepting connection failed");
 
        	bio_client = BIO_pop(bio_acc);

        	if(!(ssl_client = SSL_new(ctx)))
            		int_error("Creating SSL context failed");

        	SSL_set_bio(ssl_client, bio_client, bio_client);
		if(SSL_accept(ssl_client) <= 0)
		{
        		fprintf(stderr, "Accepting SSL connection failed\n");
			goto ERROR_AT_SSL_LAYER;
		}

		hosts[0] = ADMIN_CN; 
    		if((err = post_connection_check(ssl_client, hosts, 1, true, GLOBAL_authority_name)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Process a request
		if(!process_request(ssl_client))
			goto ERROR_AT_SSL_LAYER;

ERROR_AT_SSL_LAYER:

		SSL_cleanup(ssl_client);
		ssl_client = NULL;
    		ERR_remove_state(0);
    	}
    
    	SSL_CTX_free(ctx);
	ctx = NULL;

    	BIO_free(bio_acc);
	bio_acc = NULL;

	pthread_exit(NULL);
    	return NULL;
}




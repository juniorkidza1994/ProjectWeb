#include "UA_common.h"
#include "simclist.h"

#define SALTED_PASSWD_HASH_PATH      "UA_cache/UA_user_management.salted_passwd_hash"

#define SSL_CERT_PRIV_KEY_PATH       "UA_cache/UA_user_management.ssl_cert_priv_key"
#define SSL_CERT_REQ_PATH            "UA_cache/UA_user_management.ssl_cert_req"
#define ENC_SSL_CERT_PATH            "UA_cache/UA_user_management.enc_ssl_cert"
#define FULL_ENC_SSL_CERT_PATH       "UA_cache/UA_user_management.full_enc_ssl_cert"
#define FULL_ENC_SSL_CERT_HASH_PATH  "UA_cache/UA_user_management.full_enc_ssl_cert_hash"

#define CPABE_PRIV_KEY_PATH          "UA_cache/UA_user_management.cpabe_priv_key"
#define ENC_CPABE_PRIV_KEY_PATH      "UA_cache/UA_user_management.cpabe_priv_key_ciphertext"
#define ENC_CPABE_PRIV_KEY_HASH_PATH "UA_cache/UA_user_management.cpabe_priv_key_ciphertext_hash"

struct sync_user_attribute_node
{
	unsigned int node_id;
	unsigned int user_attribute_id;
	unsigned int attribute_id;
	char         attribute_name[ATTRIBUTE_NAME_LENGTH + 1];
	unsigned int attribute_value;    // This field will be used if the attribute is numerical atribute
};

typedef struct sync_user_attribute_node sync_user_attribute_node_t;

// Local Variable
static list_t sync_user_attribute_node_list;

// Local Function Prototypes
static boolean is_reserved_username(char *username);
static boolean get_attribute_id(MYSQL *db_conn, char *attribute_name, unsigned int *attribute_id_ret);
static void update_user_attribute_value(MYSQL *db_conn, unsigned int user_attribute_id, unsigned int attribute_value);
static void insert_new_user_attribute(MYSQL *db_conn, unsigned int user_id, unsigned int attribute_id, unsigned int attribute_value);
static void remove_revoked_user_attribute(MYSQL *db_conn, unsigned int user_attribute_id);
static boolean receive_user_attribute_list(SSL *ssl_client, MYSQL *db_conn, unsigned int user_id, char *username, char *result_flag_msg);
static void insert_access_permission(MYSQL *db_conn, unsigned int user_id, unsigned int phr_owner_id, unsigned int phr_owner_authority_id, 
	boolean upload_permission_flag, boolean download_permission_flag, boolean delete_permission_flag);

static boolean record_transaction_log_on_user(SSL *ssl_client, char *username, boolean is_admin_flag, char *object_description, char *event_description);
static boolean register_user(SSL *ssl_client);
static boolean edit_user_email_address(SSL *ssl_client);
static void prepare_sync_user_attribute_node_list(MYSQL *db_conn, unsigned int user_id);
static boolean edit_user_attribute_list(SSL *ssl_client);
static boolean edit_user_attribute_value(SSL *ssl_client);
static boolean reset_user_passwd(SSL *ssl_client);
static boolean record_transaction_log_on_access_permission_granted_user_was_removed(SSL *ssl_client, char *revoked_username, char *phr_owner_name);
static boolean remove_user(SSL *ssl_client);
static boolean remove_user_attribute(SSL *ssl_client);
static boolean register_admin(SSL *ssl_client);
static boolean edit_admin_email_address(SSL *ssl_client);
static boolean reset_admin_passwd(SSL *ssl_client);
static boolean remove_admin(SSL *ssl_client);
static boolean process_request(SSL *ssl_client);
static size_t list_meter_sync_user_attribute_node_t(const void *element);
static int list_seeker_by_user_attribute_id(const void *element, const void *key);
static int list_comparator_by_user_attribute_node_id(const void *nodeA, const void *nodeB);
static void init_user_attribute_synchronization_list();
static void uninit_user_attribute_synchronization_list();

// Implementation
static boolean is_reserved_username(char *username)
{
	if(strcmp(username, NO_REFERENCE_USERNAME) == 0)
	{
		return true;
	}
	else if(strcmp(username, INVALID_USERNAME) == 0)
	{
		return true;
	}
	else if(strcmp(username, PASSWD_FORGETTOR_NAME) == 0)
	{
		return true;
	}
	else if(strcmp(username, ITS_ADMIN_NAME) == 0)
	{
		return true;
	}
	else if(strcmp(username, REFERENCE_TO_ALL_ADMIN_NAMES) == 0)
	{
		return true;
	}

	return false;
}

void generate_ssl_cert(MYSQL *db_conn, unsigned int user_id, char *username, boolean is_admin_flag, char *passwd, char *email_address, 
	const char *ssl_cert_priv_key_path, const char *ssl_cert_req_path, const char *enc_ssl_cert_path, const char *full_enc_ssl_cert_path, 
	const char *full_enc_ssl_cert_hash_path)
{
	char         cmd[CMD_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];
	char         stat[SQL_STATEMENT_LENGTH + 1];

	unsigned int len, enc_ssl_cert_size;
	char         *enc_ssl_cert_data;
	char         enc_ssl_cert_hash[SHA1_DIGEST_LENGTH + 1];
	char         *enc_ssl_cert_chunk;
	char         *query;

	// Generate an SSL certificate
	if(is_admin_flag)
	{
		sprintf(cmd, "openssl req -newkey rsa:1024 -sha1 -keyout %s -out %s -passout pass:%s -subj '/CN=%s.%s%s"
			"/ST=Songkla/C=TH/emailAddress=%s/O=PSU/OU=PSU'", ssl_cert_priv_key_path, ssl_cert_req_path, passwd, 
			GLOBAL_authority_name, username, ADMIN_IDENTITY_TOKEN, email_address);
	}
	else
	{
		sprintf(cmd, "openssl req -newkey rsa:1024 -sha1 -keyout %s -out %s -passout pass:%s -subj '/CN=%s.%s%s"
			"/ST=Songkla/C=TH/emailAddress=%s/O=PSU/OU=PSU'", ssl_cert_priv_key_path, ssl_cert_req_path, passwd, 
			GLOBAL_authority_name, username, USER_IDENTITY_TOKEN, email_address);
	}

	exec_cmd(cmd, strlen(cmd), err_msg, sizeof(err_msg));
	if(!strstr(err_msg, "writing new private key"))
	{
		fprintf(stderr, "Error: \"%s\"\n", err_msg);
		int_error("Generating an SSL certificate failed");
	}

	sprintf(cmd, "openssl x509 -req -days 365 -in %s -sha1 -extfile %s -extensions usr_cert -CA %s -CAkey %s -CAcreateserial "
		"-out %s -passin pass:%s", ssl_cert_req_path, OPENSSL_PHRAPP_CNF_PATH, USER_CA_FULL_CERTFILE_PATH, 
		USER_CA_FULL_CERTFILE_PATH, enc_ssl_cert_path, USER_CA_CERTFILE_PASSWD);

	exec_cmd(cmd, strlen(cmd), err_msg, sizeof(err_msg));
	if(!strstr(err_msg, "Getting CA Private Key"))
	{
		fprintf(stderr, "Error: \"%s\"\n", err_msg);
		int_error("Generating an SSL certificate failed");
	}

	sprintf(cmd, "cat %s %s %s %s > %s", enc_ssl_cert_path, ssl_cert_priv_key_path, USER_CA_ONLY_CERT_CERTFILE_PATH, 
		PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH, full_enc_ssl_cert_path);

	exec_cmd(cmd, strlen(cmd), err_msg, sizeof(err_msg));
	if(strcmp(err_msg, "") != 0)
	{
		fprintf(stderr, "Error: \"%s\"\n", err_msg);
		int_error("Generating an SSL certificate failed");
	}

	// Allocate heap variables
	enc_ssl_cert_data = (char *)malloc(sizeof(char)*1000*1024);
	if(!enc_ssl_cert_data)
	{
		int_error("Allocating memory for \"enc_ssl_cert_data\" failed");
	}

	enc_ssl_cert_chunk = (char *)malloc(sizeof(char)*((1000*1024)*2+1));
	if(!enc_ssl_cert_chunk)
	{
		int_error("Allocating memory for \"enc_ssl_cert_chunk\" failed");
	}

	query = (char *)malloc(sizeof(char)*(((1000*1024)*2+1)+sizeof(stat)+1));
	if(!query)
	{
		int_error("Allocating memory for \"query\" failed");
	}

	// Read the SSL certificate into the buffer
	if(!read_bin_file(full_enc_ssl_cert_path, enc_ssl_cert_data, sizeof(char)*1000*1024, &enc_ssl_cert_size))
		int_error("Reading full encrypted SSL certificate failed");

	sum_sha1_from_file(full_enc_ssl_cert_path, enc_ssl_cert_hash, full_enc_ssl_cert_hash_path);

	// Insert encrypted SSL certificate and its hash into database
	if(is_admin_flag)
	{
		sprintf(stat, "UPDATE %s SET enc_ssl_cert='%%s', enc_ssl_cert_hash='%s' WHERE admin_id=%u", UA__ADMINS, enc_ssl_cert_hash, user_id);
	}
	else
	{
		char ssl_pub_key_data[SSL_PUB_KEY_LENGTH + 1];

		// Read the SSL public key into the buffer
		if(!read_bin_file(enc_ssl_cert_path, ssl_pub_key_data, SSL_PUB_KEY_LENGTH, NULL))
			int_error("Reading the SSL public key failed");

		sprintf(stat, "UPDATE %s SET ssl_pub_key='%s', enc_ssl_cert='%%s', enc_ssl_cert_hash='%s' WHERE user_id=%u", 
			UA__USERS, ssl_pub_key_data, enc_ssl_cert_hash, user_id);
	}

	// Delete files
	unlink(ssl_cert_priv_key_path);
	unlink(ssl_cert_req_path);
	unlink(enc_ssl_cert_path);
	unlink(full_enc_ssl_cert_path);

	// Take the escaped SQL string
	mysql_real_escape_string(db_conn, enc_ssl_cert_chunk, enc_ssl_cert_data, enc_ssl_cert_size);
  	len = snprintf(query, sizeof(stat)+sizeof(char)*((1000*1024)*2+1), stat, enc_ssl_cert_chunk);

	if(mysql_real_query(db_conn, query, len))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	// Free heap variables
	if(enc_ssl_cert_data)
	{
		free(enc_ssl_cert_data);
		enc_ssl_cert_data = NULL;
	}

	if(enc_ssl_cert_chunk)
	{
		free(enc_ssl_cert_chunk);
		enc_ssl_cert_chunk = NULL;
	}

	if(query)
	{
		free(query);
		query = NULL;
	}
}

static boolean get_attribute_id(MYSQL *db_conn, char *attribute_name, unsigned int *attribute_id_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Query for attribute id of current authority
	sprintf(stat, "SELECT attribute_id FROM %s WHERE attribute_name LIKE '%s' COLLATE latin1_general_cs", UA__ATTRIBUTES, attribute_name);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		fprintf(stderr, "Getting an attribute id from a database failed\n");
		goto ERROR;
	}

	*attribute_id_ret = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
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

static void update_user_attribute_value(MYSQL *db_conn, unsigned int user_attribute_id, unsigned int attribute_value)
{
	char  stat[SQL_STATEMENT_LENGTH + 1];
	char  err_msg[ERR_MSG_LENGTH + 1];

	// Update the user attribute value
	sprintf(stat, "UPDATE %s SET attribute_value = %u WHERE user_attribute_id = %u", UA__USER_ATTRIBUTES, attribute_value, user_attribute_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
}

static void insert_new_user_attribute(MYSQL *db_conn, unsigned int user_id, unsigned int attribute_id, unsigned int attribute_value)
{
	char  stat[SQL_STATEMENT_LENGTH + 1];
	char  err_msg[ERR_MSG_LENGTH + 1];

	// Insert the user attribute
	sprintf(stat, "INSERT INTO %s (user_id, attribute_id, attribute_value) VALUES(%u, %u, %u)", UA__USER_ATTRIBUTES, user_id, attribute_id, attribute_value);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
}

static void remove_revoked_user_attribute(MYSQL *db_conn, unsigned int user_attribute_id)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Delete a revoked user attribute
	sprintf(stat, "DELETE FROM %s WHERE user_attribute_id = %u", UA__USER_ATTRIBUTES, user_attribute_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
}

static boolean receive_user_attribute_list(SSL *ssl_client, MYSQL *db_conn, unsigned int user_id, char *username, char *result_flag_msg)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];

	char         end_of_user_attribute_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      end_of_user_attribute_list_flag;
	char         attribute_name[ATTRIBUTE_NAME_LENGTH + 1];
	char         is_numerical_attribute_flag_str_tmp[FLAG_LENGTH + 1];
	boolean      is_numerical_attribute_flag;
	char         attribute_value_str_tmp[ATTRIBUTE_VALUE_LENGTH + 1];
	unsigned int attribute_value = 0;

	unsigned int attribute_id;
	char         object_description[DATA_DESCRIPTION_LENGTH + 1];

	sync_user_attribute_node_t *ptr_user_attribute_node = NULL;

	while(1)
	{
		// Receive user attribute list
		if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving user attribute list failed\n");
			goto ERROR;
		}

		// Get user attribute list tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, end_of_user_attribute_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "end_of_user_attribute_list_flag") != 0)
		{
			int_error("Extracting the end_of_user_attribute_list_flag failed");
		}

		end_of_user_attribute_list_flag = (strcmp(end_of_user_attribute_list_flag_str_tmp, "1") == 0) ? true : false;
		if(end_of_user_attribute_list_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, attribute_name) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "attribute_name") != 0)
		{
			int_error("Extracting the attribute_name failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, is_numerical_attribute_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_numerical_attribute_flag") != 0)
		{
			int_error("Extracting the is_numerical_attribute_flag failed");
		}

		is_numerical_attribute_flag = (strcmp(is_numerical_attribute_flag_str_tmp, "1") == 0) ? true : false;
		if(is_numerical_attribute_flag)
		{
			if(read_token_from_buffer(buffer, 4, token_name, attribute_value_str_tmp) 
				!= READ_TOKEN_SUCCESS || strcmp(token_name, "attribute_value") != 0)
			{
				int_error("Extracting the attribute_value failed");
			}

			attribute_value = atoi(attribute_value_str_tmp);
		}

		if(!get_attribute_id(db_conn, attribute_name, &attribute_id))
		{
			// Send the user attribute registration/editing result flag
			write_token_into_buffer(result_flag_msg, "0", true, buffer);
			write_token_into_buffer("error_msg", "Attribute does not exist", false, buffer);

			if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
			{
				fprintf(stderr, "Sending the user attribute registration/editing result flag failed\n");
				goto ERROR;
			}

			goto ERROR;		
		}

		// Get a user attribute node that corresponds to "attribute_name" if exists in a linked list
		ptr_user_attribute_node = (sync_user_attribute_node_t *)list_seek(&sync_user_attribute_node_list, &attribute_id);

		// If a user attribute exists then update it in a database and remove from the list, unless insert that user attribute into a database
		if(ptr_user_attribute_node)
		{
			// Update the attribute value if it is numerical attribute and value is changed
			if(is_numerical_attribute_flag && ptr_user_attribute_node->attribute_value != attribute_value)
			{
				update_user_attribute_value(db_conn, ptr_user_attribute_node->user_attribute_id, attribute_value);

				// Record a transaction log
				sprintf(object_description, "Attribute: %s.%s = %u", GLOBAL_authority_name, attribute_name, attribute_value);
				record_transaction_log_on_user(ssl_client, username, false, object_description, USER_ATTRIBUTE_CHANGING_MSG);
			}

			// Remove a user attribute from the list
			if(list_delete_at(&sync_user_attribute_node_list, list_locate(&sync_user_attribute_node_list, ptr_user_attribute_node)) < 0)
				int_error("Removing a user attribute node failed");
		}
		else
		{
			// Insert a user attribute into a database
			insert_new_user_attribute(db_conn, user_id, attribute_id, (is_numerical_attribute_flag) ? attribute_value : 0);

			// Record a transaction log
			if(is_numerical_attribute_flag)
			{
				sprintf(object_description, "Attribute: %s.%s = %u", GLOBAL_authority_name, attribute_name, attribute_value);
			}
			else
			{
				sprintf(object_description, "Attribute: %s.%s", GLOBAL_authority_name, attribute_name);
			}

			record_transaction_log_on_user(ssl_client, username, false, object_description, USER_ATTRIBUTE_ADDING_MSG);
		}
	}

	if(!list_iterator_start(&sync_user_attribute_node_list))
		int_error("Starting list iteration failed");

	// The remaining user attributes in the list are revoked by an admin
	while(list_iterator_hasnext(&sync_user_attribute_node_list))
	{
		ptr_user_attribute_node = (sync_user_attribute_node_t *)list_iterator_next(&sync_user_attribute_node_list);

		// Remove a revoked user attribute from a database
		remove_revoked_user_attribute(db_conn, ptr_user_attribute_node->user_attribute_id);

		// Record a transaction log
		sprintf(object_description, "Attribute: %s.%s", GLOBAL_authority_name, ptr_user_attribute_node->attribute_name);
		record_transaction_log_on_user(ssl_client, username, false, object_description, USER_ATTRIBUTE_REMOVAL_MSG);
	}

	if(!list_iterator_stop(&sync_user_attribute_node_list))
		int_error("Stopping list iteration failed");

	// Remove all nodes from the list
	list_clear(&sync_user_attribute_node_list);

	// Send the user attribute registration/editing result flag
	write_token_into_buffer(result_flag_msg, "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user attribute registration/editing result flag failed\n");
		goto ERROR;
	}

	return true;

ERROR:

	return false;
}

void generate_cpabe_priv_key(MYSQL *db_conn, unsigned int user_id, char *username, char *passwd, const char *cpabe_priv_key_path, 
	const char *enc_cpabe_priv_key_path, const char *enc_cpabe_priv_key_hash_path)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	char         attribute_name[ATTRIBUTE_NAME_LENGTH + 1];
	boolean      is_numerical_attribute_flag;
	unsigned int attribute_value;

	char         *keygen_cmd;
	char         attribute_token[ATTRIBUTE_TOKEN_LENGTH + 1];

	unsigned int len, enc_cpabe_priv_key_size;
	char         *enc_cpabe_priv_key_data = NULL;
	char         enc_cpabe_priv_key_hash[SHA1_DIGEST_LENGTH + 1];
	char         *enc_cpabe_priv_key_chunk = NULL;
	char         *query = NULL;

	// Allocate a heap variable
	keygen_cmd = (char *)malloc(sizeof(char)*1000*1024);
	if(!keygen_cmd)
	{
		int_error("Allocating memory for \"keygen_cmd\" failed");
	}

	// Query for user attributes
	sprintf(stat, "SELECT ATT.attribute_name, ATT.is_numerical_attribute_flag, UAT.attribute_value FROM %s ATT, %s UAT "
		"WHERE UAT.user_id=%u AND UAT.attribute_id=ATT.attribute_id", UA__ATTRIBUTES, UA__USER_ATTRIBUTES, user_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// No any user attribute
	if(!row)
	{
		int_error("Getting user attributes for making a CP-ABE private key failed");
	}

	// Make a CP-ABE private key generation command
	sprintf(keygen_cmd, "%s -o %s %s %s 'UsernameNode__SUB__%s__SUB__%s'", CPABE_KEYGEN_PATH, cpabe_priv_key_path, 
		CPABE_PUB_KEY_PATH, CPABE_MASTER_KEY_PATH, GLOBAL_authority_name, username);

	do
	{
		strcpy(attribute_name, row[0]);
		is_numerical_attribute_flag = (strcmp(row[1], "1") == 0) ? true : false;
		attribute_value             = atoi(row[2]);

		if(is_numerical_attribute_flag)
		{
			sprintf(attribute_token, " 'AttributeNode__SUB__%s__SUB__%s = %u'", GLOBAL_authority_name, attribute_name, attribute_value);
		}
		else
		{
			sprintf(attribute_token, " 'AttributeNode__SUB__%s__SUB__%s'", GLOBAL_authority_name, attribute_name);
		}

		strcat(keygen_cmd, attribute_token);		
	}
	while((row = mysql_fetch_row(result)));

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Generate a CP-ABE private key
	exec_cmd(keygen_cmd, strlen(keygen_cmd), err_msg, sizeof(err_msg));
	if(strcmp(err_msg, "") != 0)
	{
		fprintf(stderr, "Error: \"%s\"\n", err_msg);
		int_error("Generating a CP-ABE private key failed");
	}

	if(keygen_cmd)
	{
		free(keygen_cmd);
		keygen_cmd = NULL;
	}

	// Encrypt the CP-ABE private key with random password
	if(!des3_encrypt(cpabe_priv_key_path, enc_cpabe_priv_key_path, passwd, err_msg))
	{
		fprintf(stderr, "Error: \"%s\"\n", err_msg);
		int_error("Encrypting the CP-ABE private key failed");
	}

	unlink(cpabe_priv_key_path);

	// Allocate heap variables
	enc_cpabe_priv_key_data = (char *)malloc(sizeof(char)*1000*1024);
	if(!enc_cpabe_priv_key_data)
	{
		int_error("Allocating memory for \"enc_cpabe_priv_key_data\" failed");
	}

	enc_cpabe_priv_key_chunk = (char *)malloc(sizeof(char)*((1000*1024)*2+1));
	if(!enc_cpabe_priv_key_chunk)
	{
		int_error("Allocating memory for \"enc_cpabe_priv_key_chunk\" failed");
	}

	query = (char *)malloc(sizeof(char)*(((1000*1024)*2+1)+sizeof(stat)+1));
	if(!query)
	{
		int_error("Allocating memory for \"query\" failed");
	}

	// Read the CP-ABE private key into the buffer
	if(!read_bin_file(enc_cpabe_priv_key_path, enc_cpabe_priv_key_data, sizeof(char)*1000*1024, &enc_cpabe_priv_key_size))
		int_error("Reading an encrypted CP-ABE private key failed");

	sum_sha1_from_file(enc_cpabe_priv_key_path, enc_cpabe_priv_key_hash, enc_cpabe_priv_key_hash_path);
	unlink(enc_cpabe_priv_key_path);

	// Insert encrypted CP-ABE private key and its hash into database
	sprintf(stat, "UPDATE %s SET enc_cpabe_priv_key='%%s', enc_cpabe_priv_key_hash='%s' WHERE user_id=%u", UA__USERS, enc_cpabe_priv_key_hash, user_id);

	mysql_real_escape_string(db_conn, enc_cpabe_priv_key_chunk, enc_cpabe_priv_key_data, enc_cpabe_priv_key_size);
  	len = snprintf(query, sizeof(stat)+sizeof(char)*((1000*1024)*2+1), stat, enc_cpabe_priv_key_chunk);

	if(mysql_real_query(db_conn, query, len))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	// Free heap variables
	if(enc_cpabe_priv_key_data)
	{
		free(enc_cpabe_priv_key_data);
		enc_cpabe_priv_key_data = NULL;
	}

	if(enc_cpabe_priv_key_chunk)
	{
		free(enc_cpabe_priv_key_chunk);
		enc_cpabe_priv_key_chunk = NULL;
	}

	if(query)
	{
		free(query);
		query = NULL;
	}
}

static void insert_access_permission(MYSQL *db_conn, unsigned int user_id, unsigned int phr_owner_id, unsigned int phr_owner_authority_id, 
	boolean upload_permission_flag, boolean download_permission_flag, boolean delete_permission_flag)
{
  	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Check for the existence of access permission for PHR owner's data. It should not exists
	sprintf(stat, "SELECT access_permission_id FROM %s WHERE user_id=%u AND phr_owner_id=%u AND "
		"phr_owner_authority_id=%u", UA__ACCESS_PERMISSIONS, user_id, phr_owner_id, phr_owner_authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The permission exists
	if(row)
		int_error("The permission exists");

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Insert access permission into database
	sprintf(stat, "INSERT INTO %s(user_id, phr_owner_id, phr_owner_authority_id, upload_permission_flag, download_permission_flag, "
		"delete_permission_flag) VALUES(%u, %u, %u, '%s', '%s', '%s')", UA__ACCESS_PERMISSIONS, user_id, phr_owner_id, phr_owner_authority_id, 
		(upload_permission_flag) ? "1" : "0", (download_permission_flag) ? "1" : "0", (delete_permission_flag) ? "1" : "0");

	if(mysql_query(db_conn, stat))
 	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
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

boolean send_passwd_to_user_email_address(char *email_to, char *username, boolean is_admin_flag, char *passwd)
{
printf("***passwd: %s\n", passwd);

	char payload_msg[EMAIL_MSG_LINE_LENGTH + 1];
	sprintf(payload_msg, "To: %s\n", email_to);
	send_email_config_payload(0, payload_msg);

	sprintf(payload_msg, "From: %s(%s's mailer)\n", GLOBAL_authority_email_address, GLOBAL_authority_name);
	send_email_config_payload(1, payload_msg);

	sprintf(payload_msg, "Subject: Your account's password\n");
	send_email_config_payload(2, payload_msg);

	sprintf(payload_msg, "\n");  // Empty line to divide headers from body, see RFC5322
	send_email_config_payload(3, payload_msg);

	sprintf(payload_msg, "Authority name = \"%s\"\n", GLOBAL_authority_name);
	send_email_config_payload(4, payload_msg);

	sprintf(payload_msg, "Username = \"%s\"\n", username);
	send_email_config_payload(5, payload_msg);

	sprintf(payload_msg, "Status = \"%s\"\n", (is_admin_flag) ? "administrator" : "user");
	send_email_config_payload(6, payload_msg);

	sprintf(payload_msg, "Password = \"%s\"\n", passwd);
	send_email_config_payload(7, payload_msg);

	payload_msg[0] = 0;  // Fill a NULL terminated character to tell a send_main() that end of payload
	send_email_config_payload(8, payload_msg);

	return send_email(email_to);
}

static boolean register_user(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];
	char         email_address[EMAIL_ADDRESS_LENGTH + 1];

	char         random_passwd[PASSWD_LENGTH + 1];
	char         random_salt_value[SALT_VALUE_LENGTH + 1];
	char         random_passwd_with_salt_value[PASSWD_LENGTH + SALT_VALUE_LENGTH + 1];
	char         salted_passwd_hash[SHA1_DIGEST_LENGTH + 1];

	unsigned int user_id;

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];
	
	// Receive user information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving user information failed\n");
		goto ERROR;
	}

	// Get user information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	if(read_token_from_buffer(buffer, 2, token_name, email_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "email_address") != 0)
		int_error("Extracting the email_address failed");

	// Check for reserved username
	if(is_reserved_username(username))
	{
		// Send the user registration result flag
		write_token_into_buffer("user_registration_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "This username is reserved already", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user registration result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username. If the username does not exist then add it into the database
	sprintf(stat, "SELECT user_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, username);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The username exists
	if(row)
	{
		// Send the user registration result flag
		write_token_into_buffer("user_registration_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Username name exists already", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user registration result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Generate a random 8 character password
	gen_random_password(random_passwd);

	// Generate a random 8 character salt value
	gen_random_salt_value(random_salt_value);

	// Get the salted password hash
	sprintf(random_passwd_with_salt_value, "%s%s", random_passwd, random_salt_value);
	sum_sha1_from_string(random_passwd_with_salt_value, strlen(random_passwd_with_salt_value), salted_passwd_hash, SALTED_PASSWD_HASH_PATH);

	// Insert a new user if he/she does not exist
	sprintf(stat, "INSERT INTO %s(username, salted_passwd_hash, salt_value, email_address, passwd_resetting_code, enc_ssl_cert, enc_ssl_cert_hash, "
		"enc_cpabe_priv_key, enc_cpabe_priv_key_hash) VALUES('%s', '%s', '%s', '%s', '', NULL, NULL, NULL, NULL)", UA__USERS, username, 
		salted_passwd_hash, random_salt_value, email_address);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
	
	// Get a user's id
	sprintf(stat, "SELECT user_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, username);
	if(mysql_query(db_conn, stat))
 	{
	      	sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      	int_error(err_msg);
	}

	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	if(!row)
		int_error("Getting a user id from database failed");

	user_id = atoi(row[0]);
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Record a transaction log
	record_transaction_log_on_user(ssl_client, username, false, NO_SPECIFIC_DATA, USER_REGISTRATION_MSG);
	
	// Generate an SSL certificate
	generate_ssl_cert(db_conn, user_id, username, false, random_passwd, email_address, SSL_CERT_PRIV_KEY_PATH, SSL_CERT_REQ_PATH, ENC_SSL_CERT_PATH, 
		FULL_ENC_SSL_CERT_PATH, FULL_ENC_SSL_CERT_HASH_PATH);
	
	// Send the user registration result flag
	write_token_into_buffer("user_registration_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user registration result flag failed\n");
		goto ERROR;
	}
		
	// Generate a CP-ABE private key and an access permission set for a user
	if(!receive_user_attribute_list(ssl_client, db_conn, user_id, username, "user_attribute_registration_result_flag"))
	{
		// If receiving the user attribute list failed then delete the user
		remove_all_user_info(ssl_client, db_conn, user_id, username, false, NULL);   // Ignore any error
		goto ERROR;
	}

	insert_access_permission(db_conn, user_id, user_id, GLOBAL_authority_id, true, true, true);
	generate_cpabe_priv_key(db_conn, user_id, username, random_passwd, CPABE_PRIV_KEY_PATH, ENC_CPABE_PRIV_KEY_PATH, ENC_CPABE_PRIV_KEY_HASH_PATH);
	disconnect_db(&db_conn);

	// Lock an e-mail sending
	if(sem_wait(&email_sending_lock_mutex) != 0)
		int_error("Locking the mutex failed");

	if(!send_passwd_to_user_email_address(email_address, username, false, random_passwd))
	{
		// Send the key and permission generating result flag
		write_token_into_buffer("key_and_permission_generating_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", get_send_email_error_msg(), false, buffer);

		// Unlock an e-mail sending
		if(sem_post(&email_sending_lock_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the key and permission generating result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Unlock an e-mail sending
	if(sem_post(&email_sending_lock_mutex) != 0)
		int_error("Unlocking the mutex failed");

	// Send the key and permission generating result flag
	write_token_into_buffer("key_and_permission_generating_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the key and permission generating result flag failed\n");
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

static boolean edit_user_email_address(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];
	char         email_address[EMAIL_ADDRESS_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_id;
	char         object_description[DATA_DESCRIPTION_LENGTH + 1];

	// Receive user's e-mail address information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving user's e-mail address information failed\n");
		goto ERROR;
	}

	// Get user's e-mail address information editing tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	if(read_token_from_buffer(buffer, 2, token_name, email_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "email_address") != 0)
		int_error("Extracting the email_address failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username
	sprintf(stat, "SELECT user_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, username);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The user does not exist
	if(!row)
	{
		// Send the user email address editing result flag
		write_token_into_buffer("user_email_address_editing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "User does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user email address editing result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	user_id = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Update the user's e-mail address
	sprintf(stat, "UPDATE %s SET email_address = '%s' WHERE user_id = %u", UA__USERS, email_address, user_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	disconnect_db(&db_conn);
	
	// Send the user email address editing result flag
	write_token_into_buffer("user_email_address_editing_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user email address editing result flag failed\n");
		goto ERROR;
	}

	// Record a transaction log
	sprintf(object_description, "E-mail address: %s", email_address);
	record_transaction_log_on_user(ssl_client, username, false, object_description, USER_EMAIL_ADDRESS_CHANGING_MSG);
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

static void prepare_sync_user_attribute_node_list(MYSQL *db_conn, unsigned int user_id)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	sync_user_attribute_node_t user_attribute_node;
	unsigned int               counter = 0;

	// Query for user attribute info
	sprintf(stat, "SELECT UAT.user_attribute_id, UAT.attribute_id, ATT.attribute_name, UAT.attribute_value FROM %s UAT, %s ATT "
		"WHERE UAT.user_id = %u AND UAT.attribute_id = ATT.attribute_id", UA__USER_ATTRIBUTES, UA__ATTRIBUTES, user_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		user_attribute_node.node_id           = counter++;
		user_attribute_node.user_attribute_id = atoi(row[0]);
		user_attribute_node.attribute_id      = atoi(row[1]);
		strcpy(user_attribute_node.attribute_name, row[2]);
		user_attribute_node.attribute_value   = atoi(row[3]);

		// Append the user attribute list
		if(list_append(&sync_user_attribute_node_list, &user_attribute_node) < 0)
			int_error("Appending the linked list failed");
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static boolean edit_user_attribute_list(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_id;
	char         email_address[EMAIL_ADDRESS_LENGTH + 1];

	char         random_passwd[PASSWD_LENGTH + 1];
	char         random_salt_value[SALT_VALUE_LENGTH + 1];
	char         random_passwd_with_salt_value[PASSWD_LENGTH + SALT_VALUE_LENGTH + 1];
	char         salted_passwd_hash[SHA1_DIGEST_LENGTH + 1];

	// Receive username information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving username information failed\n");
		goto ERROR;
	}

	// Get a username token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username
	sprintf(stat, "SELECT user_id, email_address FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, username);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The user does not exist
	if(!row)
	{
		// Send the user attribute list editing result flag
		write_token_into_buffer("user_attribute_list_editing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "User does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user attribute list editing result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	user_id = atoi(row[0]);
	strcpy(email_address, row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Generate a random 8 character password
	gen_random_password(random_passwd);

	// Generate a random 8 character salt value
	gen_random_salt_value(random_salt_value);

	// Get the salted password hash
	sprintf(random_passwd_with_salt_value, "%s%s", random_passwd, random_salt_value);
	sum_sha1_from_string(random_passwd_with_salt_value, strlen(random_passwd_with_salt_value), salted_passwd_hash, SALTED_PASSWD_HASH_PATH);

	// Update the password hash information
	sprintf(stat, "UPDATE %s SET salted_passwd_hash = '%s', salt_value = '%s' WHERE user_id = %u", UA__USERS, salted_passwd_hash, random_salt_value, user_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	generate_ssl_cert(db_conn, user_id, username, false, random_passwd, email_address, SSL_CERT_PRIV_KEY_PATH, SSL_CERT_REQ_PATH, ENC_SSL_CERT_PATH, 
		FULL_ENC_SSL_CERT_PATH, FULL_ENC_SSL_CERT_HASH_PATH);

	// Send the user attribute list editing result flag
	write_token_into_buffer("user_attribute_list_editing_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user attribute list editing result flag failed\n");
		goto ERROR;
	}

	// Load an attribute list of the desired user
	prepare_sync_user_attribute_node_list(db_conn, user_id);

	// Generate a CP-ABE private key for a user		
	if(!receive_user_attribute_list(ssl_client, db_conn, user_id, username, "user_attribute_editing_result_flag"))
	{
		// If receiving the user attribute list failed then delete the user
		remove_all_user_info(ssl_client, db_conn, user_id, username, false, NULL);   // Ignore any error
		goto ERROR;
	}

	generate_cpabe_priv_key(db_conn, user_id, username, random_passwd, CPABE_PRIV_KEY_PATH, ENC_CPABE_PRIV_KEY_PATH, ENC_CPABE_PRIV_KEY_HASH_PATH);
	disconnect_db(&db_conn);

	// Lock an e-mail sending
	if(sem_wait(&email_sending_lock_mutex) != 0)
		int_error("Locking the mutex failed");

	if(!send_passwd_to_user_email_address(email_address, username, false, random_passwd))
	{
		// Send the key and permission generating result flag
		write_token_into_buffer("key_and_permission_generating_result_flag", "0", true, buffer);
		write_token_into_file("error_msg", get_send_email_error_msg(), false, buffer);

		// Unlock an e-mail sending
		if(sem_post(&email_sending_lock_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the key and permission generating result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Unlock an e-mail sending
	if(sem_post(&email_sending_lock_mutex) != 0)
		int_error("Unlocking the mutex failed");

	// Send the key and permission generating result flag
	write_token_into_buffer("key_and_permission_generating_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the key and permission generating result flag failed\n");
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

static boolean edit_user_attribute_value(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];
	char         attribute_name[ATTRIBUTE_NAME_LENGTH + 1];
	char         attribute_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         attribute_value_str_tmp[ATTRIBUTE_VALUE_LENGTH + 1];
	unsigned int attribute_value;

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_id;
	unsigned int user_attribute_id;
	char         email_address[EMAIL_ADDRESS_LENGTH + 1];

	char         random_passwd[PASSWD_LENGTH + 1];
	char         random_salt_value[SALT_VALUE_LENGTH + 1];
	char         random_passwd_with_salt_value[PASSWD_LENGTH + SALT_VALUE_LENGTH + 1];
	char         salted_passwd_hash[SHA1_DIGEST_LENGTH + 1];

	char         object_description[DATA_DESCRIPTION_LENGTH + 1];

	// Receive attribute value editing information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving attribute value editing information failed\n");
		goto ERROR;
	}

	// Get attribute value editing information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	if(read_token_from_buffer(buffer, 2, token_name, attribute_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "attribute_name") != 0)
		int_error("Extracting the attribute_name failed");

	if(read_token_from_buffer(buffer, 3, token_name, attribute_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "attribute_authority_name") != 0)
		int_error("Extracting the attribute_authority_name failed");

	if(read_token_from_buffer(buffer, 4, token_name, attribute_value_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "attribute_value") != 0)
		int_error("Extracting the attribute_value failed");

	attribute_value = atoi(attribute_value_str_tmp);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username
	sprintf(stat, "SELECT user_id, email_address FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, username);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The user does not exist
	if(!row)
	{
		// Send the user attribute value editing result flag
		write_token_into_buffer("user_attribute_value_editing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "User does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user attribute value editing result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	user_id = atoi(row[0]);
	strcpy(email_address, row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Generate a random 8 character password
	gen_random_password(random_passwd);

	// Generate a random 8 character salt value
	gen_random_salt_value(random_salt_value);

	// Get the salted password hash
	sprintf(random_passwd_with_salt_value, "%s%s", random_passwd, random_salt_value);
	sum_sha1_from_string(random_passwd_with_salt_value, strlen(random_passwd_with_salt_value), salted_passwd_hash, SALTED_PASSWD_HASH_PATH);

	// Update the password hash information
	sprintf(stat, "UPDATE %s SET salted_passwd_hash = '%s', salt_value = '%s' WHERE user_id = %u", UA__USERS, salted_passwd_hash, random_salt_value, user_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	// Generate an SSL certificate
	generate_ssl_cert(db_conn, user_id, username, false, random_passwd, email_address, SSL_CERT_PRIV_KEY_PATH, SSL_CERT_REQ_PATH, ENC_SSL_CERT_PATH, 
		FULL_ENC_SSL_CERT_PATH, FULL_ENC_SSL_CERT_HASH_PATH);

	// Check for the existence of user attribute
	sprintf(stat, "SELECT UAT.user_attribute_id FROM %s UAT, %s ATT, %s AUT WHERE UAT.user_id = %u AND UAT.attribute_id = ATT.attribute_id AND "
		"ATT.attribute_name LIKE '%s' COLLATE latin1_general_cs AND ATT.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' "
		"COLLATE latin1_general_cs", UA__USER_ATTRIBUTES, UA__ATTRIBUTES, UA__AUTHORITIES, user_id, 
		attribute_name, attribute_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The user attribute does not exist
	if(!row)
	{
		// Delete the user
		if(!remove_all_user_info(ssl_client, db_conn, user_id, username, false, NULL))
			goto ERROR;

		// Send the user attribute value editing result flag
		write_token_into_buffer("user_attribute_value_editing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "User attribute does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user attribute value editing result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	user_attribute_id = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Update the attribute value
	update_user_attribute_value(db_conn, user_attribute_id, attribute_value);

	generate_cpabe_priv_key(db_conn, user_id, username, random_passwd, CPABE_PRIV_KEY_PATH, ENC_CPABE_PRIV_KEY_PATH, ENC_CPABE_PRIV_KEY_HASH_PATH);
	disconnect_db(&db_conn);

	// Lock an e-mail sending
	if(sem_wait(&email_sending_lock_mutex) != 0)
		int_error("Locking the mutex failed");

	if(!send_passwd_to_user_email_address(email_address, username, false, random_passwd))
	{
		// Send the user attribute value editing result flag
		write_token_into_buffer("user_attribute_value_editing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", get_send_email_error_msg(), false, buffer);

		// Unlock an e-mail sending
		if(sem_post(&email_sending_lock_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user attribute value editing result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Unlock an e-mail sending
	if(sem_post(&email_sending_lock_mutex) != 0)
		int_error("Unlocking the mutex failed");

	// Send the user attribute value editing result flag
	write_token_into_buffer("user_attribute_value_editing_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user attribute value editing result flag failed\n");
		goto ERROR;
	}

	// Record a transaction log
	sprintf(object_description, "Attribute: %s.%s = %u", GLOBAL_authority_name, attribute_name, attribute_value);
	record_transaction_log_on_user(ssl_client, username, false, object_description, USER_ATTRIBUTE_VALUE_CHANGING_MSG);
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

static boolean reset_user_passwd(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_id;
	char         email_address[EMAIL_ADDRESS_LENGTH + 1];

	char         random_passwd[PASSWD_LENGTH + 1];
	char         random_salt_value[SALT_VALUE_LENGTH + 1];
	char         random_passwd_with_salt_value[PASSWD_LENGTH + SALT_VALUE_LENGTH + 1];
	char         salted_passwd_hash[SHA1_DIGEST_LENGTH + 1];

	// Receive user password resetting information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving user password resetting information failed\n");
		goto ERROR;
	}

	// Get a user password resetting information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username
	sprintf(stat, "SELECT user_id, email_address FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, username);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The user does not exist
	if(!row)
	{
		// Send the user password resetting result flag
		write_token_into_buffer("user_passwd_resetting_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "User does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user password resetting result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	user_id = atoi(row[0]);
	strcpy(email_address, row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Generate a random 8 character password
	gen_random_password(random_passwd);

	// Generate a random 8 character salt value
	gen_random_salt_value(random_salt_value);

	// Get the salted password hash
	sprintf(random_passwd_with_salt_value, "%s%s", random_passwd, random_salt_value);
	sum_sha1_from_string(random_passwd_with_salt_value, strlen(random_passwd_with_salt_value), salted_passwd_hash, SALTED_PASSWD_HASH_PATH);

	// Update the password hash information
	sprintf(stat, "UPDATE %s SET salted_passwd_hash = '%s', salt_value = '%s' WHERE user_id = %u", UA__USERS, salted_passwd_hash, random_salt_value, user_id);
	if(mysql_query(db_conn, stat))
	{
	      	sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      	int_error(err_msg);
	}

	// Generate an SSL certificate
	generate_ssl_cert(db_conn, user_id, username, false, random_passwd, email_address, SSL_CERT_PRIV_KEY_PATH, SSL_CERT_REQ_PATH, ENC_SSL_CERT_PATH, 
		FULL_ENC_SSL_CERT_PATH, FULL_ENC_SSL_CERT_HASH_PATH);

	// Generate a CP-ABE private key
	generate_cpabe_priv_key(db_conn, user_id, username, random_passwd, CPABE_PRIV_KEY_PATH, ENC_CPABE_PRIV_KEY_PATH, ENC_CPABE_PRIV_KEY_HASH_PATH);
	disconnect_db(&db_conn);

	// Lock an e-mail sending
	if(sem_wait(&email_sending_lock_mutex) != 0)
		int_error("Locking the mutex failed");

	if(!send_passwd_to_user_email_address(email_address, username, false, random_passwd))
	{
		// Send the user password resetting result flag
		write_token_into_buffer("user_passwd_resetting_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", get_send_email_error_msg(), false, buffer);

		// Unlock an e-mail sending
		if(sem_post(&email_sending_lock_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user password resetting result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Unlock an e-mail sending
	if(sem_post(&email_sending_lock_mutex) != 0)
		int_error("Unlocking the mutex failed");

	// Send the user password resetting result flag
	write_token_into_buffer("user_passwd_resetting_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user password resetting result flag failed\n");
		goto ERROR;
	}

	// Record a transaction log
	record_transaction_log_on_user(ssl_client, username, false, NO_SPECIFIC_DATA, USER_PASSWD_RESETTING_MSG);
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

static boolean record_transaction_log_on_access_permission_granted_user_was_removed(SSL *ssl_client, char *revoked_username, char *phr_owner_name)
{
	SSL  *ssl_conn_AS = NULL;
	char buffer[BUFFER_LENGTH + 1];
	char actor_name[USER_NAME_LENGTH + 1];
	char current_date_time[DATETIME_STR_LENGTH  + 1];
	char client_ip_address[IP_ADDRESS_LENGTH + 1];

	// Get certificate owner's name, current date/time and client's IP address
	get_cert_ownername(ssl_client, GLOBAL_authority_name, actor_name, NULL);
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

	// Send a transaction log
	write_token_into_buffer("actor_name", actor_name, true, buffer);
	write_token_into_buffer("actor_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", "1", false, buffer);
	write_token_into_buffer("object_owner_name", revoked_username, false, buffer);
	write_token_into_buffer("object_owner_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("affected_username", phr_owner_name, false, buffer);
	write_token_into_buffer("affected_user_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_description", NO_SPECIFIC_DATA, false, buffer);
	write_token_into_buffer("event_description", ACCESS_PERMISSION_GRANTED_USER_WAS_REMOVED, false, buffer);
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

// "result_flag_msg" can be NULL if send_result_flag = false
boolean remove_all_user_info(SSL *ssl_client, MYSQL *db_conn, unsigned int user_id, char *username, boolean send_result_flag, char *result_flag_msg)
{
	if(send_result_flag && result_flag_msg == NULL)
		int_error("result_flag_msg is NULL");

	char      buffer[BUFFER_LENGTH + 1];

	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Delete user info
	sprintf(stat, "DELETE FROM %s WHERE user_id = %u", UA__USERS, user_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      	int_error(err_msg);
	}

	// Delete all user's attributes
	sprintf(stat, "DELETE FROM %s WHERE user_id = %u", UA__USER_ATTRIBUTES, user_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}

	// Query for PHR owners that have the same authority with current authority
	sprintf(stat, "SELECT phr_owner_id FROM %s WHERE user_id = %u AND phr_owner_authority_id = %u AND "
		"phr_owner_id != %u", UA__ACCESS_PERMISSIONS, user_id, GLOBAL_authority_id, user_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		unsigned int phr_owner_id;
		char         phr_owner_name[USER_NAME_LENGTH + 1];

		MYSQL_RES    *phr_owner_result = NULL;
  		MYSQL_ROW    phr_owner_row;

		phr_owner_id = atoi(row[0]);

		// Query for the PHR owner name	
		sprintf(stat, "SELECT username FROM %s WHERE user_id = %u", UA__USERS, phr_owner_id);
		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

		phr_owner_result = mysql_store_result(db_conn);
		phr_owner_row    = mysql_fetch_row(phr_owner_result);

		if(!phr_owner_row)
		{
			if(phr_owner_result)
			{
				mysql_free_result(phr_owner_result);
				phr_owner_result = NULL;
			}

			continue;
		}
		
		strcpy(phr_owner_name, phr_owner_row[0]);

		if(phr_owner_result)
		{
			mysql_free_result(phr_owner_result);
			phr_owner_result = NULL;
		}

		// Delete assigned access permissions of the PHR owner
		sprintf(stat, "DELETE FROM %s WHERE user_id = %u AND object_user_id = %u AND object_user_authority_id = %u", 
			UA__PERMISSIONS_ASSIGNED_TO_OTHERS, phr_owner_id, user_id, GLOBAL_authority_id);

		if(mysql_query(db_conn, stat))
		{
			sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		      	int_error(err_msg);
		}

		// Record a transaction log
		record_transaction_log_on_access_permission_granted_user_was_removed(ssl_client, username, phr_owner_name);
	}
	
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Delete all user's access permissions related with the removed user
	sprintf(stat, "DELETE FROM %s WHERE user_id = %u", UA__ACCESS_PERMISSIONS, user_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      	int_error(err_msg);
	}


	// Query for object users that have the same authority with current authority
	sprintf(stat, "SELECT object_user_id FROM %s WHERE user_id = %u AND object_user_authority_id = %u", 
		UA__PERMISSIONS_ASSIGNED_TO_OTHERS, user_id, GLOBAL_authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		unsigned int object_user_id = atoi(row[0]);

		// Delete access permissions for the object user
		sprintf(stat, "DELETE FROM %s WHERE user_id = %u AND phr_owner_id = %u", UA__ACCESS_PERMISSIONS, object_user_id, user_id);

		if(mysql_query(db_conn, stat))
		{
			sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		      	int_error(err_msg);
		}
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Delete all assigned access permissions
	sprintf(stat, "DELETE FROM %s WHERE user_id = %u", UA__PERMISSIONS_ASSIGNED_TO_OTHERS, user_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      	int_error(err_msg);
	}

	if(send_result_flag)
	{
		// Send the user/user attribute removal result flag
		write_token_into_buffer(result_flag_msg, "1", true, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user/user attribute removal result flag failed\n");
			goto ERROR;
		}
	}

	// Record a transaction log
	record_transaction_log_on_user(ssl_client, username, false, NO_SPECIFIC_DATA, USER_REMOVAL_MSG);
	return true;

ERROR:
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return false;
}

static boolean remove_user(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_id;

	// Receive user removal information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving user removal information failed\n");
		goto ERROR;
	}

	// Get a user removal information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username
	sprintf(stat, "SELECT user_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, username);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The user does not exist
	if(!row)
	{
		// Send the user removal result flag
		write_token_into_buffer("user_removal_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "User does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user removal result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	user_id = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(!remove_all_user_info(ssl_client, db_conn, user_id, username, true, "user_removal_result_flag"))
		goto ERROR;

	disconnect_db(&db_conn);
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

static boolean remove_user_attribute(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];
	char         attribute_name[ATTRIBUTE_NAME_LENGTH + 1];
	char         attribute_authority_name[AUTHORITY_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	char         email_address[EMAIL_ADDRESS_LENGTH + 1];
	unsigned int user_id;
	unsigned int user_attribute_id;

	char         object_description[DATA_DESCRIPTION_LENGTH + 1];
	boolean      has_user_attribute_left;

	// Receive user attribute removal information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving user attribute removal information failed\n");
		goto ERROR;
	}

	// Get user attribute removal information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	if(read_token_from_buffer(buffer, 2, token_name, attribute_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "attribute_name") != 0)
		int_error("Extracting the attribute_name failed");

	if(read_token_from_buffer(buffer, 3, token_name, attribute_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "attribute_authority_name") != 0)
		int_error("Extracting the attribute_authority_name failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username
	sprintf(stat, "SELECT user_id, email_address FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, username);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The user does not exist
	if(!row)
	{
		// Send the user attribute removal result flag
		write_token_into_buffer("user_attribute_removal_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "User does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user attribute removal result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	user_id = atoi(row[0]);
	strcpy(email_address, row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Check for the existence of user attribute
	sprintf(stat, "SELECT UAT.user_attribute_id FROM %s UAT, %s ATT, %s AUT WHERE UAT.user_id = %u AND UAT.attribute_id = ATT.attribute_id AND "
		"ATT.attribute_name LIKE '%s' COLLATE latin1_general_cs AND ATT.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' "
		"COLLATE latin1_general_cs", UA__USER_ATTRIBUTES, UA__ATTRIBUTES, UA__AUTHORITIES, user_id, attribute_name, attribute_authority_name);

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
		// Send the user attribute removal result flag
		write_token_into_buffer("user_attribute_removal_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "User attribute does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the user attribute removal result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	user_attribute_id = atoi(row[0]);

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
	sprintf(object_description, "Attribute: %s.%s", GLOBAL_authority_name, attribute_name);
	record_transaction_log_on_user(ssl_client, username, false, object_description, USER_ATTRIBUTE_REMOVAL_MSG);

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
		sum_sha1_from_string(random_passwd_with_salt_value, strlen(random_passwd_with_salt_value), salted_passwd_hash, SALTED_PASSWD_HASH_PATH);

		// Update the password hash information
		sprintf(stat, "UPDATE %s SET salted_passwd_hash = '%s', salt_value = '%s' WHERE user_id = %u", UA__USERS, salted_passwd_hash, random_salt_value, user_id);
		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

		// Generate an SSL certificate
		generate_ssl_cert(db_conn, user_id, username, false, random_passwd, email_address, SSL_CERT_PRIV_KEY_PATH, SSL_CERT_REQ_PATH, ENC_SSL_CERT_PATH, 
			FULL_ENC_SSL_CERT_PATH, FULL_ENC_SSL_CERT_HASH_PATH);

		// Generate a CP-ABE private key
		generate_cpabe_priv_key(db_conn, user_id, username, random_passwd, CPABE_PRIV_KEY_PATH, ENC_CPABE_PRIV_KEY_PATH, ENC_CPABE_PRIV_KEY_HASH_PATH);

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

	// Send the user attribute removal result flag
	write_token_into_buffer("user_attribute_removal_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the user attribute removal result flag failed\n");
		goto ERROR;
	}

	disconnect_db(&db_conn);
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

static boolean register_admin(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];
	char         email_address[EMAIL_ADDRESS_LENGTH + 1];

	char         random_passwd[PASSWD_LENGTH + 1];
	char         random_salt_value[SALT_VALUE_LENGTH + 1];
	char         random_passwd_with_salt_value[PASSWD_LENGTH + SALT_VALUE_LENGTH + 1];
	char         salted_passwd_hash[SHA1_DIGEST_LENGTH + 1];

	unsigned int admin_id;

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];
	
	// Receive admin information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving admin information failed\n");
		goto ERROR;
	}

	// Get admin information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	if(read_token_from_buffer(buffer, 2, token_name, email_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "email_address") != 0)
		int_error("Extracting the email_address failed");

	// Check for reserved username
	if(is_reserved_username(username))
	{
		// Send the admin registration result flag
		write_token_into_buffer("admin_registration_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "This username is reserved already", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the admin registration result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username. If the username does not exist then add it into database
	sprintf(stat, "SELECT admin_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__ADMINS, username);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The username exists
	if(row)
	{
		// Send the admin registration result flag
		write_token_into_buffer("admin_registration_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Username exists already", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the admin registration result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Generate a random 8 character password
	gen_random_password(random_passwd);

	// Generate a random 8 character salt value
	gen_random_salt_value(random_salt_value);

	// Get the salted password hash
	sprintf(random_passwd_with_salt_value, "%s%s", random_passwd, random_salt_value);
	sum_sha1_from_string(random_passwd_with_salt_value, strlen(random_passwd_with_salt_value), salted_passwd_hash, SALTED_PASSWD_HASH_PATH);

	// Insert a new user if he/she does not exist
	sprintf(stat, "INSERT INTO %s(username, salted_passwd_hash, salt_value, email_address, passwd_resetting_code, enc_ssl_cert, enc_ssl_cert_hash) "
		"VALUES('%s', '%s', '%s', '%s', '', NULL, NULL)", UA__ADMINS, username, salted_passwd_hash, random_salt_value, email_address);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
	
	// Get an admin's id
	sprintf(stat, "SELECT admin_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__ADMINS, username);

	if(mysql_query(db_conn, stat))
 	{
	      	sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      	int_error(err_msg);
	}

	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	if(!row)
		int_error("Getting an admin id from database failed");

	admin_id = atoi(row[0]);
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
	
	// Generate an SSL certificate
	generate_ssl_cert(db_conn, admin_id, username, true, random_passwd, email_address, SSL_CERT_PRIV_KEY_PATH, SSL_CERT_REQ_PATH, ENC_SSL_CERT_PATH, 
		FULL_ENC_SSL_CERT_PATH, FULL_ENC_SSL_CERT_HASH_PATH);

	disconnect_db(&db_conn);

	// Lock an e-mail sending
	if(sem_wait(&email_sending_lock_mutex) != 0)
		int_error("Locking the mutex failed");

	if(!send_passwd_to_user_email_address(email_address, username, true, random_passwd))
	{
		// Send the admin registration result flag
		write_token_into_buffer("admin_registration_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", get_send_email_error_msg(), false, buffer);

		// Unlock an e-mail sending
		if(sem_post(&email_sending_lock_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the admin registration result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Unlock an e-mail sending
	if(sem_post(&email_sending_lock_mutex) != 0)
		int_error("Unlocking the mutex failed");
	
	// Send the admin registration result flag
	write_token_into_buffer("admin_registration_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the admin registration result flag failed\n");
		goto ERROR;
	}	

	// Record a transaction log
	record_transaction_log_on_user(ssl_client, username, true, NO_SPECIFIC_DATA, ADMIN_REGISTRATION_MSG);
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

static boolean edit_admin_email_address(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];
	char         email_address[EMAIL_ADDRESS_LENGTH + 1];

	unsigned int admin_id;
	char         object_description[DATA_DESCRIPTION_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];
	
	// Receive admin's e-mail address editing information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving admin's e-mail address editing information failed\n");
		goto ERROR;
	}

	// Get admin's e-mail address editing information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	if(read_token_from_buffer(buffer, 2, token_name, email_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "email_address") != 0)
		int_error("Extracting the email_address failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username
	sprintf(stat, "SELECT admin_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__ADMINS, username);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The username exists
	if(!row)
	{
		// Send the admin email address editing result flag
		write_token_into_buffer("admin_email_address_editing_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Admin does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the admin email address editing result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	admin_id = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Update the admin's e-mail address
	sprintf(stat, "UPDATE %s SET email_address = '%s' WHERE admin_id = %u", UA__ADMINS, email_address, admin_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	disconnect_db(&db_conn);

	// Send the admin email address editing result flag
	write_token_into_buffer("admin_email_address_editing_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the admin email address editing result flag failed\n");
		goto ERROR;
	}

	// Record a transaction log
	sprintf(object_description, "E-mail address: %s", email_address);
	record_transaction_log_on_user(ssl_client, username, false, object_description, ADMIN_EMAIL_ADDRESS_CHANGING_MSG);
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

static boolean reset_admin_passwd(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int admin_id;
	char         email_address[EMAIL_ADDRESS_LENGTH + 1];

	char         random_passwd[PASSWD_LENGTH + 1];
	char         random_salt_value[SALT_VALUE_LENGTH + 1];
	char         random_passwd_with_salt_value[PASSWD_LENGTH + SALT_VALUE_LENGTH + 1];
	char         salted_passwd_hash[SHA1_DIGEST_LENGTH + 1];

	// Receive admin password resetting information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving admin password resetting information failed\n");
		goto ERROR;
	}

	// Get an admin password resetting information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username
	sprintf(stat, "SELECT admin_id, email_address FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__ADMINS, username);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The admin does not exist
	if(!row)
	{
		// Send the admin password resetting result flag
		write_token_into_buffer("admin_passwd_resetting_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Admin does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the admin password resetting result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	admin_id = atoi(row[0]);
	strcpy(email_address, row[1]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Generate a random 8 character password
	gen_random_password(random_passwd);

	// Generate a random 8 character salt value
	gen_random_salt_value(random_salt_value);

	// Get the salted password hash
	sprintf(random_passwd_with_salt_value, "%s%s", random_passwd, random_salt_value);
	sum_sha1_from_string(random_passwd_with_salt_value, strlen(random_passwd_with_salt_value), salted_passwd_hash, SALTED_PASSWD_HASH_PATH);

	// Update the password hash information
	sprintf(stat, "UPDATE %s SET salted_passwd_hash = '%s', salt_value = '%s' WHERE admin_id = %u", UA__ADMINS, salted_passwd_hash, random_salt_value, admin_id);
	if(mysql_query(db_conn, stat))
	{
	      	sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      	int_error(err_msg);
	}

	// Generate an SSL certificate
	generate_ssl_cert(db_conn, admin_id, username, true, random_passwd, email_address, SSL_CERT_PRIV_KEY_PATH, SSL_CERT_REQ_PATH, ENC_SSL_CERT_PATH, 
		FULL_ENC_SSL_CERT_PATH, FULL_ENC_SSL_CERT_HASH_PATH);

	disconnect_db(&db_conn);

	// Lock an e-mail sending
	if(sem_wait(&email_sending_lock_mutex) != 0)
		int_error("Locking the mutex failed");

	if(!send_passwd_to_user_email_address(email_address, username, true, random_passwd))
	{
		// Send the admin password resetting result flag
		write_token_into_buffer("admin_passwd_resetting_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", get_send_email_error_msg(), false, buffer);

		// Unlock an e-mail sending
		if(sem_post(&email_sending_lock_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the admin password resetting result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Unlock an e-mail sending
	if(sem_post(&email_sending_lock_mutex) != 0)
		int_error("Unlocking the mutex failed");

	// Send the admin password resetting result flag
	write_token_into_buffer("admin_passwd_resetting_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the admin password resetting result flag failed\n");
		goto ERROR;
	}

	// Record a transaction log
	record_transaction_log_on_user(ssl_client, username, true, NO_SPECIFIC_DATA, ADMIN_PASSWD_RESETTING_MSG);
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

static boolean remove_admin(SSL *ssl_client)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         username[USER_NAME_LENGTH + 1];

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int admin_id;

	// Receive admin removal information
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving admin removal information failed\n");
		goto ERROR;
	}

	// Get an admin removal information token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		int_error("Extracting the username failed");

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Check for the existence of username
	sprintf(stat, "SELECT admin_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__ADMINS, username);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	// The admin does not exist
	if(!row)
	{
		// Send the admin removal result flag
		write_token_into_buffer("admin_removal_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Admin does not exist", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the admin removal result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	admin_id = atoi(row[0]);

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	// Delete the admin
	sprintf(stat, "DELETE FROM %s WHERE admin_id = %u", UA__ADMINS, admin_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}

	disconnect_db(&db_conn);

	// Send the admin removal result flag
	write_token_into_buffer("admin_removal_result_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the admin removal result flag failed\n");
		goto ERROR;
	}

	// Record a transaction log
	record_transaction_log_on_user(ssl_client, username, true, NO_SPECIFIC_DATA,  ADMIN_REMOVAL_MSG);
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

	if(strcmp(request, USER_REGISTRATION) == 0)
	{
		return register_user(ssl_client);
	}
	else if(strcmp(request, USER_EMAIL_ADDRESS_AND_ATTRIBUTE_LIST_EDITING) == 0)
	{
		if(!edit_user_email_address(ssl_client))
			return false;

		return edit_user_attribute_list(ssl_client);
	}
	else if(strcmp(request, USER_EMAIL_ADDRESS_EDITING) == 0)
	{
		return edit_user_email_address(ssl_client);
	}
	else if(strcmp(request, USER_ATTRIBUTE_LIST_EDITING) == 0)
	{
		return edit_user_attribute_list(ssl_client);
	}
	else if(strcmp(request, USER_ATTRIBUTE_VALUE_EDITING) == 0)
	{
		return edit_user_attribute_value(ssl_client);
	}
	else if(strcmp(request, USER_PASSWD_RESETTING) == 0)
	{
		return reset_user_passwd(ssl_client);
	}
	else if(strcmp(request, USER_REMOVAL) == 0)
	{
		return remove_user(ssl_client);
	}
	else if(strcmp(request, USER_ATTRIBUTE_REMOVAL) == 0)
	{
		return remove_user_attribute(ssl_client);
	}
	else if(strcmp(request, ADMIN_REGISTRATION) == 0)
	{
		return register_admin(ssl_client);
	}
	else if(strcmp(request, ADMIN_EMAIL_ADDRESS_EDITING) == 0)
	{
		return edit_admin_email_address(ssl_client);
	}
	else if(strcmp(request, ADMIN_PASSWD_RESETTING) == 0)
	{
		return reset_admin_passwd(ssl_client);
	}
	else if(strcmp(request, ADMIN_REMOVAL) == 0)
	{
		return remove_admin(ssl_client);
	}
	else
	{
		fprintf(stderr, "Invalid request type\n");
		goto ERROR;
	}

ERROR:

	return false;
}

static size_t list_meter_sync_user_attribute_node_t(const void *element)
{
	return sizeof(sync_user_attribute_node_t);
}

static int list_seeker_by_user_attribute_id(const void *element, const void *key)
{
	const sync_user_attribute_node_t *node = (sync_user_attribute_node_t *)element;

	if(node->attribute_id == *(unsigned int *)key)
		return 1;
	else
		return 0;
}

static int list_comparator_by_user_attribute_node_id(const void *nodeA, const void *nodeB)
{
	if(((sync_user_attribute_node_t *)nodeA)->node_id > ((sync_user_attribute_node_t *)nodeB)->node_id)
	{
		return -1;
	}
	else if(((sync_user_attribute_node_t *)nodeA)->node_id == ((sync_user_attribute_node_t *)nodeB)->node_id)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

static void init_user_attribute_synchronization_list()
{
	// Initialize a linked list
	if(list_init(&sync_user_attribute_node_list) < 0)
		int_error("Initial a linked list failed");

	// Request to store copies and provide the metric function
    	if(list_attributes_copy(&sync_user_attribute_node_list, list_meter_sync_user_attribute_node_t, 1) < 0)
		int_error("Initial a metric function failed");

	// Set the custom seeker function
	if(list_attributes_seeker(&sync_user_attribute_node_list, list_seeker_by_user_attribute_id) < 0)
		int_error("Initial a custom seeker function failed");

	// Set the custom comparator function
	if(list_attributes_comparator(&sync_user_attribute_node_list, list_comparator_by_user_attribute_node_id) < 0)
		int_error("Initial a custom comparator function failed");
}

static void uninit_user_attribute_synchronization_list()
{
	// Destroy a linked list
	list_destroy(&sync_user_attribute_node_list);
}

void *user_management_main(void *arg)
{
    	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *hosts[1];

	init_user_attribute_synchronization_list();

    	ctx = setup_server_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(UA_USER_MANAGEMENT_PORT);
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

	uninit_user_attribute_synchronization_list();

	pthread_exit(NULL);
    	return NULL;
}




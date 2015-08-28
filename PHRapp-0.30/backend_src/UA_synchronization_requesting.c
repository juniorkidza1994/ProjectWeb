#include "UA_common.h"
#include "simclist.h"

struct sync_attribute_node
{
	unsigned int node_id;
	unsigned int attribute_id;
	char         attribute_name[ATTRIBUTE_NAME_LENGTH + 1];
};

typedef struct sync_attribute_node sync_attribute_node_t;

struct sync_user_node
{
	unsigned int node_id;
	unsigned int user_id;
	char         username[USER_NAME_LENGTH + 1];
};

typedef struct sync_user_node sync_user_node_t;

struct sync_access_permission_node
{
	unsigned int node_id;
	unsigned int access_permission_id;
	char         username[USER_NAME_LENGTH + 1];
	char         phr_ownername[USER_NAME_LENGTH + 1];
	boolean      upload_permission_flag;
	boolean      download_permission_flag;
	boolean      delete_permission_flag;
};

typedef struct sync_access_permission_node sync_access_permission_node_t;

struct access_permission_key
{
	char username[USER_NAME_LENGTH + 1];
	char phr_ownername[USER_NAME_LENGTH + 1];
};

typedef struct access_permission_key access_permission_key_t;

// Local Variables
static list_t sync_attribute_node_list;
static list_t sync_user_node_list;
static list_t sync_access_permission_node_list;

// Local Function Prototypes
static boolean connect_to_synchronization_service(char *authority_name, char *user_auth_ip_addr, SSL **ssl_conn_ret);
static boolean record_transaction_log_on_syncing_authority_was_removed(SSL *ssl_peer, char *authority_name);
static void remove_authority(SSL *ssl_peer, unsigned int authority_id, char *authority_name);
static boolean request_authority_joining(SSL *ssl_conn, char *request_result_ret);
static boolean request_authority_synchronization(SSL *ssl_conn, char *request_result_ret);
static void set_authority_join_flag(MYSQL *db_conn, unsigned int authority_id);
static boolean synchronize_authority_info(MYSQL *db_conn, SSL *ssl_conn, unsigned int authority_id);
static void prepare_sync_attribute_node_list(MYSQL *db_conn, unsigned int authority_id);
static void insert_new_attribute(MYSQL *db_conn, char *attribute_name, boolean is_numerical_attribute_flag, unsigned int authority_id);
static void remove_revoked_attribute(MYSQL *db_conn, unsigned int attribute_id);
static boolean synchronize_attribute(MYSQL *db_conn, SSL *ssl_conn, unsigned int authority_id);
static void prepare_sync_user_node_list(MYSQL *db_conn, unsigned int authority_id);
static void update_user_info(MYSQL *db_conn, unsigned int user_id, char *email_address, char *ssl_pub_key);
static void insert_new_user(MYSQL *db_conn, char *username, unsigned int authority_id, char *email_address, char *ssl_pub_key);
static void remove_access_permission_assigned_by_revoked_phr_owner(MYSQL *db_conn, unsigned int phr_owner_id, unsigned int phr_owner_authority_id);

static boolean record_transaction_log_on_access_permission_granted_user_was_removed_by_syncing_authority(SSL *ssl_conn, char *revoked_username, 
	char *revoked_user_authority_name, char *phr_owner_name);

static void remove_access_permission_assigned_to_revoked_object_user(SSL *ssl_conn, MYSQL *db_conn, unsigned int object_user_id, char *object_owner_name, 
	unsigned int object_user_authority_id, char *object_user_authorirty_name);

static void remove_revoked_user(MYSQL *db_conn, SSL *ssl_conn, unsigned int user_id, char *username, unsigned int authority_id, char *authority_name);
static boolean synchronize_user(MYSQL *db_conn, SSL *ssl_conn, unsigned int authority_id, char *authority_name);
static boolean get_username(MYSQL *db_conn, unsigned int user_id, char *username_ret);
static boolean get_phr_ownername(MYSQL *db_conn, unsigned int phr_owner_id, unsigned int phr_owner_authority_id, char *phr_ownername_ret);
static void prepare_sync_access_permission_node_list(MYSQL *db_conn, unsigned int authority_id);
static void update_access_permission(MYSQL *db_conn, unsigned int access_permission_id, boolean upload_permission_flag, 
	boolean download_permission_flag, boolean delete_permission_flag);

static boolean get_user_id(MYSQL *db_conn, char *username, unsigned int *user_id_ret);
static boolean get_phr_owner_id(MYSQL *db_conn, char *phr_ownername, unsigned int phr_owner_authority_id, unsigned int *phr_owner_id_ret);
static boolean insert_new_access_permission(MYSQL *db_conn, char *username, char *phr_ownername, unsigned int phr_owner_authority_id, boolean upload_permission_flag, 
	boolean download_permission_flag, boolean delete_permission_flag);

static void remove_revoked_access_permission(MYSQL *db_conn, unsigned int access_permission_id);
static boolean synchronize_access_permission(MYSQL *db_conn, SSL *ssl_conn, unsigned int authority_id);
static boolean connect_to_emergency_delegation_synchronization_service(SSL **ssl_conn_ret);
static boolean synchronize_emergency_delegation(SSL *ssl_incoming_conn, char *peer_authority_name);
static boolean synchronize_phr_transaction_log(SSL *ssl_incoming_conn);
static boolean authority_synchronization_main(SSL *ssl_conn, unsigned int authority_id, char *authority_name);
static void process();
static size_t list_meter_sync_attribute_node_t(const void *element);
static int list_seeker_by_attribute_name(const void *element, const void *key);
static int list_comparator_by_attribute_node_id(const void *nodeA, const void *nodeB);
static void init_attribute_synchronization_list();
static size_t list_meter_sync_user_node_t(const void *element);
static int list_seeker_by_username(const void *element, const void *key);
static int list_comparator_by_user_node_id(const void *nodeA, const void *nodeB);
static void init_user_synchronization_list();
static size_t list_meter_sync_access_permission_node_t(const void *element);
static int list_seeker_by_access_permission_info(const void *element, const void *key);
static int list_comparator_by_access_permission_node_id(const void *nodeA, const void *nodeB);
static void init_access_permission_synchronization_list();
static void init_synchronization_module();
static void uninit_synchronization_module();

// Implementation
static boolean connect_to_synchronization_service(char *authority_name, char *user_auth_ip_addr, SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    user_auth_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to User Authority of another authority
	sprintf(user_auth_addr, "%s:%s", user_auth_ip_addr, UA_SYNCHRONIZATION_RESPONDING_PORT/*"7016"*/);  //****
	bio_conn = BIO_new_connect(user_auth_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		fprintf(stderr, "Connecting to %s's user authority failed\n", authority_name);
		goto ERROR_AT_BIO_LAYER;
	}

	ctx = setup_client_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
	if(!(*ssl_conn_ret = SSL_new(ctx)))
            	int_error("Creating SSL context failed");
 
    	SSL_set_bio(*ssl_conn_ret, bio_conn, bio_conn);
    	if(SSL_connect(*ssl_conn_ret) <= 0)
	{
        	fprintf(stderr, "Connecting SSL object failed\n");
		goto ERROR_AT_SSL_LAYER;
	}

	hosts[0] = USER_AUTH_CN;
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, true, authority_name)) != X509_V_OK)
   	{
		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
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

static boolean record_transaction_log_on_syncing_authority_was_removed(SSL *ssl_peer, char *authority_name)
{
	SSL  *ssl_conn_AS = NULL;
	char buffer[BUFFER_LENGTH + 1];
	char object_description[DATA_DESCRIPTION_LENGTH + 1];
	char current_date_time[DATETIME_STR_LENGTH  + 1];
	char peer_ip_address[IP_ADDRESS_LENGTH + 1];

	// Get current date/time and peer's IP address
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_peer, peer_ip_address, NULL);

	sprintf(object_description, "Authority: %s", authority_name);

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
	write_token_into_buffer("actor_name", ITS_ADMIN_NAME, true, buffer);
	write_token_into_buffer("actor_authority_name", authority_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", "1", false, buffer);
	write_token_into_buffer("object_owner_name", NO_REFERENCE_USERNAME, false, buffer);
	write_token_into_buffer("object_owner_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("affected_username", REFERENCE_TO_ALL_ADMIN_NAMES, false, buffer);
	write_token_into_buffer("affected_user_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_affected_user_is_admin_flag", "1", false, buffer);
	write_token_into_buffer("object_description", object_description, false, buffer);
	write_token_into_buffer("event_description", AUTHORITY_REMOVAL_MSG, false, buffer);
	write_token_into_buffer("date_time", current_date_time, false, buffer);
	write_token_into_buffer("actor_ip_address", peer_ip_address, false, buffer);

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

// This function is executed when the synchronization mechanism detects that the joining authority permission is revoked by its administrator
// Do not need to lock the synchronization because the function that calls this code will lock the synchronization already
static void remove_authority(SSL *ssl_peer, unsigned int authority_id, char *authority_name)
{
	MYSQL *db_conn = NULL;
	char  stat[SQL_STATEMENT_LENGTH + 1];
	char  err_msg[ERR_MSG_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	remove_attribute_list_of_authority(db_conn, authority_id);

	// Delete both the user list and the access permissions regarding to revoked authority
	remove_user_list_of_authority(ssl_peer, db_conn, authority_id, authority_name, true);

	// Delete the authority
	sprintf(stat, "DELETE FROM %s WHERE authority_id = %u", UA__AUTHORITIES, authority_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}

	disconnect_db(&db_conn);

	// Record a transaction log
	record_transaction_log_on_syncing_authority_was_removed(ssl_peer, authority_name);
}

static boolean request_authority_joining(SSL *ssl_conn, char *request_result_ret)
{
	char buffer[BUFFER_LENGTH + 1];
	char token_name[TOKEN_NAME_LENGTH + 1];

	// Send the joining requesting message
	write_token_into_buffer("request", AUTHORITY_JOINING_REQUESTING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the joining requesting message failed\n");
		return false;
	}

	// Receive the request result
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the request result failed\n");
		return false;
	}

	if(read_token_from_buffer(buffer, 1, token_name, request_result_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "request_result") != 0)
	{
		int_error("Extracting the request_result failed");
	}

	return true;
}

static boolean request_authority_synchronization(SSL *ssl_conn, char *request_result_ret)
{
	char buffer[BUFFER_LENGTH + 1];
	char token_name[TOKEN_NAME_LENGTH + 1];

	// Send the authority synchronization requesting message
	write_token_into_buffer("request", AUTHORITY_SYNCHRONIZATION_REQUESTING, true, buffer);

	if(!SSL_send_buffer(ssl_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the authority synchronization requesting message failed\n");
		return false;
	}

	// Receive the request result
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the request result failed\n");
		return false;
	}

	if(read_token_from_buffer(buffer, 1, token_name, request_result_ret) != READ_TOKEN_SUCCESS || strcmp(token_name, "request_result") != 0)
	{
		int_error("Extracting the request_result failed");
	}

	return true;
}

static void set_authority_join_flag(MYSQL *db_conn, unsigned int authority_id)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Set the authority join flag
	sprintf(stat, "UPDATE %s SET authority_join_flag = '1' WHERE authority_id = %u", UA__AUTHORITIES, authority_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
}

static boolean synchronize_authority_info(MYSQL *db_conn, SSL *ssl_conn, unsigned int authority_id)
{
	char  buffer[BUFFER_LENGTH + 1];
	char  token_name[TOKEN_NAME_LENGTH + 1];
	char  emergency_server_ip_addr[IP_ADDRESS_LENGTH + 1];

	char  stat[SQL_STATEMENT_LENGTH + 1];
	char  err_msg[ERR_MSG_LENGTH + 1];

	// Receive authority infomation
	if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving authority information failed\n");
		return false;
	}

	if(read_token_from_buffer(buffer, 1, token_name, emergency_server_ip_addr) != READ_TOKEN_SUCCESS || strcmp(token_name, "emergency_server_ip_addr") != 0)
	{
		int_error("Extracting the emergency_server_ip_addr failed");
	}

	// Update the emergency server's ip address
	sprintf(stat, "UPDATE %s SET emergency_server_ip_addr='%s' WHERE authority_id=%u", UA__AUTHORITIES, emergency_server_ip_addr, authority_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	return true;
}

static void prepare_sync_attribute_node_list(MYSQL *db_conn, unsigned int authority_id)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	sync_attribute_node_t attribute_node;
	unsigned int          counter = 0;

	// Query for attribute info
	sprintf(stat, "SELECT attribute_id, attribute_name FROM %s WHERE authority_id = %u", UA__ATTRIBUTES, authority_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		attribute_node.node_id      = counter++;
		attribute_node.attribute_id = atoi(row[0]);
		strcpy(attribute_node.attribute_name, row[1]);

		// Append the attribute list
		if(list_append(&sync_attribute_node_list, &attribute_node) < 0)
			int_error("Appending the linked list failed");
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static void insert_new_attribute(MYSQL *db_conn, char *attribute_name, boolean is_numerical_attribute_flag, unsigned int authority_id)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Insert a new attribute
	sprintf(stat, "INSERT INTO %s(attribute_name, is_numerical_attribute_flag, authority_id) VALUES('%s', '%s', %u)", 
		UA__ATTRIBUTES, attribute_name, (is_numerical_attribute_flag) ? "1" : "0", authority_id);
	
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
}

static void remove_revoked_attribute(MYSQL *db_conn, unsigned int attribute_id)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Delete a revoked attribute
	sprintf(stat, "DELETE FROM %s WHERE attribute_id = %u", UA__ATTRIBUTES, attribute_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
}

static boolean synchronize_attribute(MYSQL *db_conn, SSL *ssl_conn, unsigned int authority_id)
{
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    is_end_of_attribute_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_attribute_list_flag;
	char    attribute_name[ATTRIBUTE_NAME_LENGTH + 1];
	char    is_numerical_attribute_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_numerical_attribute_flag;

	sync_attribute_node_t *ptr_attribute_node = NULL;

	// Load an attribute list of the desired authority
	prepare_sync_attribute_node_list(db_conn, authority_id);

	while(1)
	{
		// Receive attribute infomation
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving attribute information failed\n");
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

		// Get an attribute node that corresponds to "attribute_name" if exists in a linked list
		ptr_attribute_node = (sync_attribute_node_t *)list_seek(&sync_attribute_node_list, attribute_name);

		// If an attribute node exists then remove from the list, unless insert that attribute into a database
		if(ptr_attribute_node)
		{
printf("[synced att] = %s\n", attribute_name);
			// Remove an attribute node from the list
			if(list_delete_at(&sync_attribute_node_list, list_locate(&sync_attribute_node_list, ptr_attribute_node)) < 0)
				int_error("Removing an attribute node failed");
		}
		else
		{
printf("[new att] = %s\n", attribute_name);
			// Insert an attribute into a database
			insert_new_attribute(db_conn, attribute_name, is_numerical_attribute_flag, authority_id);
		}		
	}

	if(!list_iterator_start(&sync_attribute_node_list))
		int_error("Starting list iteration failed");

	// The remaining attribute nodes in the list are the revoked attributes
	while(list_iterator_hasnext(&sync_attribute_node_list))
	{
		ptr_attribute_node = (sync_attribute_node_t *)list_iterator_next(&sync_attribute_node_list);
printf("[revoke att] = %s\n", ptr_attribute_node->attribute_name);

		// Remove a revoked attribute from a database
		remove_revoked_attribute(db_conn, ptr_attribute_node->attribute_id);
	}

	if(!list_iterator_stop(&sync_attribute_node_list))
		int_error("Stopping list iteration failed");

	// Remove all nodes from the list
	list_clear(&sync_attribute_node_list);
	return true;

ERROR:

	// Remove all nodes from the list
	list_clear(&sync_attribute_node_list);
	return false;
}

static void prepare_sync_user_node_list(MYSQL *db_conn, unsigned int authority_id)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	sync_user_node_t user_node;
	unsigned int     counter = 0;

	// Query for user info
	sprintf(stat, "SELECT user_id, username FROM %s WHERE authority_id = %u", UA__USERS_IN_OTHER_AUTHORITIES, authority_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		user_node.node_id = counter++;
		user_node.user_id = atoi(row[0]);
		strcpy(user_node.username, row[1]);

		// Append the user list
		if(list_append(&sync_user_node_list, &user_node) < 0)
			int_error("Appending the linked list failed");
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static void update_user_info(MYSQL *db_conn, unsigned int user_id, char *email_address, char *ssl_pub_key)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Update the user's e-mail address if any update
	sprintf(stat, "UPDATE %s SET email_address = '%s' WHERE user_id = %u AND email_address NOT LIKE '%s' COLLATE latin1_general_cs", 
		UA__USERS_IN_OTHER_AUTHORITIES, email_address, user_id, email_address);

	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}

	// Update the user's SSL public key if any update
	sprintf(stat, "UPDATE %s SET ssl_pub_key = '%s' WHERE user_id = %u AND ssl_pub_key NOT LIKE '%s' COLLATE latin1_general_cs", 
		UA__USERS_IN_OTHER_AUTHORITIES, ssl_pub_key, user_id, ssl_pub_key);

	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
}

static void insert_new_user(MYSQL *db_conn, char *username, unsigned int authority_id, char *email_address, char *ssl_pub_key)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Insert a new user
	sprintf(stat, "INSERT INTO %s(username, authority_id, email_address, ssl_pub_key) VALUES('%s', %u, '%s', '%s')", 
		UA__USERS_IN_OTHER_AUTHORITIES, username, authority_id, email_address, ssl_pub_key);

	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
}

static void remove_access_permission_assigned_by_revoked_phr_owner(MYSQL *db_conn, unsigned int phr_owner_id, unsigned int phr_owner_authority_id)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Delete the access permission assigned by the PHR owner
	sprintf(stat, "DELETE FROM %s WHERE phr_owner_id = %u AND phr_owner_authority_id = %u", UA__ACCESS_PERMISSIONS, phr_owner_id, phr_owner_authority_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
}

static boolean record_transaction_log_on_access_permission_granted_user_was_removed_by_syncing_authority(SSL *ssl_conn, char *revoked_username, 
	char *revoked_user_authority_name, char *phr_owner_name)
{
	SSL  *ssl_conn_AS = NULL;
	char buffer[BUFFER_LENGTH + 1];
	char current_date_time[DATETIME_STR_LENGTH  + 1];
	char peer_ip_address[IP_ADDRESS_LENGTH + 1];

	// Get current date/time and peer's IP address
	get_current_date_time(current_date_time);
	SSL_get_peer_address(ssl_conn, peer_ip_address, NULL);

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
	write_token_into_buffer("actor_name", ITS_ADMIN_NAME, true, buffer);
	write_token_into_buffer("actor_authority_name", revoked_user_authority_name, false, buffer);
	write_token_into_buffer("does_actor_is_admin_flag", "1", false, buffer);
	write_token_into_buffer("object_owner_name", revoked_username, false, buffer);
	write_token_into_buffer("object_owner_authority_name", revoked_user_authority_name, false, buffer);
	write_token_into_buffer("does_object_owner_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("affected_username", phr_owner_name, false, buffer);
	write_token_into_buffer("affected_user_authority_name", GLOBAL_authority_name, false, buffer);
	write_token_into_buffer("does_affected_user_is_admin_flag", "0", false, buffer);
	write_token_into_buffer("object_description", NO_SPECIFIC_DATA, false, buffer);
	write_token_into_buffer("event_description", ACCESS_PERMISSION_GRANTED_USER_WAS_REMOVED, false, buffer);
	write_token_into_buffer("date_time", current_date_time, false, buffer);
	write_token_into_buffer("actor_ip_address", peer_ip_address, false, buffer);

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

static void remove_access_permission_assigned_to_revoked_object_user(SSL *ssl_conn, MYSQL *db_conn, unsigned int object_user_id, char *object_owner_name, 
	unsigned int object_user_authority_id, char *object_user_authorirty_name)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int assigned_permission_id;
	char         phr_owner_name[USER_NAME_LENGTH + 1];

	// Query for user list that assigned access permissions to the revoked object user
	sprintf(stat, "SELECT PAO.assigned_permission_id, USR.username FROM %s PAO, %s USR WHERE PAO.object_user_id = '%u' AND PAO.object_user_authority_id = '%u' AND "
		"PAO.user_id = USR.user_id", UA__PERMISSIONS_ASSIGNED_TO_OTHERS, UA__USERS, object_user_id, object_user_authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		assigned_permission_id = atoi(row[0]);
		strcpy(phr_owner_name, row[1]);

		// Delete assigned access permissions of each PHR owner
		sprintf(stat, "DELETE FROM %s WHERE assigned_permission_id = %u", UA__PERMISSIONS_ASSIGNED_TO_OTHERS, assigned_permission_id);
		if(mysql_query(db_conn, stat))
		{
			sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		      	int_error(err_msg);
		}

		// Record a transaction log
		record_transaction_log_on_access_permission_granted_user_was_removed_by_syncing_authority(
			ssl_conn, object_owner_name, object_user_authorirty_name, phr_owner_name);
	}
	
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static void remove_revoked_user(MYSQL *db_conn, SSL *ssl_conn, unsigned int user_id, char *username, unsigned int authority_id, char *authority_name)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	remove_access_permission_assigned_by_revoked_phr_owner(db_conn, user_id, authority_id);
	remove_access_permission_assigned_to_revoked_object_user(ssl_conn, db_conn, user_id, username, authority_id, authority_name);

	// Delete a revoked user
	sprintf(stat, "DELETE FROM %s WHERE user_id = %u", UA__USERS_IN_OTHER_AUTHORITIES, user_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
}

static boolean synchronize_user(MYSQL *db_conn, SSL *ssl_conn, unsigned int authority_id, char *authority_name)
{
	char    buffer[LARGE_BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    is_end_of_user_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_user_list_flag;
	char    username[USER_NAME_LENGTH + 1];
	char    email_address[EMAIL_ADDRESS_LENGTH + 1];
	char    ssl_pub_key[SSL_PUB_KEY_LENGTH + 1];

	sync_user_node_t *ptr_user_node = NULL;

	// Load a user list of the desired authority
	prepare_sync_user_node_list(db_conn, authority_id);

	while(1)
	{
		// Receive user information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving user information failed\n");
			goto ERROR;
		}

		// Get user information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_user_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_user_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_user_list_flag failed");
		}

		is_end_of_user_list_flag = (strcmp(is_end_of_user_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_user_list_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "username") != 0)
		{
			int_error("Extracting the username failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, email_address) != READ_TOKEN_SUCCESS || strcmp(token_name, "email_address") != 0)
		{
			int_error("Extracting the email_address failed");
		}

		if(read_token_from_buffer(buffer, 4, token_name, ssl_pub_key) != READ_TOKEN_SUCCESS || strcmp(token_name, "ssl_pub_key") != 0)
		{
			int_error("Extracting the ssl_pub_key failed");
		}

		// Get a user node that corresponds to "username" if exists in a linked list
		ptr_user_node = (sync_user_node_t *)list_seek(&sync_user_node_list, username);

		// If a user exists then update the user's information and remove a node from the list, unless insert that user into a database
		if(ptr_user_node)
		{
printf("[synced usr] = %s\n", username);
			// Update the user's e-mail address or SSL public key if any update
			update_user_info(db_conn, ptr_user_node->user_id, email_address, ssl_pub_key);

			// Remove a user from the list
			if(list_delete_at(&sync_user_node_list, list_locate(&sync_user_node_list, ptr_user_node)) < 0)
				int_error("Removing a user node failed");
		}
		else
		{
printf("[new usr] = %s\n", username);
			// Insert a user into a database
			insert_new_user(db_conn, username, authority_id, email_address, ssl_pub_key);
		}		
	}

	if(!list_iterator_start(&sync_user_node_list))
		int_error("Starting list iteration failed");

	// The remaining users in the list are the revoked users
	while(list_iterator_hasnext(&sync_user_node_list))
	{
		ptr_user_node = (sync_user_node_t *)list_iterator_next(&sync_user_node_list);
printf("[revoke usr] = %s\n", ptr_user_node->username);

		// Remove the revoked user from a database
		remove_revoked_user(db_conn, ssl_conn, ptr_user_node->user_id, ptr_user_node->username, authority_id, authority_name);
	}

	if(!list_iterator_stop(&sync_user_node_list))
		int_error("Stopping list iteration failed");

	// Remove all nodes from the list
	list_clear(&sync_user_node_list);
	return true;

ERROR:

	// Remove all nodes from the list
	list_clear(&sync_user_node_list);
	return false;
}

static boolean get_username(MYSQL *db_conn, unsigned int user_id, char *username_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Query for username of current authority
	sprintf(stat, "SELECT username FROM %s WHERE user_id = %u", UA__USERS, user_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		fprintf(stderr, "Getting a username from a database failed\n");
		goto ERROR;
	}

	strcpy(username_ret, row[0]);

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

static boolean get_phr_ownername(MYSQL *db_conn, unsigned int phr_owner_id, unsigned int phr_owner_authority_id, char *phr_ownername_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Query for PHR ownername
	sprintf(stat, "SELECT username FROM %s WHERE user_id = %u AND authority_id = %u", UA__USERS_IN_OTHER_AUTHORITIES, phr_owner_id, phr_owner_authority_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		fprintf(stderr, "Getting a PHR ownername from a database failed\n");
		goto ERROR;
	}

	strcpy(phr_ownername_ret, row[0]);

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

static void prepare_sync_access_permission_node_list(MYSQL *db_conn, unsigned int authority_id)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	sync_access_permission_node_t access_permission_node;
	unsigned int                  user_id;
	unsigned int                  phr_owner_id;
	unsigned int                  counter = 0;

	// Query for access permission info
	sprintf(stat, "SELECT access_permission_id, user_id, phr_owner_id, upload_permission_flag, download_permission_flag, "
		"delete_permission_flag FROM %s WHERE phr_owner_authority_id = %u", UA__ACCESS_PERMISSIONS, authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		user_id      = atoi(row[1]);
		phr_owner_id = atoi(row[2]);

		if(!get_username(db_conn, user_id, access_permission_node.username))
			continue;
		
		if(!get_phr_ownername(db_conn, phr_owner_id, authority_id, access_permission_node.phr_ownername))
			continue;

		access_permission_node.node_id                  = counter++;
		access_permission_node.access_permission_id     = atoi(row[0]);
		access_permission_node.upload_permission_flag   = (strcmp(row[3], "1") == 0) ? true : false;
		access_permission_node.download_permission_flag = (strcmp(row[4], "1") == 0) ? true : false;
		access_permission_node.delete_permission_flag   = (strcmp(row[5], "1") == 0) ? true : false;

		// Append the access permission list
		if(list_append(&sync_access_permission_node_list, &access_permission_node) < 0)
			int_error("Appending the linked list failed");
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static void update_access_permission(MYSQL *db_conn, unsigned int access_permission_id, boolean upload_permission_flag, 
	boolean download_permission_flag, boolean delete_permission_flag)
{
	char  stat[SQL_STATEMENT_LENGTH + 1];
	char  err_msg[ERR_MSG_LENGTH + 1];

	// Update the permissions
	sprintf(stat, "UPDATE %s SET upload_permission_flag = '%s', download_permission_flag = '%s', delete_permission_flag = '%s' WHERE access_permission_id = %u", 
		UA__ACCESS_PERMISSIONS, (upload_permission_flag) ? "1" : "0", (download_permission_flag) ? "1" : "0", (delete_permission_flag) ? "1" : "0", 
		access_permission_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
}

static boolean get_user_id(MYSQL *db_conn, char *username, unsigned int *user_id_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Query for user id of current authority
	sprintf(stat, "SELECT user_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs", UA__USERS, username);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		fprintf(stderr, "Getting a user id from a database failed\n");
		goto ERROR;
	}

	*user_id_ret = atoi(row[0]);

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

static boolean get_phr_owner_id(MYSQL *db_conn, char *phr_ownername, unsigned int phr_owner_authority_id, unsigned int *phr_owner_id_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Query for phr owner id
	sprintf(stat, "SELECT user_id FROM %s WHERE username LIKE '%s' COLLATE latin1_general_cs AND authority_id = %u", 
		UA__USERS_IN_OTHER_AUTHORITIES, phr_ownername, phr_owner_authority_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		fprintf(stderr, "Getting a PHR owner id from a database failed\n");
		goto ERROR;
	}

	*phr_owner_id_ret = atoi(row[0]);

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

static boolean insert_new_access_permission(MYSQL *db_conn, char *username, char *phr_ownername, unsigned int phr_owner_authority_id, boolean upload_permission_flag, 
	boolean download_permission_flag, boolean delete_permission_flag)
{
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	unsigned int user_id;
	unsigned int phr_owner_id;

	if(!get_user_id(db_conn, username, &user_id))
		goto ERROR;

	if(!get_phr_owner_id(db_conn, phr_ownername, phr_owner_authority_id, &phr_owner_id))
		goto ERROR;

	// Insert the access permission for this desired user (access_permissions)
	sprintf(stat, "INSERT INTO %s(user_id, phr_owner_id, phr_owner_authority_id, upload_permission_flag, download_permission_flag, delete_permission_flag) "
		"VALUES(%u, %u, %u, '%s', '%s', '%s')", UA__ACCESS_PERMISSIONS, user_id, phr_owner_id, phr_owner_authority_id, (upload_permission_flag) ? "1" : "0", 
		(download_permission_flag) ? "1" : "0", (delete_permission_flag) ? "1" : "0");

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	return true;

ERROR:

	return false;
}

static void remove_revoked_access_permission(MYSQL *db_conn, unsigned int access_permission_id)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Delete a revoked access permission
	sprintf(stat, "DELETE FROM %s WHERE access_permission_id = %u", UA__ACCESS_PERMISSIONS, access_permission_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
}

static boolean synchronize_access_permission(MYSQL *db_conn, SSL *ssl_conn, unsigned int authority_id)
{
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    is_end_of_assigned_access_permission_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_assigned_access_permission_list_flag;
	char    username[USER_NAME_LENGTH + 1];
	char    phr_ownername[USER_NAME_LENGTH + 1];
	char    permission_flag_str_tmp[FLAG_LENGTH + 1];
	boolean upload_permission_flag;
	boolean download_permission_flag;
	boolean delete_permission_flag;

	access_permission_key_t       ap_key;
	sync_access_permission_node_t *ptr_access_permission_node = NULL;

	// Load an access permission list of desired authority's users that assigned to users in current authority
	prepare_sync_access_permission_node_list(db_conn, authority_id);

	while(1)
	{
		// Receive access permission information
		if(SSL_recv_buffer(ssl_conn, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving access permission information failed\n");
			goto ERROR;
		}

		// Get access permission information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_assigned_access_permission_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_assigned_access_permission_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_assigned_access_permission_list_flag failed");
		}

		is_end_of_assigned_access_permission_list_flag = (strcmp(is_end_of_assigned_access_permission_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_assigned_access_permission_list_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, username) != READ_TOKEN_SUCCESS || strcmp(token_name, "assigned_username") != 0)
		{
			int_error("Extracting the assigned_username failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		{
			int_error("Extracting the phr_ownername failed");
		}

		if(read_token_from_buffer(buffer, 4, token_name, permission_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "upload_permission_flag") != 0)
		{
			int_error("Extracting the upload_permission_flag failed");
		}

		upload_permission_flag = (strcmp(permission_flag_str_tmp, "1") == 0) ? true : false;

		if(read_token_from_buffer(buffer, 5, token_name, permission_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "download_permission_flag") != 0)
		{
			int_error("Extracting the download_permission_flag failed");
		}

		download_permission_flag = (strcmp(permission_flag_str_tmp, "1") == 0) ? true : false;

		if(read_token_from_buffer(buffer, 6, token_name, permission_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "delete_permission_flag") != 0)
		{
			int_error("Extracting the delete_permission_flag failed");
		}

		delete_permission_flag = (strcmp(permission_flag_str_tmp, "1") == 0) ? true : false;

		// Get an access permission node that corresponds to the access permission key if exists in a linked list
		strcpy(ap_key.username, username);
		strcpy(ap_key.phr_ownername, phr_ownername);
		ptr_access_permission_node = (sync_access_permission_node_t *)list_seek(&sync_access_permission_node_list, &ap_key);

		// If an access permission exists then update it in a database and remove from the list, unless insert that access permission into a database
		if(ptr_access_permission_node)
		{
printf("[synced ap] => user = %s, owner = %s\n", username, phr_ownername);
			// Update the permissions if they are changed
			if(ptr_access_permission_node->upload_permission_flag != upload_permission_flag || ptr_access_permission_node->download_permission_flag 
				!= download_permission_flag || ptr_access_permission_node->delete_permission_flag != delete_permission_flag)
			{
				update_access_permission(db_conn, ptr_access_permission_node->access_permission_id, 
					upload_permission_flag, download_permission_flag, delete_permission_flag);
			}

			// Remove an access permission from the list
			if(list_delete_at(&sync_access_permission_node_list, list_locate(&sync_access_permission_node_list, ptr_access_permission_node)) < 0)
				int_error("Removing an access permission node failed");
		}
		else
		{
printf("[new ap] => user = %s, owner = %s\n", username, phr_ownername);
			// Insert an access permission into a database
			if(!insert_new_access_permission(db_conn, username, phr_ownername, authority_id, upload_permission_flag, 
				download_permission_flag, delete_permission_flag))
			{
				goto ERROR;
			}
		}		
	}

	if(!list_iterator_start(&sync_access_permission_node_list))
		int_error("Starting list iteration failed");

	// The remaining access permission sets in the list are revoked access permission sets
	while(list_iterator_hasnext(&sync_access_permission_node_list))
	{
		ptr_access_permission_node = (sync_access_permission_node_t *)list_iterator_next(&sync_access_permission_node_list);
printf("[revoke ap] => user = %s, owner = %s\n", ptr_access_permission_node->username, ptr_access_permission_node->phr_ownername);

		// Remove a revoked access permission set from a database
		remove_revoked_access_permission(db_conn, ptr_access_permission_node->access_permission_id);
	}

	if(!list_iterator_stop(&sync_access_permission_node_list))
		int_error("Stopping list iteration failed");

	// Remove all nodes from the list
	list_clear(&sync_access_permission_node_list);
	return true;

ERROR:

	// Remove all nodes from the list
	list_clear(&sync_access_permission_node_list);
	return false;
}

static boolean connect_to_emergency_delegation_synchronization_service(SSL **ssl_conn_ret)
{
	BIO     *bio_conn = NULL;
    	SSL_CTX *ctx      = NULL;
	int     err;
	char    *hosts[1];
	char    emergency_server_addr[IP_ADDRESS_LENGTH + PORT_NUMBER_LENGTH + 2];

	// Connect to Emergency Server
	sprintf(emergency_server_addr, "%s:%s", GLOBAL_emergency_server_ip_addr, EMS_DELEGATION_SYNCHRONIZATION_RECEIVING_PORT);
	bio_conn = BIO_new_connect(emergency_server_addr);
    	if(!bio_conn)
        	int_error("Creating BIO connection failed");
 
    	if(BIO_do_connect(bio_conn) <= 0)
	{
		fprintf(stderr, "Connecting to emergency server failed\n");
		goto ERROR_AT_BIO_LAYER;
	}

	ctx = setup_client_ctx(UA_CERTFILE_PATH, UA_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
	if(!(*ssl_conn_ret = SSL_new(ctx)))
            	int_error("Creating SSL context failed");
 
    	SSL_set_bio(*ssl_conn_ret, bio_conn, bio_conn);
    	if(SSL_connect(*ssl_conn_ret) <= 0)
	{
        	fprintf(stderr, "Connecting SSL object failed\n");
		goto ERROR_AT_SSL_LAYER;
	}

	hosts[0] = EMERGENCY_SERVER_CN;
	if((err = post_connection_check(*ssl_conn_ret, hosts, 1, true, GLOBAL_authority_name)) != X509_V_OK)
   	{
		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
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

static boolean synchronize_emergency_delegation(SSL *ssl_incoming_conn, char *peer_authority_name)
{
	SSL     *ssl_outgoing_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    sync_flag_str_tmp[FLAG_LENGTH + 1];
	boolean sync_flag;

	char    is_end_of_peer_phr_owner_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_peer_phr_owner_list_flag;

	char    is_end_of_peer_trusted_user_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_peer_trusted_user_list_flag;

	// Connect to Emergency Server
	if(!connect_to_emergency_delegation_synchronization_service(&ssl_outgoing_conn))
	{
		// Send the sync flag
		write_token_into_buffer("sync_flag", "0", true, buffer);
		if(!SSL_send_buffer(ssl_incoming_conn, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the sync flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}	

	// Send the sync flag
	write_token_into_buffer("sync_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_incoming_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the sync flag failed\n");
		goto ERROR;
	}

	// Send peer authority name
	write_token_into_buffer("peer_authority_name", peer_authority_name, true, buffer);
	if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending peer authority name failed\n");
		goto ERROR;
	}

	// Receive the sync flag
	if(SSL_recv_buffer(ssl_incoming_conn, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the syncing flag failed\n");
		goto ERROR;
	}

	// Get the syncing flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, sync_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "sync_flag") != 0)
	{
		int_error("Extracting the sync_flag failed");
	}

	sync_flag = (strcmp(sync_flag_str_tmp, "1") == 0) ? true : false;
	if(!sync_flag)
	{
		goto ERROR;
	}

	// Peer PHR owner list
	while(1)
	{
		// Receive the peer PHR owner information
		if(SSL_recv_buffer(ssl_incoming_conn, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving the peer PHR owner information failed\n");
			goto ERROR;
		}

		// Get the "is_end_of_peer_phr_owner_list_flag" token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_peer_phr_owner_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_peer_phr_owner_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_peer_phr_owner_list_flag failed");
		}

		is_end_of_peer_phr_owner_list_flag = (strcmp(is_end_of_peer_phr_owner_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_peer_phr_owner_list_flag)
			break;

		// Forward the packet to emergency server
		if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Forwarding the peer PHR owner information failed\n");
			goto ERROR;
		}
	}

	// Forward the last packet to emergency server
	if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Forwarding the peer PHR owner information failed\n");
		goto ERROR;
	}

	// Peer trusted user list
	while(1)
	{
		// Receive the peer trusted user information
		if(SSL_recv_buffer(ssl_incoming_conn, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving the peer trusted user information failed\n");
			goto ERROR;
		}

		// Get the "is_end_of_peer_trusted_user_list_flag" token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_peer_trusted_user_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_peer_trusted_user_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_peer_trusted_user_list_flag failed");
		}

		is_end_of_peer_trusted_user_list_flag = (strcmp(is_end_of_peer_trusted_user_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_peer_trusted_user_list_flag)
			break;

		// Forward the packet to emergency server
		if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Forwarding the peer trusted user information failed\n");
			goto ERROR;
		}
	}

	// Forward the last packet to emergency server
	if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Forwarding the peer trusted user information failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_outgoing_conn);
	ssl_outgoing_conn = NULL;
	return true;

ERROR:

	if(ssl_outgoing_conn)
	{
		SSL_cleanup(ssl_outgoing_conn);
		ssl_outgoing_conn = NULL;
	}

	return false;
}

static boolean synchronize_phr_transaction_log(SSL *ssl_incoming_conn)
{
	SSL     *ssl_outgoing_conn = NULL;
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];

	char    sync_flag_str_tmp[FLAG_LENGTH + 1];
	boolean sync_flag;

	char    is_end_of_phr_transaction_logs_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_phr_transaction_logs_flag;

	// Connect to Audit Server
	if(!connect_to_transaction_log_recording_service(&ssl_outgoing_conn))
	{
		// Send the sync flag
		write_token_into_buffer("sync_flag", "0", true, buffer);
		if(!SSL_send_buffer(ssl_incoming_conn, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the sync flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Send the sync flag
	write_token_into_buffer("sync_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_incoming_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the sync flag failed\n");
		goto ERROR;
	}

	// Send transaction log request type
	write_token_into_buffer("request_type", PHR_LOG_SYNCHRONIZATION, true, buffer);
	if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending transaction log request type failed\n");
		goto ERROR;
	}

	// Receive the sync flag
	if(SSL_recv_buffer(ssl_incoming_conn, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving the syncing flag failed\n");
		goto ERROR;
	}

	// Get the syncing flag token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, sync_flag_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "sync_flag") != 0)
	{
		int_error("Extracting the sync_flag failed");
	}

	sync_flag = (strcmp(sync_flag_str_tmp, "1") == 0) ? true : false;
	if(!sync_flag)
	{
		goto ERROR;
	}

	while(1)
	{
		// Receive PHR transaction log information
		if(SSL_recv_buffer(ssl_incoming_conn, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving PHR transaction log information failed\n");
			goto ERROR;
		}

		// Get the "is_end_of_phr_transaction_logs_flag" token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_phr_transaction_logs_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_phr_transaction_logs_flag") != 0)
		{
			int_error("Extracting the is_end_of_phr_transaction_logs_flag failed");
		}

		is_end_of_phr_transaction_logs_flag = (strcmp(is_end_of_phr_transaction_logs_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_phr_transaction_logs_flag)
			break;

		// Forward the packet to audit server
		if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Forwarding the PHR transaction log information failed\n");
			goto ERROR;
		}
	}

	// Forward the last packet to audit server
	if(!SSL_send_buffer(ssl_outgoing_conn, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Forwarding the PHR transaction log information failed\n");
		goto ERROR;
	}

	SSL_cleanup(ssl_outgoing_conn);
	ssl_outgoing_conn = NULL;
	return true;

ERROR:

	if(ssl_outgoing_conn)
	{
		SSL_cleanup(ssl_outgoing_conn);
		ssl_outgoing_conn = NULL;
	}

	return false;
}

static boolean authority_synchronization_main(SSL *ssl_conn, unsigned int authority_id, char *authority_name)
{
	MYSQL *db_conn = NULL;

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	if(!synchronize_authority_info(db_conn, ssl_conn, authority_id))
		goto ERROR;

	if(!synchronize_attribute(db_conn, ssl_conn, authority_id))
		goto ERROR;

	if(!synchronize_user(db_conn, ssl_conn, authority_id, authority_name))
		goto ERROR;

	if(!synchronize_access_permission(db_conn, ssl_conn, authority_id))
		goto ERROR;

	if(!synchronize_emergency_delegation(ssl_conn, authority_name))
		goto ERROR;

	if(!synchronize_phr_transaction_log(ssl_conn))
		goto ERROR;

	disconnect_db(&db_conn);
	return true;

ERROR:

	disconnect_db(&db_conn);
	return false;
}

static void process()
{
	MYSQL        *db_conn = NULL;
	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int authority_id;
	char         authority_name[AUTHORITY_NAME_LENGTH + 1];
	char         user_auth_ip_addr[IP_ADDRESS_LENGTH + 1];
	boolean      authority_join_flag;

	SSL          *ssl_conn = NULL;
	char         request_result[RESULT_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query for authority info
	sprintf(stat, "SELECT authority_id, authority_name, user_auth_ip_addr, authority_join_flag FROM %s WHERE "
		"authority_name NOT LIKE '%s' COLLATE latin1_general_cs", UA__AUTHORITIES, GLOBAL_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);

	// Lock the synchronization from removing an authority
	if(sem_wait(&sync_lock_mutex) != 0)
		int_error("Locking the mutex failed");

	while((row = mysql_fetch_row(result)))
	{
		authority_id = atoi(row[0]);
		strcpy(authority_name, row[1]);
		strcpy(user_auth_ip_addr, row[2]);
		authority_join_flag = (strcmp(row[3], "1") == 0) ? true : false;

		// Connect to the selected authority's User Authority
		if(!connect_to_synchronization_service(authority_name, user_auth_ip_addr, &ssl_conn))
			goto ERROR;

		if(!authority_join_flag)
		{
printf("[REQ]send join msg\n");
			// Send the joining requesting message
			if(!request_authority_joining(ssl_conn, request_result))
				goto ERROR;

			// Process the result
			if(strcmp(request_result, AUTHORITY_JOINING_APPROVAL) == 0)
			{
printf("[REQ]join approve\n");
				set_authority_join_flag(db_conn, authority_id);
				if(!authority_synchronization_main(ssl_conn, authority_id, authority_name))
					goto ERROR;
			}
			else if(strcmp(request_result, AUTHORITY_JOINING_NO_APPROVAL) == 0)
			{
printf("[REQ]join not approve\n");
				printf("No approval to join an authority \"%s\"\n", authority_name);
			}
			else
			{
				fprintf(stderr, "Invalid result type\n");
				goto ERROR;
			}
		}
		else
		{
printf("[REQ]send sync msg\n");
			// Send the authority synchronization requesting message
			if(!request_authority_synchronization(ssl_conn, request_result))
				goto ERROR;

			// Process the result
			if(strcmp(request_result, AUTHORITY_SYNCHRONIZATION_APPROVAL) == 0)
			{
printf("[REQ]sync approve\n");
				if(!authority_synchronization_main(ssl_conn, authority_id, authority_name))
					goto ERROR;
			}
			else if(strcmp(request_result, AUTHORITY_REVOCATION) == 0)
			{
printf("[REQ]auth revoked\n");
				remove_authority(ssl_conn, authority_id, authority_name);
			}
			else
			{
				fprintf(stderr, "Invalid result type\n");
				goto ERROR;
			}
		}

ERROR:
		if(ssl_conn)
		{
			SSL_cleanup(ssl_conn);
			ssl_conn = NULL;
		}

		// Unlock the synchronization and yield to remove an authority (if any)
		if(sem_post(&sync_lock_mutex) != 0)
			int_error("Unlocking the mutex failed");

		sleep(1);

		// Lock the synchronization from removing an authority
		if(sem_wait(&sync_lock_mutex) != 0)
			int_error("Locking the mutex failed");
	}

	// Unlock the synchronization and yield to remove an authority (if any)
	if(sem_post(&sync_lock_mutex) != 0)
		int_error("Unlocking the mutex failed");

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
}

static size_t list_meter_sync_attribute_node_t(const void *element)
{
	return sizeof(sync_attribute_node_t);
}

static int list_seeker_by_attribute_name(const void *element, const void *key)
{
	const sync_attribute_node_t *node = (sync_attribute_node_t *)element;

	if(strcmp(node->attribute_name, (char *)key) == 0)
		return 1;
	else
		return 0;
}

static int list_comparator_by_attribute_node_id(const void *nodeA, const void *nodeB)
{
	if(((sync_attribute_node_t *)nodeA)->node_id > ((sync_attribute_node_t *)nodeB)->node_id)
	{
		return -1;
	}
	else if(((sync_attribute_node_t *)nodeA)->node_id == ((sync_attribute_node_t *)nodeB)->node_id)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

static void init_attribute_synchronization_list()
{
	// Initialize a linked list
	if(list_init(&sync_attribute_node_list) < 0)
		int_error("Initial a linked list failed");

	// Request to store copies and provide the metric function
    	if(list_attributes_copy(&sync_attribute_node_list, list_meter_sync_attribute_node_t, 1) < 0)
		int_error("Initial a metric function failed");

	// Set the custom seeker function
	if(list_attributes_seeker(&sync_attribute_node_list, list_seeker_by_attribute_name) < 0)
		int_error("Initial a custom seeker function failed");

	// Set the custom comparator function
	if(list_attributes_comparator(&sync_attribute_node_list, list_comparator_by_attribute_node_id) < 0)
		int_error("Initial a custom comparator function failed");
}

static size_t list_meter_sync_user_node_t(const void *element)
{
	return sizeof(sync_user_node_t);
}

static int list_seeker_by_username(const void *element, const void *key)
{
	const sync_user_node_t *node = (sync_user_node_t *)element;

	if(strcmp(node->username, (char *)key) == 0)
		return 1;
	else
		return 0;
}

static int list_comparator_by_user_node_id(const void *nodeA, const void *nodeB)
{
	if(((sync_user_node_t *)nodeA)->node_id > ((sync_user_node_t *)nodeB)->node_id)
	{
		return -1;
	}
	else if(((sync_user_node_t *)nodeA)->node_id == ((sync_user_node_t *)nodeB)->node_id)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

static void init_user_synchronization_list()
{
	// Initialize a linked list
	if(list_init(&sync_user_node_list) < 0)
		int_error("Initial a linked list failed");

	// Request to store copies and provide the metric function
    	if(list_attributes_copy(&sync_user_node_list, list_meter_sync_user_node_t, 1) < 0)
		int_error("Initial a metric function failed");

	// Set the custom seeker function
	if(list_attributes_seeker(&sync_user_node_list, list_seeker_by_username) < 0)
		int_error("Initial a custom seeker function failed");

	// Set the custom comparator function
	if(list_attributes_comparator(&sync_user_node_list, list_comparator_by_user_node_id) < 0)
		int_error("Initial a custom comparator function failed");
}

static size_t list_meter_sync_access_permission_node_t(const void *element)
{
	return sizeof(sync_access_permission_node_t);
}

static int list_seeker_by_access_permission_info(const void *element, const void *key)
{
	const sync_access_permission_node_t *node   = (sync_access_permission_node_t *)element;
	const access_permission_key_t       *ap_key = (access_permission_key_t *)key;

	if(strcmp(node->username, ap_key->username) == 0 && strcmp(node->phr_ownername, ap_key->phr_ownername) == 0)
		return 1;
	else
		return 0;
}

static int list_comparator_by_access_permission_node_id(const void *nodeA, const void *nodeB)
{
	if(((sync_access_permission_node_t *)nodeA)->node_id > ((sync_access_permission_node_t *)nodeB)->node_id)
	{
		return -1;
	}
	else if(((sync_access_permission_node_t *)nodeA)->node_id == ((sync_access_permission_node_t *)nodeB)->node_id)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

static void init_access_permission_synchronization_list()
{
	// Initialize a linked list
	if(list_init(&sync_access_permission_node_list) < 0)
		int_error("Initial a linked list failed");

	// Request to store copies and provide the metric function
    	if(list_attributes_copy(&sync_access_permission_node_list, list_meter_sync_access_permission_node_t, 1) < 0)
		int_error("Initial a metric function failed");

	// Set the custom seeker function
	if(list_attributes_seeker(&sync_access_permission_node_list, list_seeker_by_access_permission_info) < 0)
		int_error("Initial a custom seeker function failed");

	// Set the custom comparator function
	if(list_attributes_comparator(&sync_access_permission_node_list, list_comparator_by_access_permission_node_id) < 0)
		int_error("Initial a custom comparator function failed");
}

static void init_synchronization_module()
{
	init_attribute_synchronization_list();
	init_user_synchronization_list();
	init_access_permission_synchronization_list();
}

static void uninit_synchronization_module()
{
	// Destroy linked lists
	list_destroy(&sync_attribute_node_list);
	list_destroy(&sync_user_node_list);
	list_destroy(&sync_access_permission_node_list);
}

void *synchronization_requesting_main(void *arg)
{
	init_synchronization_module();

	while(1)
	{
printf("[REQ]in\n");
		process();
printf("[REQ]out\n\n");
		sleep(SYNCHRONIZATION_TIME_PERIOD*60);
	}

	uninit_synchronization_module();

	pthread_exit(NULL);
    	return NULL;
}




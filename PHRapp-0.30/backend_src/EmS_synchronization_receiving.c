#include "EmS_common.h"
#include "simclist.h"

struct sync_emergency_delegation_node
{
	unsigned int node_id;
	unsigned int delegation_id;
	char         trusted_username[USER_NAME_LENGTH + 1];
	char         phr_ownername[USER_NAME_LENGTH + 1];
};

typedef struct sync_emergency_delegation_node sync_emergency_delegation_node_t;

struct list_search_key_params
{
	char trusted_username[USER_NAME_LENGTH + 1];
	char phr_ownername[USER_NAME_LENGTH + 1];
};

typedef struct list_search_key_params list_search_key_params_t;

// Local Variables
static list_t sync_peer_phr_owner_node_list;
static list_t sync_peer_trusted_user_node_list;

// Local Function Prototypes
static size_t list_meter_sync_emergency_delegation_node_t(const void *element);
static int emergency_delegation_node_list_seeker(const void *element, const void *keys);
static int list_comparator_by_emergency_delegation_node_id(const void *nodeA, const void *nodeB);
static void init_peer_phr_owner_synchronization_list();
static void init_peer_trusted_user_synchronization_list();
static void init_synchronization_module();
static void uninit_synchronization_module();
static void get_username(MYSQL *db_conn, unsigned int user_id, char *username_ret);
static void prepare_sync_peer_phr_owner_node_list(MYSQL *db_conn, char *peer_authority_name);
static void prepare_sync_peer_trusted_user_node_list(MYSQL *db_conn, char *peer_authority_name);
static void insert_new_delegation(MYSQL *db_conn, char *phr_ownername, char *phr_owner_authority_name, char *trusted_username);
static void remove_revoked_delegation(MYSQL *db_conn, unsigned int delegation_id);
static boolean synchronize_peer_phr_owner_list(MYSQL *db_conn, SSL *ssl_client, char *peer_authority_name);
static void set_delegation_node_rejection_by_trusted_user(MYSQL *db_conn, unsigned int delegation_id);
static boolean synchronize_peer_trusted_user_list(MYSQL *db_conn, SSL *ssl_client);
static boolean process_synchronization(SSL *ssl_client);

// Implementation
static size_t list_meter_sync_emergency_delegation_node_t(const void *element)
{
	return sizeof(sync_emergency_delegation_node_t);
}

static int emergency_delegation_node_list_seeker(const void *element, const void *keys)
{
	const sync_emergency_delegation_node_t *node = (sync_emergency_delegation_node_t *)element;

	if(strcmp(node->trusted_username, (char *)(((list_search_key_params_t *)keys)->trusted_username)) == 0 && 
		strcmp(node->phr_ownername, (char *)(((list_search_key_params_t *)keys)->phr_ownername)) == 0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

static int list_comparator_by_emergency_delegation_node_id(const void *nodeA, const void *nodeB)
{
	if(((sync_emergency_delegation_node_t *)nodeA)->node_id > ((sync_emergency_delegation_node_t *)nodeB)->node_id)
	{
		return -1;
	}
	else if(((sync_emergency_delegation_node_t *)nodeA)->node_id == ((sync_emergency_delegation_node_t *)nodeB)->node_id)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

static void init_peer_phr_owner_synchronization_list()
{
	// Initialize a linked list
	if(list_init(&sync_peer_phr_owner_node_list) < 0)
		int_error("Initial a linked list failed");

	// Request to store copies and provide the metric function
    	if(list_attributes_copy(&sync_peer_phr_owner_node_list, list_meter_sync_emergency_delegation_node_t, 1) < 0)
		int_error("Initial a metric function failed");

	// Set the custom seeker function
	if(list_attributes_seeker(&sync_peer_phr_owner_node_list, emergency_delegation_node_list_seeker) < 0)
		int_error("Initial a custom seeker function failed");

	// Set the custom comparator function
	if(list_attributes_comparator(&sync_peer_phr_owner_node_list, list_comparator_by_emergency_delegation_node_id) < 0)
		int_error("Initial a custom comparator function failed");
}

static void init_peer_trusted_user_synchronization_list()
{
	// Initialize a linked list
	if(list_init(&sync_peer_trusted_user_node_list) < 0)
		int_error("Initial a linked list failed");

	// Request to store copies and provide the metric function
    	if(list_attributes_copy(&sync_peer_trusted_user_node_list, list_meter_sync_emergency_delegation_node_t, 1) < 0)
		int_error("Initial a metric function failed");

	// Set the custom seeker function
	if(list_attributes_seeker(&sync_peer_trusted_user_node_list, emergency_delegation_node_list_seeker) < 0)
		int_error("Initial a custom seeker function failed");

	// Set the custom comparator function
	if(list_attributes_comparator(&sync_peer_trusted_user_node_list, list_comparator_by_emergency_delegation_node_id) < 0)
		int_error("Initial a custom comparator function failed");
}

static void init_synchronization_module()
{
	init_peer_phr_owner_synchronization_list();
	init_peer_trusted_user_synchronization_list();
}

static void uninit_synchronization_module()
{
	// Destroy linked lists
	list_destroy(&sync_peer_phr_owner_node_list);
	list_destroy(&sync_peer_trusted_user_node_list);
}

static void get_username(MYSQL *db_conn, unsigned int user_id, char *username_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	// Query for the username
	sprintf(stat, "SELECT username FROM %s WHERE user_id=%u", EMS__USERS, user_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(!row)
	{
		int_error("Getting the username failed");
	}

	strcpy(username_ret, row[0]);
	
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static void prepare_sync_peer_phr_owner_node_list(MYSQL *db_conn, char *peer_authority_name)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int trusted_user_id;
	unsigned int phr_owner_id;

	sync_emergency_delegation_node_t peer_phr_owner_node;
	unsigned int counter = 0;

	// Query for the delegation rows that have the PHR owner belonged to the desired authority
	sprintf(stat, "SELECT DGT.delegation_id, DGT.trusted_user_id, DGT.phr_owner_id FROM %s DGT, %s USR, %s AUT WHERE DGT.phr_owner_id = USR.user_id "
		"AND USR.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs", EMS__DELEGATIONS, EMS__USERS, 
		EMS__AUTHORITIES, peer_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		peer_phr_owner_node.node_id       = counter++;
		peer_phr_owner_node.delegation_id = atoi(row[0]);
		trusted_user_id                   = atoi(row[1]);
		phr_owner_id                      = atoi(row[2]);

		// Get usernames
		get_username(db_conn, trusted_user_id, peer_phr_owner_node.trusted_username);
		get_username(db_conn, phr_owner_id, peer_phr_owner_node.phr_ownername);

		// Append the peer PHR owner list
		if(list_append(&sync_peer_phr_owner_node_list, &peer_phr_owner_node) < 0)
			int_error("Appending the linked list failed");
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static void prepare_sync_peer_trusted_user_node_list(MYSQL *db_conn, char *peer_authority_name)
{
	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int trusted_user_id;
	unsigned int phr_owner_id;

	sync_emergency_delegation_node_t peer_trusted_user_node;
	unsigned int counter = 0;

	// Query for the delegation rows that have the trusted user belonged to the desired authority
	sprintf(stat, "SELECT DGT.delegation_id, DGT.trusted_user_id, DGT.phr_owner_id FROM %s DGT, %s USR, %s AUT WHERE DGT.trusted_user_id = USR.user_id "
		"AND USR.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs AND DGT.rejection_by_trusted_user_flag='0'", 
		EMS__DELEGATIONS, EMS__USERS, EMS__AUTHORITIES, peer_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	while((row = mysql_fetch_row(result)))
	{
		peer_trusted_user_node.node_id       = counter++;
		peer_trusted_user_node.delegation_id = atoi(row[0]);
		trusted_user_id                      = atoi(row[1]);
		phr_owner_id                         = atoi(row[2]);

		// Get usernames
		get_username(db_conn, trusted_user_id, peer_trusted_user_node.trusted_username);
		get_username(db_conn, phr_owner_id, peer_trusted_user_node.phr_ownername);

		// Append the peer trusted user list
		if(list_append(&sync_peer_trusted_user_node_list, &peer_trusted_user_node) < 0)
			int_error("Appending the linked list failed");
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}
}

static void insert_new_delegation(MYSQL *db_conn, char *phr_ownername, char *phr_owner_authority_name, char *trusted_username)
{
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         err_msg[ERR_MSG_LENGTH + 1];

	unsigned int phr_owner_id;
	unsigned int trusted_user_id;

	phr_owner_id    = get_user_id_if_not_exist_create(db_conn, phr_ownername, phr_owner_authority_name);
	trusted_user_id = get_user_id_if_not_exist_create(db_conn, trusted_username, GLOBAL_authority_name);

	// Insert a new delegation
	sprintf(stat, "INSERT INTO %s(trusted_user_id, rejection_by_trusted_user_flag, phr_owner_id) VALUES(%u, '0', %u)", EMS__DELEGATIONS, trusted_user_id, phr_owner_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
}

static void remove_revoked_delegation(MYSQL *db_conn, unsigned int delegation_id)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Delete the revoked delegation
	sprintf(stat, "DELETE FROM %s WHERE delegation_id = %u", EMS__DELEGATIONS, delegation_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
}

static boolean synchronize_peer_phr_owner_list(MYSQL *db_conn, SSL *ssl_client, char *peer_authority_name)
{
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    phr_ownername[USER_NAME_LENGTH + 1];
	char    trusted_username[USER_NAME_LENGTH + 1];

	char    is_end_of_peer_phr_owner_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_peer_phr_owner_list_flag;

	sync_emergency_delegation_node_t *ptr_peer_phr_owner_node = NULL;
	list_search_key_params_t         list_search_keys;

	// Peer PHR owner list
	while(1)
	{
		// Receive the peer PHR owner information
		if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving the peer PHR owner information failed\n");
			goto ERROR;
		}

		// Get the delegation information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_peer_phr_owner_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_peer_phr_owner_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_peer_phr_owner_list_flag failed");
		}

		is_end_of_peer_phr_owner_list_flag = (strcmp(is_end_of_peer_phr_owner_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_peer_phr_owner_list_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		{
			int_error("Extracting the phr_ownername failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, trusted_username) != READ_TOKEN_SUCCESS || strcmp(token_name, "trusted_username") != 0)
		{
			int_error("Extracting the trusted_username failed");
		}

		// Get a peer PHR owner node that corresponds to the specific "phr_ownername" and "trusted_username" if exists in a linked list
		strcpy(list_search_keys.trusted_username, trusted_username);
		strcpy(list_search_keys.phr_ownername, phr_ownername);
		ptr_peer_phr_owner_node = (sync_emergency_delegation_node_t *)list_seek(&sync_peer_phr_owner_node_list, &list_search_keys);

		// If a peer PHR owner node exists then remove from the list, unless insert that the delegation into a database
		if(ptr_peer_phr_owner_node)
		{
printf("[synced phr_owner dgt] = PHR owner: %s, trusted user: %s\n", phr_ownername, trusted_username);
			// Remove a peer PHR owner node from the list
			if(list_delete_at(&sync_peer_phr_owner_node_list, list_locate(&sync_peer_phr_owner_node_list, ptr_peer_phr_owner_node)) < 0)
				int_error("Removing a peer PHR owner node failed");
		}
		else
		{
printf("[new phr_owner dgt] = PHR owner: %s, trusted user: %s\n", phr_ownername, trusted_username);
			// Insert the delegation into a database
			insert_new_delegation(db_conn, phr_ownername, peer_authority_name, trusted_username);
		}
	}

	if(!list_iterator_start(&sync_peer_phr_owner_node_list))
		int_error("Starting list iteration failed");

	// The remaining delegation nodes in the list are the revoked delegations
	while(list_iterator_hasnext(&sync_peer_phr_owner_node_list))
	{
		ptr_peer_phr_owner_node = (sync_emergency_delegation_node_t *)list_iterator_next(&sync_peer_phr_owner_node_list);
printf("[revoke phr_owner dgt] = PHR owner: %s, trusted user: %s\n", ptr_peer_phr_owner_node->phr_ownername, ptr_peer_phr_owner_node->trusted_username);

		// Remove a revoked delegation from a database
		remove_revoked_delegation(db_conn, ptr_peer_phr_owner_node->delegation_id);
	}

	if(!list_iterator_stop(&sync_peer_phr_owner_node_list))
		int_error("Stopping list iteration failed");

	// Remove all nodes from the list
	list_clear(&sync_peer_phr_owner_node_list);
	return true;

ERROR:

	// Remove all nodes from the list
	list_clear(&sync_peer_phr_owner_node_list);
	return false;
}

static void set_delegation_node_rejection_by_trusted_user(MYSQL *db_conn, unsigned int delegation_id)
{
	char stat[SQL_STATEMENT_LENGTH + 1];
	char err_msg[ERR_MSG_LENGTH + 1];

	// Set the "rejection_by_trusted_user_flag" variable
	sprintf(stat, "UPDATE %s SET rejection_by_trusted_user_flag = '1' WHERE delegation_id = %u", EMS__DELEGATIONS, delegation_id);

	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}
}

static boolean synchronize_peer_trusted_user_list(MYSQL *db_conn, SSL *ssl_client)
{
	char    buffer[BUFFER_LENGTH + 1];
	char    token_name[TOKEN_NAME_LENGTH + 1];
	char    trusted_username[USER_NAME_LENGTH + 1];
	char    phr_ownername[USER_NAME_LENGTH + 1];

	char    rejection_by_trusted_user_flag_str_tmp[FLAG_LENGTH + 1];
	boolean rejection_by_trusted_user_flag;

	char    is_end_of_peer_trusted_user_list_flag_str_tmp[FLAG_LENGTH + 1];
	boolean is_end_of_peer_trusted_user_list_flag;

	sync_emergency_delegation_node_t *ptr_peer_trusted_user_node = NULL;
	list_search_key_params_t         list_search_keys;

	// Peer trusted user list
	while(1)
	{
		// Receive the peer trusted user information
		if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
		{
			fprintf(stderr, "Receiving the peer trusted user information failed\n");
			goto ERROR;
		}

		// Get the delegation information tokens from buffer
		if(read_token_from_buffer(buffer, 1, token_name, is_end_of_peer_trusted_user_list_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "is_end_of_peer_trusted_user_list_flag") != 0)
		{
			int_error("Extracting the is_end_of_peer_trusted_user_list_flag failed");
		}

		is_end_of_peer_trusted_user_list_flag = (strcmp(is_end_of_peer_trusted_user_list_flag_str_tmp, "1") == 0) ? true : false;
		if(is_end_of_peer_trusted_user_list_flag)
			break;

		if(read_token_from_buffer(buffer, 2, token_name, trusted_username) != READ_TOKEN_SUCCESS || strcmp(token_name, "trusted_username") != 0)
		{
			int_error("Extracting the trusted_username failed");
		}

		if(read_token_from_buffer(buffer, 3, token_name, rejection_by_trusted_user_flag_str_tmp) 
			!= READ_TOKEN_SUCCESS || strcmp(token_name, "rejection_by_trusted_user_flag") != 0)
		{
			int_error("Extracting the rejection_by_trusted_user_flag failed");
		}

		rejection_by_trusted_user_flag = (strcmp(rejection_by_trusted_user_flag_str_tmp, "1") == 0) ? true : false;

		if(read_token_from_buffer(buffer, 4, token_name, phr_ownername) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_ownername") != 0)
		{
			int_error("Extracting the phr_ownername failed");
		}

		// Get a peer trusted user node that corresponds to the specific "phr_ownername" and "trusted_username" if exists in a linked list
		strcpy(list_search_keys.trusted_username, trusted_username);
		strcpy(list_search_keys.phr_ownername, phr_ownername);
		ptr_peer_trusted_user_node = (sync_emergency_delegation_node_t *)list_seek(&sync_peer_trusted_user_node_list, &list_search_keys);

		// If a peer trusted user node exists then update the "rejection_by_trusted_user_flag" 
		// in a database and remove node from the list, unless ignore and consider the next packet
		if(ptr_peer_trusted_user_node)
		{
printf("[synced trusted_user dgt] = PHR owner: %s, trusted user: %s\n", phr_ownername, trusted_username);
			
			if(rejection_by_trusted_user_flag)
			{
				// Set the "rejection_by_trusted_user_flag" variable in a database
				set_delegation_node_rejection_by_trusted_user(db_conn, ptr_peer_trusted_user_node->delegation_id);				
			}

			// Remove a peer trusted user node from the list
			if(list_delete_at(&sync_peer_trusted_user_node_list, list_locate(&sync_peer_trusted_user_node_list, ptr_peer_trusted_user_node)) < 0)
				int_error("Removing a peer trusted user node failed");
		}
	}

	// The remaining delegation nodes are ignored
	// Remove all nodes from the list
	list_clear(&sync_peer_trusted_user_node_list);
	return true;

ERROR:

	// Remove all nodes from the list
	list_clear(&sync_peer_trusted_user_node_list);
	return false;
}

static boolean process_synchronization(SSL *ssl_client)
{
	MYSQL *db_conn = NULL;
	char  buffer[BUFFER_LENGTH + 1];
	char  token_name[TOKEN_NAME_LENGTH + 1];
	char  peer_authority_name[AUTHORITY_NAME_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	init_synchronization_module();

	// Receive peer authority name
	if(SSL_recv_buffer(ssl_client, buffer, NULL) == 0)
	{
		fprintf(stderr, "Receiving peer authority name failed\n");
		goto ERROR;
	}

	// Get a peer authority name token from buffer
	if(read_token_from_buffer(buffer, 1, token_name, peer_authority_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "peer_authority_name") != 0)
	{
		int_error("Extracting the peer_authority_name failed");
	}

	// Load a peer PHR owner list of the desired authority
	prepare_sync_peer_phr_owner_node_list(db_conn, peer_authority_name);

	// Load a peer trusted user list of the desired authority
	prepare_sync_peer_trusted_user_node_list(db_conn, peer_authority_name);

	// Peer PHR owner list
	if(!synchronize_peer_phr_owner_list(db_conn, ssl_client, peer_authority_name))
		goto ERROR;

	// Peer trusted user list
	if(!synchronize_peer_trusted_user_list(db_conn, ssl_client))
		goto ERROR;

	disconnect_db(&db_conn);
	uninit_synchronization_module();
	return true;

ERROR:

	disconnect_db(&db_conn);
	uninit_synchronization_module();
	return false;
}

void *synchronization_receiving_main(void *arg)
{
	BIO     *bio_acc    = NULL;
	BIO     *bio_client = NULL;
    	SSL     *ssl_client = NULL;
    	SSL_CTX *ctx        = NULL;

	int     err;
	char    *host[1];

    	ctx = setup_server_ctx(EMS_CERTFILE_PATH, EMS_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(EMS_DELEGATION_SYNCHRONIZATION_RECEIVING_PORT);
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

		host[0] = USER_AUTH_CN; 
    		if((err = post_connection_check(ssl_client, host, 1, true, GLOBAL_authority_name)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Process Synchronization
		if(!process_synchronization(ssl_client))
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




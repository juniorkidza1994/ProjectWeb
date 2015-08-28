#include "PHRsv_common.h"

#define SGN_ACCESS_GRANTING_TICKET_PATH "PHRsv_cache/PHRsv_phr_services.sgn_access_granting_ticket"
#define ACCESS_GRANTING_TICKET_PATH     "PHRsv_cache/PHRsv_phr_services.access_granting_ticket"

#define GENERATING_PHR_FILENAME         "PHRsv_cache/PHRsv_phr_services.generating_phr_filename"

// Local Function Prototypes
static boolean do_phr_files_of_desired_phr_owner_exist(MYSQL *db_conn, unsigned int phr_owner_id);
static boolean do_phr_owners_of_desired_authority_exist(MYSQL *db_conn, unsigned int authority_id);
static void respond_phr_deletion(active_phr_node_t *ptr_active_node, SSL *ssl_client, boolean send_notification_msg_flag);
static void set_hidden_phr(active_phr_node_t *ptr_active_node);
static void respond_phr_deletion_request(active_phr_node_t *ptr_active_node, SSL *ssl_client);
static void respond_phr_downloading(active_phr_node_t *ptr_active_node, SSL *ssl_client);
static void respond_phr_downloading_request(active_phr_node_t *ptr_active_node, SSL *ssl_client);
static boolean respond_phr_uploading(active_phr_node_t *ptr_active_node, SSL *ssl_client, char *phr_filename);
static void respond_phr_uploading_request(active_phr_node_t *ptr_active_node, SSL *ssl_client, char *phr_filename);
static boolean check_phr_existence(unsigned int phr_id, char *phr_owner_name, char *phr_owner_authority_name);
static void init_active_node_for_phr_downloading_or_deletion_task(active_phr_node_t *active_node, unsigned int phr_id);
static void init_active_node_for_phr_uploading_task(active_phr_node_t *active_node, unsigned int phr_id);
static unsigned int get_authority_id(char *authority_name);   // If an authority name does not exist then add it and return its id
static unsigned int get_phr_owner_id(char *phr_owner_name, char *phr_owner_authority_name);  // If a PHR owner does not exist then add it and return its id
static unsigned int insert_new_phr_index(char *phr_owner_name, char *phr_owner_authority_name, char *phr_filename);
static void dispatch_work(SSL *ssl_client, char *phr_owner_name, char *phr_owner_authority_name, char *required_operation);
static void *respond_phr_service_for_user_main(void *arg);
static void *respond_phr_service_for_emergency_server_main(void *arg);

// Implementation
static boolean do_phr_files_of_desired_phr_owner_exist(MYSQL *db_conn, unsigned int phr_owner_id)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	boolean   found = false;

	// Query for PHR id
	sprintf(stat, "SELECT phr_id FROM %s WHERE phr_owner_id = %u", PHRSV__DATA, phr_owner_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(row)
	{
		found = true;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return found;
}

static boolean do_phr_owners_of_desired_authority_exist(MYSQL *db_conn, unsigned int authority_id)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	boolean   found = false;

	// Query for PHR owner id
	sprintf(stat, "SELECT phr_owner_id FROM %s WHERE authority_id = %u", PHRSV__PHR_OWNERS, authority_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	result = mysql_store_result(db_conn);
	row    = mysql_fetch_row(result);

	if(row)
	{
		found = true;
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return found;
}

// "ssl_client" can be NULL if "send_notification_msg_flag" is false
static void respond_phr_deletion(active_phr_node_t *ptr_active_node, SSL *ssl_client, boolean send_notification_msg_flag)
{
	if(send_notification_msg_flag && ssl_client == NULL)
		int_error("\"ssl_client\" is NULL");

	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	boolean      is_phr_available_to_delete_flag = false;
	char         phr_filename[SHA1_DIGEST_LENGTH + 1];
	char         phr_file_path[PATH_LENGTH + 1];

	unsigned int phr_owner_id = 0;
	unsigned int authority_id = 0;

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query the filename index, PHR owner id and authority id
	sprintf(stat, "SELECT DATA.filename_index, DATA.phr_owner_id, OWNER.authority_id FROM %s DATA, %s OWNER WHERE DATA.phr_id = %u AND "
		"DATA.phr_owner_id = OWNER.phr_owner_id", PHRSV__DATA, PHRSV__PHR_OWNERS, ptr_active_node->phr_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	if(row)
	{
		is_phr_available_to_delete_flag = true;
		strcpy(phr_filename, row[0]);
		phr_owner_id = atoi(row[1]);
		authority_id = atoi(row[2]);
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	if(!is_phr_available_to_delete_flag)
		goto PHR_HAS_BEEN_DELETED;

	// Generate a PHR file path
	sprintf(phr_file_path, "%s/%s", PHR_DIRECTORY_PATH, phr_filename);

	// Delete a PHR file
	unlink(phr_file_path);

	// Delete the PHR record from the database
	sprintf(stat, "DELETE FROM %s WHERE phr_id = %u", PHRSV__DATA, ptr_active_node->phr_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}

	if(!do_phr_files_of_desired_phr_owner_exist(db_conn, phr_owner_id))
	{
		// Delete this PHR owner from the database
		sprintf(stat, "DELETE FROM %s WHERE phr_owner_id = %u", PHRSV__PHR_OWNERS, phr_owner_id);
		if(mysql_query(db_conn, stat))
		{
			sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
			int_error(err_msg);
		}

		if(!do_phr_owners_of_desired_authority_exist(db_conn, authority_id))
		{
			// Delete this authority from the database
			sprintf(stat, "DELETE FROM %s WHERE authority_id = %u", PHRSV__AUTHORITIES, authority_id);
			if(mysql_query(db_conn, stat))
			{
				sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
				int_error(err_msg);
			}
		}
	}

	disconnect_db(&db_conn);

	if(send_notification_msg_flag)
	{
		char buffer[BUFFER_LENGTH + 1];

		// Send the "is_requested_phr_available_to_delete_flag"
		write_token_into_buffer("is_requested_phr_available_to_delete_flag", "1", true, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
			fprintf(stderr, "Sending the is_requested_phr_available_to_delete_flag failed\n");
	}

	return;

PHR_HAS_BEEN_DELETED:

	disconnect_db(&db_conn);

	if(send_notification_msg_flag)
	{
		char buffer[BUFFER_LENGTH + 1];

		// Send the "is_requested_phr_available_to_delete_flag"
		write_token_into_buffer("is_requested_phr_available_to_delete_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "The requested PHR has been deleted already", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
			fprintf(stderr, "Sending the is_requested_phr_available_to_delete_flag failed\n");
	}
}

static void set_hidden_phr(active_phr_node_t *ptr_active_node)
{
	MYSQL *db_conn = NULL;
	char  stat[SQL_STATEMENT_LENGTH + 1];
	char  err_msg[ERR_MSG_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Update the "hidden_flag" to '1'
	sprintf(stat, "UPDATE %s SET hidden_flag = '1' WHERE phr_id = %u", PHRSV__DATA, ptr_active_node->phr_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}
	
	disconnect_db(&db_conn);
}

static void respond_phr_deletion_request(active_phr_node_t *ptr_active_node, SSL *ssl_client)
{
	char buffer[BUFFER_LENGTH + 1];

	if(ptr_active_node == NULL)
		goto ACTIVE_NODE_IS_NULL;

	// working_thread_counter++
	if(sem_wait(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Locking the mutex failed");

	ptr_active_node->working_thread_counter++;

	if(sem_post(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Unlocking the mutex failed");


	// Unlock the "active_PHR_node_list"
	if(sem_post(&active_phr_node_list_mutex) != 0)
		int_error("Unlocking the mutex failed");


	// Set a delete flag and if there is no any thread downloading the PHR then delete it
	if(sem_wait(&ptr_active_node->downloading_mutex) != 0)
		int_error("Locking the mutex failed");

	if(sem_wait(&ptr_active_node->deletion_mutex) != 0)
		int_error("Locking the mutex failed");

	ptr_active_node->mark_delete_flag = true;
	set_hidden_phr(ptr_active_node);

	if(ptr_active_node->downloading_thread_counter == 0)
	{
		 respond_phr_deletion(ptr_active_node, ssl_client, true);
	}
	else
	{
		// Send the "is_requested_phr_available_to_delete_flag"
		write_token_into_buffer("is_requested_phr_available_to_delete_flag", "1", true, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
			fprintf(stderr, "Sending the is_requested_phr_available_to_delete_flag failed\n");
	}

	if(sem_post(&ptr_active_node->deletion_mutex) != 0)
		int_error("Unlocking the mutex failed");

	if(sem_post(&ptr_active_node->downloading_mutex) != 0)
		int_error("Unlocking the mutex failed");

	
	// working_thread_counter--
	if(sem_wait(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Locking the mutex failed");

	ptr_active_node->working_thread_counter--;

	if(sem_post(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Unlocking the mutex failed");

	return;

ACTIVE_NODE_IS_NULL:

	// Send the "is_requested_phr_available_to_delete_flag"
	write_token_into_buffer("is_requested_phr_available_to_delete_flag", "0", true, buffer);
	write_token_into_buffer("error_msg", "The requested PHR has been deleted already", false, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		fprintf(stderr, "Sending the is_requested_phr_available_to_delete_flag failed\n");

	// Unlock the "active_PHR_node_list"
	if(sem_post(&active_phr_node_list_mutex) != 0)
		int_error("Unlocking the mutex failed");

	return;
}

static void respond_phr_downloading(active_phr_node_t *ptr_active_node, SSL *ssl_client)
{
	MYSQL     *db_conn = NULL;
  	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	boolean   is_phr_available_to_download_flag = false;
	char      phr_filename[SHA1_DIGEST_LENGTH + 1];
	char      phr_file_path[PATH_LENGTH + 1];
	char      file_size_str[INT_TO_STR_DIGITS_LENGTH + 1];
	char      buffer[BUFFER_LENGTH + 1];

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query the filename_index
	sprintf(stat, "SELECT filename_index, file_size FROM %s WHERE phr_id = %u AND hidden_flag = '0'", PHRSV__DATA, ptr_active_node->phr_id);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	if(row)
	{
		is_phr_available_to_download_flag = true;
		strcpy(phr_filename, row[0]);
		strcpy(file_size_str, row[1]);
	}

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);

	if(!is_phr_available_to_download_flag)
		goto PHR_HAS_BEEN_DELETED;

	// Send the "is_requested_phr_available_to_download_flag"
	write_token_into_buffer("is_requested_phr_available_to_download_flag", "1", true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the is_requested_phr_available_to_download_flag failed\n");
		goto ERROR;
	}

	// Send the PHR file size
	write_token_into_buffer("file_size", file_size_str, true, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the file_size failed\n");
		goto ERROR;
	}

	// Generate a PHR file path
	sprintf(phr_file_path, "%s/%s", PHR_DIRECTORY_PATH, phr_filename);

	// Send a PHR file
	if(!SSL_send_large_file(ssl_client, phr_file_path))
	{
		fprintf(stderr, "Sending a PHR file failed\n");
		goto ERROR;
	}

	return;

ERROR:

	return;

PHR_HAS_BEEN_DELETED:

	// Send the "is_requested_phr_available_to_download_flag"
	write_token_into_buffer("is_requested_phr_available_to_download_flag", "0", true, buffer);
	write_token_into_buffer("error_msg", "The requested PHR has been deleted already", false, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		fprintf(stderr, "Sending the is_requested_phr_available_to_download_flag failed\n");

	return;
}

static void respond_phr_downloading_request(active_phr_node_t *ptr_active_node, SSL *ssl_client)
{
	boolean is_requested_phr_available_to_download_flag;
	char    buffer[BUFFER_LENGTH + 1];

	if(ptr_active_node == NULL)
		goto ACTIVE_NODE_IS_NULL;

	// working_thread_counter++
	if(sem_wait(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Locking the mutex failed");

	ptr_active_node->working_thread_counter++;

	if(sem_post(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Unlocking the mutex failed");


	// Unlock the "active_PHR_node_list"
	if(sem_post(&active_phr_node_list_mutex) != 0)
		int_error("Unlocking the mutex failed");


	// Lock downloading_mutex and deletion_mutex
	if(sem_wait(&ptr_active_node->downloading_mutex) != 0)
		int_error("Locking the mutex failed");

	if(sem_wait(&ptr_active_node->deletion_mutex) != 0)
		int_error("Locking the mutex failed");

	is_requested_phr_available_to_download_flag = !ptr_active_node->mark_delete_flag;

	// downloading_thread_counter++
	if(is_requested_phr_available_to_download_flag)
	{
		ptr_active_node->downloading_thread_counter++;
	}


	// Unlock deletion_mutex and downloading_mutex
	if(sem_post(&ptr_active_node->deletion_mutex) != 0)
		int_error("Unlocking the mutex failed");

	if(sem_post(&ptr_active_node->downloading_mutex) != 0)
		int_error("Unlocking the mutex failed");

	if(!is_requested_phr_available_to_download_flag)
		goto PHR_HAS_BEEN_DELETED;

	respond_phr_downloading(ptr_active_node, ssl_client);


	// downloading_thread_counter--
	if(sem_wait(&ptr_active_node->downloading_mutex) != 0)
		int_error("Locking the mutex failed");

	ptr_active_node->downloading_thread_counter--;

	if(sem_wait(&ptr_active_node->deletion_mutex) != 0)
		int_error("Locking the mutex failed");

	if(ptr_active_node->mark_delete_flag && ptr_active_node->downloading_thread_counter == 0)
	{
		 respond_phr_deletion(ptr_active_node, NULL, false);
	}

	if(sem_post(&ptr_active_node->deletion_mutex) != 0)
		int_error("Unlocking the mutex failed");

	if(sem_post(&ptr_active_node->downloading_mutex) != 0)
		int_error("Unlocking the mutex failed");


	// working_thread_counter--
	if(sem_wait(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Locking the mutex failed");

	ptr_active_node->working_thread_counter--;

	if(sem_post(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Unlocking the mutex failed");

	return;

ACTIVE_NODE_IS_NULL:

	// Send the "is_requested_phr_available_to_download_flag"
	write_token_into_buffer("is_requested_phr_available_to_download_flag", "0", true, buffer);
	write_token_into_buffer("error_msg", "The requested PHR has been deleted already", false, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		fprintf(stderr, "Sending the is_requested_phr_available_to_download_flag failed\n");

	// Unlock the "active_PHR_node_list"
	if(sem_post(&active_phr_node_list_mutex) != 0)
		int_error("Unlocking the mutex failed");

	return;

PHR_HAS_BEEN_DELETED:

	// Send the "is_requested_phr_available_to_download_flag"
	write_token_into_buffer("is_requested_phr_available_to_download_flag", "0", true, buffer);
	write_token_into_buffer("error_msg", "The requested PHR has been deleted already", false, buffer);

	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		fprintf(stderr, "Sending the is_requested_phr_available_to_download_flag failed\n");

	// working_thread_counter--
	if(sem_wait(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Locking the mutex failed");

	ptr_active_node->working_thread_counter--;

	if(sem_post(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Unlocking the mutex failed");
}

static boolean respond_phr_uploading(active_phr_node_t *ptr_active_node, SSL *ssl_client, char *phr_filename)
{
	char         buffer[BUFFER_LENGTH + 1];
	char         token_name[TOKEN_NAME_LENGTH + 1];
	char         data_description[DATA_DESCRIPTION_LENGTH + 1];
	char	     phr_conf_level_flag[FLAG_LENGTH + 1];   // 0 - secure level, 1 - restricted level, 2 - exclusive level

	char         phr_file_path[PATH_LENGTH + 1];
	unsigned int file_size;

	MYSQL        *db_conn = NULL;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char         data_description_chunk[DATA_DESCRIPTION_LENGTH*2 + 1];
	char	     query[(SQL_STATEMENT_LENGTH + 1) + (DATA_DESCRIPTION_LENGTH*2 + 1)];
	unsigned int len;
	char	     err_msg[ERR_MSG_LENGTH + 1];

	char         phr_id_str[INT_TO_STR_DIGITS_LENGTH + 1];

	// Generate a PHR file path
	sprintf(phr_file_path, "%s/%s", PHR_DIRECTORY_PATH, phr_filename);

	// Receive a data description
	if(!SSL_recv_buffer(ssl_client, buffer, NULL))
	{
		fprintf(stderr, "Receiving a data description failed\n");
		goto ERROR;
	}

	if(read_token_from_buffer(buffer, 1, token_name, data_description) != READ_TOKEN_SUCCESS || strcmp(token_name, "data_description") != 0)
		int_error("Extracting the data_description failed");

	if(read_token_from_buffer(buffer, 2, token_name, phr_conf_level_flag) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_conf_level_flag") != 0)
		int_error("Extracting the phr_conf_level_flag failed");

	// Receive a PHR file
	if(!SSL_recv_large_file(ssl_client, phr_file_path))
	{
		fprintf(stderr, "Receiving a PHR file failed\n");
		goto ERROR;
	}

	if(!get_file_size(phr_file_path, &file_size))
	{
		fprintf(stderr, "Getting a PHR file size failed\n");
		goto ERROR;
	}

	// Send the PHR id
	sprintf(phr_id_str, "%u", ptr_active_node->phr_id);
	write_token_into_buffer("phr_id", phr_id_str, true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the PHR id failed\n");
		goto ERROR;
	}

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Update the PHR data description, file size, and set the "hidden_flag" to '0'
	sprintf(stat, "UPDATE %s SET data_description = '%%s', file_size = %u, phr_conf_level_flag = '%s', hidden_flag = '0' "
		"WHERE phr_id = %u", PHRSV__DATA, file_size, phr_conf_level_flag, ptr_active_node->phr_id);

	// Take the escaped SQL string
	mysql_real_escape_string(db_conn, data_description_chunk, data_description, strlen(data_description));

	len = snprintf(query, sizeof(query), stat, data_description_chunk);
	if(mysql_real_query(db_conn, query, len))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

	disconnect_db(&db_conn);
	return true;

ERROR:
	// Delete a PHR file
	unlink(phr_file_path);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Delete the PHR record from the database
	sprintf(stat, "DELETE FROM %s WHERE phr_id = %u", PHRSV__DATA, ptr_active_node->phr_id);
	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}

	disconnect_db(&db_conn);		
	return false;
}

static void respond_phr_uploading_request(active_phr_node_t *ptr_active_node, SSL *ssl_client, char *phr_filename)
{
	// working_thread_counter++
	if(sem_wait(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Locking the mutex failed");

	ptr_active_node->working_thread_counter++;

	if(sem_post(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Unlocking the mutex failed");


	// Unlock the "active_PHR_node_list"
	if(sem_post(&active_phr_node_list_mutex) != 0)
		int_error("Unlocking the mutex failed");

	// Upload a PHR
	if(respond_phr_uploading(ptr_active_node, ssl_client, phr_filename))
	{
		// Unlock downloading_mutex and deletion_mutex
		if(sem_post(&ptr_active_node->downloading_mutex) != 0)
			int_error("Unlocking the mutex failed");

		if(sem_post(&ptr_active_node->deletion_mutex) != 0)
			int_error("Unlocking the mutex failed");
	}


	// working_thread_counter--
	if(sem_wait(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Locking the mutex failed");

	ptr_active_node->working_thread_counter--;

	if(sem_post(&ptr_active_node->working_thread_counter_mutex) != 0)
		int_error("Unlocking the mutex failed");
}

static boolean check_phr_existence(unsigned int phr_id, char *phr_owner_name, char *phr_owner_authority_name)
{
	MYSQL     *db_conn = NULL;
  	MYSQL_RES *result  = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	boolean   phr_existence_checking_result = false;

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query the PHR id
	sprintf(stat, "SELECT DATA.phr_id FROM %s DATA, %s OWN, %s AUT WHERE DATA.phr_id = %u AND DATA.hidden_flag = '0' AND DATA.phr_owner_id = OWN.phr_owner_id AND "
		"OWN.username LIKE '%s' COLLATE latin1_general_cs AND OWN.authority_id = AUT.authority_id AND AUT.authority_name LIKE '%s' COLLATE latin1_general_cs", 
		PHRSV__DATA, PHRSV__PHR_OWNERS, PHRSV__AUTHORITIES, phr_id, phr_owner_name, phr_owner_authority_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	if(row)
		phr_existence_checking_result = true;
	else
		phr_existence_checking_result = false;

	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
	return phr_existence_checking_result;
}

static void init_active_node_for_phr_downloading_or_deletion_task(active_phr_node_t *active_node, unsigned int phr_id)
{
	active_node->phr_id = phr_id;

	active_node->working_thread_counter = 0;
	if(sem_init(&active_node->working_thread_counter_mutex, 0, 1) != 0)
		int_error("Initial a mutex failed");

	active_node->downloading_thread_counter = 0;
	active_node->mark_delete_flag           = false;

	if(sem_init(&active_node->downloading_mutex, 0, 1) != 0)
		int_error("Initial a mutex failed");

	if(sem_init(&active_node->deletion_mutex, 0, 1) != 0)
		int_error("Initial a mutex failed");
}

static void init_active_node_for_phr_uploading_task(active_phr_node_t *active_node, unsigned int phr_id)
{
	active_node->phr_id = phr_id;

	active_node->working_thread_counter = 0;
	if(sem_init(&active_node->working_thread_counter_mutex, 0, 1) != 0)
		int_error("Initial a mutex failed");

	active_node->downloading_thread_counter = 0;
	active_node->mark_delete_flag           = false;

	// Force threads that need to download or delete this PHR due to the PHR is uploaded completely yet 
	if(sem_init(&active_node->downloading_mutex, 0, 0) != 0)
		int_error("Initial a mutex failed");

	if(sem_init(&active_node->deletion_mutex, 0, 0) != 0)
		int_error("Initial a mutex failed");
}

// If an authority name does not exist then add it and return its id
static unsigned int get_authority_id(char *authority_name)
{
	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int authority_id;

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query the authority id
	sprintf(stat, "SELECT authority_id FROM %s WHERE authority_name LIKE '%s' COLLATE latin1_general_cs", PHRSV__AUTHORITIES, authority_name);
	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	// An authority name does not exist in database then insert it and get its id
	if(!row)
	{
		if(result)
		{
			mysql_free_result(result);
			result = NULL;
		}

		// Insert authority name and get its id
		sprintf(stat, "INSERT INTO %s(authority_name) VALUES('%s')", PHRSV__AUTHORITIES, authority_name);
		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

		// Query the authority id
		sprintf(stat, "SELECT authority_id FROM %s WHERE authority_name LIKE '%s' COLLATE latin1_general_cs", PHRSV__AUTHORITIES, authority_name);
		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

	  	result = mysql_store_result(db_conn);
	  	row = mysql_fetch_row(result);

		if(!row)
			int_error("Getting an authority id from the database failed");
	}

	authority_id = atoi(row[0]);
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
	return authority_id;
}

// If a PHR owner does not exist then add it and return its id
static unsigned int get_phr_owner_id(char *phr_owner_name, char *phr_owner_authority_name)
{
	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int phr_owner_authority_id;
	unsigned int phr_owner_id;

	phr_owner_authority_id = get_authority_id(phr_owner_authority_name);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Query the phr owner id
	sprintf(stat, "SELECT phr_owner_id FROM %s WHERE authority_id = %u AND username LIKE '%s' "
		"COLLATE latin1_general_cs", PHRSV__PHR_OWNERS, phr_owner_authority_id, phr_owner_name);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	// A PHR owner does not exist in database then insert it and get its id
	if(!row)
	{
		if(result)
		{
			mysql_free_result(result);
			result = NULL;
		}

		// Insert phr owner information and get its id
		sprintf(stat, "INSERT INTO %s(authority_id, username) VALUES(%u, '%s')", PHRSV__PHR_OWNERS, phr_owner_authority_id, phr_owner_name);

		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

		// Query the phr owner id
		sprintf(stat, "SELECT phr_owner_id FROM %s WHERE authority_id = %u AND username LIKE '%s' "
			"COLLATE latin1_general_cs", PHRSV__PHR_OWNERS, phr_owner_authority_id, phr_owner_name);

		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

	  	result = mysql_store_result(db_conn);
	  	row = mysql_fetch_row(result);

		if(!row)
			int_error("Getting a PHR owner id from the database failed");
	}

	phr_owner_id = atoi(row[0]);
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
	return phr_owner_id;
}

static unsigned int insert_new_phr_index(char *phr_owner_name, char *phr_owner_authority_name, char *phr_filename)
{
	MYSQL        *db_conn = NULL;
  	MYSQL_RES    *result  = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int phr_owner_id;
	unsigned int phr_id;

	phr_owner_id = get_phr_owner_id(phr_owner_name, phr_owner_authority_name);

	// Connect the database
	connect_db(&db_conn, DB_IP, DB_USERNAME, DB_PASSWD, DB_NAME);

	// Insert new PHR index information and get its phr_id
	sprintf(stat, "INSERT INTO %s(phr_owner_id, filename_index, hidden_flag) VALUES(%u, '%s', '1')", PHRSV__DATA, phr_owner_id, phr_filename);

	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      	int_error(err_msg);
	}

	// Query the phr_id
	sprintf(stat, "SELECT phr_id FROM %s WHERE phr_owner_id = %u AND filename_index LIKE '%s' COLLATE latin1_general_cs", PHRSV__DATA, phr_owner_id, phr_filename);

	if(mysql_query(db_conn, stat))
	{
		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
		int_error(err_msg);
	}

	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	if(!row)
		int_error("Getting a PHR id from the database failed");

	phr_id = atoi(row[0]);
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	disconnect_db(&db_conn);
	return phr_id;
}

static void dispatch_work(SSL *ssl_client, char *phr_owner_name, char *phr_owner_authority_name, char *required_operation)
{
	if(strcmp(required_operation, PHR_UPLOADING) == 0)
	{
		char              current_date_time[DATETIME_STR_LENGTH + 1];
		char              phr_filename[SHA1_DIGEST_LENGTH + 1];
		unsigned int      phr_id;

		active_phr_node_t active_node;
		active_phr_node_t *ptr_active_node = NULL;

		// Lock the "active_phr_node_list"
		if(sem_wait(&active_phr_node_list_mutex) != 0)
			int_error("Locking the mutex failed");

		// Generate a PHR filename
		get_current_date_time(current_date_time);
		sum_sha1_from_string(current_date_time, strlen(current_date_time), phr_filename, GENERATING_PHR_FILENAME);	

		// Insert a new PHR index into a database
		phr_id = insert_new_phr_index(phr_owner_name, phr_owner_authority_name, phr_filename);

		// Init an active node
		init_active_node_for_phr_uploading_task(&active_node, phr_id);

		if(list_append(&active_phr_node_list, &active_node) < 0)
			int_error("Appending the linked list failed");

		ptr_active_node = (active_phr_node_t *)list_get_at(&active_phr_node_list, list_size(&active_phr_node_list)-1);
		if(ptr_active_node == NULL)
			int_error("Getting an active node failed");

		respond_phr_uploading_request(ptr_active_node, ssl_client, phr_filename);
	}
	else if(strcmp(required_operation, PHR_DOWNLOADING) == 0 || strcmp(required_operation, PHR_DELETION) == 0)
	{
		char              buffer[BUFFER_LENGTH + 1];
		char              token_name[TOKEN_NAME_LENGTH + 1];
		char              phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
		unsigned int      phr_id;

		active_phr_node_t *ptr_active_node = NULL;

		// Receive a PHR id
		if(!SSL_recv_buffer(ssl_client, buffer, NULL))
		{
			fprintf(stderr, "Receiving a PHR id failed\n");
			goto ERROR;
		}

		// Get a PHR id token from buffer
		if(read_token_from_buffer(buffer, 1, token_name, phr_id_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_id") != 0)
			int_error("Extracting the phr_id failed");

		phr_id = atoi(phr_id_str_tmp);

		// Lock the "active_phr_node_list"
		if(sem_wait(&active_phr_node_list_mutex) != 0)
			int_error("Locking the mutex failed");

		if(check_phr_existence(phr_id, phr_owner_name, phr_owner_authority_name))
		{
			// Get an active node that corresponds "phr_id" if exists on a linked list
			ptr_active_node = (active_phr_node_t *)list_seek(&active_phr_node_list, &phr_id);

			// If an active node exists then skip this fragment code below unless create it
			if(ptr_active_node == NULL)
			{
				active_phr_node_t active_node;

				// Init an active node
				init_active_node_for_phr_downloading_or_deletion_task(&active_node, phr_id);

				if(list_append(&active_phr_node_list, &active_node) < 0)
					int_error("Appending the linked list failed");

				ptr_active_node = (active_phr_node_t *)list_get_at(&active_phr_node_list, list_size(&active_phr_node_list)-1);
				if(ptr_active_node == NULL)
					int_error("Getting an active node failed");
			}
		}

		if(strcmp(required_operation, PHR_DOWNLOADING) == 0)
		{
			respond_phr_downloading_request(ptr_active_node, ssl_client);
		}
		else if(strcmp(required_operation, PHR_DELETION) == 0)
		{
			respond_phr_deletion_request(ptr_active_node, ssl_client);
		}
	}
	else
	{
		fprintf(stderr, "Unknown operation\n");
		goto ERROR;
	}

	return;

ERROR:

	return;
}

static void *respond_phr_service_for_user_main(void *arg)
{
	SSL  *ssl_client = (SSL *)arg;

	char err_msg[ERR_MSG_LENGTH + 1];
	char buffer[BUFFER_LENGTH + 1];
	char access_granting_ticket_buffer[BUFFER_LENGTH + 1];

	char token_name[TOKEN_NAME_LENGTH + 1];
	char desired_phr_owner_name[USER_NAME_LENGTH + 1];
	char desired_phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char required_operation[PHR_OPERATION_NAME_LENGTH + 1];

	char requestor_authority_name[AUTHORITY_NAME_LENGTH + 1];
	char requestor_name[USER_NAME_LENGTH + 1];

	// Receive a request information
	if(!SSL_recv_buffer(ssl_client, buffer, NULL))
	{
		fprintf(stderr, "Receiving a request information failed\n");
		goto ERROR_BEFORE_RELEASE_WAIT_MUTEX;
	}

	// Get request information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, desired_phr_owner_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "desired_phr_owner_name") != 0)
		int_error("Extracting the desired_phr_owner_name failed");

	if(read_token_from_buffer(buffer, 2, token_name, desired_phr_owner_authority_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "desired_phr_owner_authority_name") != 0)
	{
		int_error("Extracting the desired_phr_owner_authority_name failed");
	}

	if(read_token_from_buffer(buffer, 3, token_name, required_operation) != READ_TOKEN_SUCCESS || strcmp(token_name, "required_operation") != 0)
		int_error("Extracting the required_operation failed");

	// Receive the access granting ticket
	if(!SSL_recv_file(ssl_client, SGN_ACCESS_GRANTING_TICKET_PATH))
	{
		fprintf(stderr, "Receiving an access granting ticket failed\n");
		goto ERROR_BEFORE_RELEASE_WAIT_MUTEX;
	}

	// Verify the access granting ticket with the server CA's public key
	if(!smime_verify_with_cert(SGN_ACCESS_GRANTING_TICKET_PATH, ACCESS_GRANTING_TICKET_PATH, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH, err_msg))
	{
		// Send the PHR access permission verification result flag
		write_token_into_buffer("phr_access_permission_verification_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Verifying the access granting ticket signature failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the PHR access permission verification result flag failed\n");
			goto ERROR_BEFORE_RELEASE_WAIT_MUTEX;
		}

		goto ERROR_BEFORE_RELEASE_WAIT_MUTEX;
	}

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);

	// Read the access granting ticket info into a buffer
	if(!read_bin_file(ACCESS_GRANTING_TICKET_PATH, access_granting_ticket_buffer, sizeof(access_granting_ticket_buffer), NULL))
	{
		fprintf(stderr, "Reading the access granting ticket info failed\n");
		goto ERROR_BEFORE_RELEASE_WAIT_MUTEX;
	}

	unlink(ACCESS_GRANTING_TICKET_PATH);

	// Release the critical section, so that the main thread can serve new incoming requests
	if(sem_post(&wait_for_creating_new_child_thread_mutex) != 0)
		int_error("Signaling for creating the thread \"respond_phr_service_for_user_main\" failed");

	get_cert_owner_info(ssl_client, requestor_authority_name, requestor_name);

	// Verifications
	if(!verify_access_granting_ticket(access_granting_ticket_buffer, requestor_name, 
		requestor_authority_name, desired_phr_owner_name, desired_phr_owner_authority_name))
	{		
		// Send the PHR access permission verification result flag
		write_token_into_buffer("phr_access_permission_verification_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Verifying the access granting ticket failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the PHR access permission verification result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	if(!verify_access_granting_ticket_lifetime(access_granting_ticket_buffer))
	{		
		// Send the PHR access permission verification result flag
		write_token_into_buffer("phr_access_permission_verification_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Verifying the access granting ticket lifetime failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the PHR access permission verification result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	if(!verify_access_permission(access_granting_ticket_buffer, required_operation))
	{		
		// Send the PHR access permission verification result flag
		write_token_into_buffer("phr_access_permission_verification_result_flag", "0", true, buffer);
		write_token_into_buffer("error_msg", "Verifying the access permission failed", false, buffer);

		if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
		{
			fprintf(stderr, "Sending the PHR access permission verification result flag failed\n");
			goto ERROR;
		}

		goto ERROR;
	}

	// Send the PHR access permission verification result flag
	write_token_into_buffer("phr_access_permission_verification_result_flag", "1", true, buffer);
	if(!SSL_send_buffer(ssl_client, buffer, strlen(buffer)))
	{
		fprintf(stderr, "Sending the PHR access permission verification result flag failed\n");
		goto ERROR;
	}

	// Process the request
	dispatch_work(ssl_client, desired_phr_owner_name, desired_phr_owner_authority_name, required_operation);

	SSL_cleanup(ssl_client);
	ssl_client = NULL;

	// Increase the counter
	if(sem_post(&remaining_operating_thread_counter_sem) != 0)
		int_error("Posting the counter \"remaining_operating_thread_counter_sem\" failed");

	pthread_exit(NULL);
    	return NULL;

ERROR_BEFORE_RELEASE_WAIT_MUTEX:

	// Release the critical section, so that the main thread can serve new incoming requests
	if(sem_post(&wait_for_creating_new_child_thread_mutex) != 0)
		int_error("Signaling for creating the thread \"respond_phr_service_for_user_main\" failed");

ERROR:

	unlink(SGN_ACCESS_GRANTING_TICKET_PATH);
	unlink(ACCESS_GRANTING_TICKET_PATH);

	if(ssl_client)
	{
		SSL_cleanup(ssl_client);
		ssl_client = NULL;
	}

	// Increase the counter
	if(sem_post(&remaining_operating_thread_counter_sem) != 0)
		int_error("Posting the counter \"remaining_operating_thread_counter_sem\" failed");

	pthread_exit(NULL);
    	return NULL;
}

static void *respond_phr_service_for_emergency_server_main(void *arg)
{
	SSL               *ssl_client = (SSL *)arg;

	char              buffer[BUFFER_LENGTH + 1];
	char              token_name[TOKEN_NAME_LENGTH + 1];
	char              desired_phr_owner_name[USER_NAME_LENGTH + 1];
	char              desired_phr_owner_authority_name[AUTHORITY_NAME_LENGTH + 1];

	char              phr_id_str_tmp[INT_TO_STR_DIGITS_LENGTH + 1];
	unsigned int      phr_id;

	active_phr_node_t *ptr_active_node = NULL;

	// Release the critical section, so that the main thread can serve new incoming requests
	if(sem_post(&wait_for_creating_new_child_thread_mutex) != 0)
		int_error("Signaling for creating the thread \"respond_phr_service_for_emergency_server_main\" failed");

	// Receive the request information
	if(!SSL_recv_buffer(ssl_client, buffer, NULL))
	{
		fprintf(stderr, "Receiving a request information failed\n");
		goto ERROR;
	}

	// Get request information tokens from buffer
	if(read_token_from_buffer(buffer, 1, token_name, desired_phr_owner_name) != READ_TOKEN_SUCCESS || strcmp(token_name, "desired_phr_owner_name") != 0)
		int_error("Extracting the desired_phr_owner_name failed");

	if(read_token_from_buffer(buffer, 2, token_name, desired_phr_owner_authority_name) 
		!= READ_TOKEN_SUCCESS || strcmp(token_name, "desired_phr_owner_authority_name") != 0)
	{
		int_error("Extracting the desired_phr_owner_authority_name failed");
	}

	if(read_token_from_buffer(buffer, 3, token_name, phr_id_str_tmp) != READ_TOKEN_SUCCESS || strcmp(token_name, "phr_id") != 0)
		int_error("Extracting the phr_id failed");

	phr_id = atoi(phr_id_str_tmp);

	// Lock the "active_phr_node_list"
	if(sem_wait(&active_phr_node_list_mutex) != 0)
		int_error("Locking the mutex failed");

	if(check_phr_existence(phr_id, desired_phr_owner_name, desired_phr_owner_authority_name))
	{
		// Get an active node that corresponds "phr_id" if exists on a linked list
		ptr_active_node = (active_phr_node_t *)list_seek(&active_phr_node_list, &phr_id);

		// If an active node exists then skip this fragment code below unless create it
		if(ptr_active_node == NULL)
		{
			active_phr_node_t active_node;

			// Init an active node
			init_active_node_for_phr_downloading_or_deletion_task(&active_node, phr_id);

			if(list_append(&active_phr_node_list, &active_node) < 0)
				int_error("Appending the linked list failed");

			ptr_active_node = (active_phr_node_t *)list_get_at(&active_phr_node_list, list_size(&active_phr_node_list)-1);
			if(ptr_active_node == NULL)
				int_error("Getting an active node failed");
		}
	}

	respond_phr_downloading_request(ptr_active_node, ssl_client);

	SSL_cleanup(ssl_client);
	ssl_client = NULL;

	// Increase the counter
	if(sem_post(&remaining_operating_thread_counter_sem) != 0)
		int_error("Posting the counter \"remaining_operating_thread_counter_sem\" failed");

	pthread_exit(NULL);
    	return NULL;

ERROR:

	if(ssl_client)
	{
		SSL_cleanup(ssl_client);
		ssl_client = NULL;
	}

	// Increase the counter
	if(sem_post(&remaining_operating_thread_counter_sem) != 0)
		int_error("Posting the counter \"remaining_operating_thread_counter_sem\" failed");

	pthread_exit(NULL);
    	return NULL;
}

void *phr_services_main(void *arg)
{
	BIO         *bio_acc    = NULL;
	BIO         *bio_client = NULL;
    	SSL         *ssl_client = NULL;
    	SSL_CTX     *ctx        = NULL;

	int         err;
	char        *hosts[2];

	THREAD_TYPE child_thread_id;

	char        requestor_authority_name[AUTHORITY_NAME_LENGTH + 1];
	entity_type user_or_server_type;

    	ctx = setup_server_ctx(PHRSV_CERTFILE_PATH, PHRSV_CERTFILE_PASSWD, PHR_ROOT_CA_ONLY_CERT_CERTFILE_PATH);
    	bio_acc = BIO_new_accept(PHRSV_PHR_SERVICES_PORT);
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

		hosts[0] = USER_CN;
		hosts[1] = EMERGENCY_SERVER_CN; 
    		if((err = post_connection_check(ssl_client, hosts, 2, false, NULL)) != X509_V_OK)
    		{
        		fprintf(stderr, "Checking peer certificate failed\n\"%s\"\n", X509_verify_cert_error_string(err));
        		goto ERROR_AT_SSL_LAYER;
    		}

		// Get a certificate's entity type
		get_cert_owner_info(ssl_client, requestor_authority_name, NULL);
		get_cert_ownername(ssl_client, requestor_authority_name, NULL, &user_or_server_type);

		// Pass and decrease the counter if the counter > 0, unless block until some thread increase the counter
		if(sem_wait(&remaining_operating_thread_counter_sem) != 0)
			int_error("Waiting the counter \"remaining_operating_thread_counter_sem\" failed");

		if(user_or_server_type == user)
		{
			// Create a child thread
			if(THREAD_CREATE(child_thread_id, respond_phr_service_for_user_main, (void *)ssl_client) != 0)
				int_error("Creating a thread for \"respond_phr_service_for_user_main\" failed");

			// Wait for creating the new child thread
			if(sem_wait(&wait_for_creating_new_child_thread_mutex) != 0)
				int_error("Waiting for creating the thread \"respond_phr_service_for_user_main\" failed");
		}
		else if(user_or_server_type == server)  // Emergency Server
		{
			// Create a child thread
			if(THREAD_CREATE(child_thread_id, respond_phr_service_for_emergency_server_main, (void *)ssl_client) != 0)
				int_error("Creating a thread for \"respond_phr_service_for_emergency_server_main\" failed");

			// Wait for creating the new child thread
			if(sem_wait(&wait_for_creating_new_child_thread_mutex) != 0)
				int_error("Waiting for creating the thread \"respond_phr_service_for_emergency_server_main\" failed");
		}

		// Detaching a child thread in order to allow the system automatically reclaims resources when the detached thread exits
		if(THREAD_DETACH(child_thread_id) != 0)
			int_error("Detaching a thread for \"respond_phr_service_for_emergency_server_main\" failed");

		continue;

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




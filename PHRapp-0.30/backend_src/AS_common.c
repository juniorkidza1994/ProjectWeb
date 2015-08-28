#include "AS_common.h"

// Local Function Prototypes
static unsigned int get_authority_id(MYSQL *db_conn, char *authority_name);  // If authority name does not exist then add it and return its id

// Implementation
static unsigned int get_authority_id(MYSQL *db_conn, char *authority_name)   // If authority name does not exist then add it and return its id
{
  	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int authority_id;

	// Query the authority id
	sprintf(stat, "SELECT authority_id FROM %s WHERE authority_name LIKE '%s' COLLATE latin1_general_cs", AS__AUTHORITIES, authority_name);
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
		sprintf(stat, "INSERT INTO %s(authority_name) VALUES('%s')", AS__AUTHORITIES, authority_name);
		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

		// Query the authority id
		sprintf(stat, "SELECT authority_id FROM %s WHERE authority_name LIKE '%s' COLLATE latin1_general_cs", AS__AUTHORITIES, authority_name);
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

	return authority_id;
}

// If username does not exist then add it and return its id
unsigned int get_user_id(MYSQL *db_conn, char *username, char *authority_name, boolean is_admin_flag)
{
  	MYSQL_RES    *result = NULL;
  	MYSQL_ROW    row;
	char         stat[SQL_STATEMENT_LENGTH + 1];
	char	     err_msg[ERR_MSG_LENGTH + 1];

	unsigned int authority_id;
	unsigned int user_id;

	authority_id = get_authority_id(db_conn, authority_name);

	// Query the user id
	sprintf(stat, "SELECT user_id FROM %s WHERE authority_id = %u AND username LIKE '%s' COLLATE latin1_general_cs "
		"AND is_admin_flag = '%s'", AS__USERS, authority_id, username, (is_admin_flag) ? "1" : "0");

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
  	row = mysql_fetch_row(result);

	// A username does not exist in database then insert it and get its id
	if(!row)
	{
		if(result)
		{
			mysql_free_result(result);
			result = NULL;
		}

		// Insert user information and get its id
		sprintf(stat, "INSERT INTO %s(authority_id, username, is_admin_flag) VALUES(%u, '%s', '%s')", 
			AS__USERS, authority_id, username, (is_admin_flag) ? "1" : "0");

		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

		// Query the user id
		sprintf(stat, "SELECT user_id FROM %s WHERE authority_id = %u AND username LIKE '%s' COLLATE latin1_general_cs "
			"AND is_admin_flag = '%s'", AS__USERS, authority_id, username, (is_admin_flag) ? "1" : "0");

		if(mysql_query(db_conn, stat))
	  	{
	      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
	      		int_error(err_msg);
	  	}

	  	result = mysql_store_result(db_conn);
	  	row = mysql_fetch_row(result);

		if(!row)
			int_error("Getting a user id from the database failed");
	}

	user_id = atoi(row[0]);
	if(result)
	{
		mysql_free_result(result);
		result = NULL;
	}

	return user_id;
}

boolean get_user_info(MYSQL *db_conn, unsigned int user_id, char *username_ret, char *user_authority_name_ret, boolean *is_subject_user_admin_flag_ret)
{
	MYSQL_RES *result = NULL;
  	MYSQL_ROW row;
	char      stat[SQL_STATEMENT_LENGTH + 1];
	char	  err_msg[ERR_MSG_LENGTH + 1];

	sprintf(stat, "SELECT USR.username, AUT.authority_name, USR.is_admin_flag FROM %s USR, %s AUT WHERE USR.user_id = %u "
		"AND USR.authority_id = AUT.authority_id", AS__USERS, AS__AUTHORITIES, user_id);

	if(mysql_query(db_conn, stat))
  	{
      		sprintf(err_msg, "Error %u: %s\n", mysql_errno(db_conn), mysql_error(db_conn));
      		int_error(err_msg);
  	}

  	result = mysql_store_result(db_conn);
	row = mysql_fetch_row(result);

	if(row == NULL)
		goto ERROR;

	strcpy(username_ret, row[0]);
	strcpy(user_authority_name_ret, row[1]);
	*is_subject_user_admin_flag_ret = (strcmp(row[2], "1") == 0) ? true : false;

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




// gcc EmUDB_create_db.c -o emudb_create_phr_db  `mysql_config --cflags --libs` -Wall

#include "common.h"

int main(int argc, char **argv)
{
	MYSQL *conn;
	char stat[SQL_STATEMENT_LENGTH + 1];

  	conn = mysql_init(NULL);
  	if(!conn) 
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Connect a database
  	if(mysql_real_connect(conn, DB_IP, DB_USERNAME, DB_PASSWD, NULL, 0, NULL, 0) == NULL) 
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Re-create a database
	sprintf(stat, "DROP DATABASE IF EXISTS %s", EMUDB_NAME);
  	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	sprintf(stat, "CREATE DATABASE %s", EMUDB_NAME);
	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Select a database
	if(mysql_select_db(conn, EMUDB_NAME) != 0)
	{
		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
	}

	// Create an ESA__BASIC_AUTHORITY_INFO table
	sprintf(stat, "CREATE TABLE %s("
			"authority_name			VARCHAR(%d)		NOT NULL, "
			"mail_server_url		VARCHAR(%d)		NOT NULL, "
			"authority_email_address	VARCHAR(%d)		NOT NULL, "
			"authority_email_passwd		VARCHAR(%d)		NOT NULL)"
			, ESA__BASIC_AUTHORITY_INFO, AUTHORITY_NAME_LENGTH, URL_LENGTH, EMAIL_ADDRESS_LENGTH, PASSWD_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an ESA__ADMINS table
	sprintf(stat, "CREATE TABLE %s("
			"admin_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
		      	"username	  		VARCHAR(%d)  		NOT NULL, "
			"salted_passwd_hash	  	CHAR(%d)  		NOT NULL, "
			"salt_value	  		CHAR(%d)  		NOT NULL, "
			"email_address	  		VARCHAR(%d)  		NOT NULL, "
			"passwd_resetting_code	  	CHAR(%d)  		NOT NULL, "
			"enc_ssl_cert			MEDIUMBLOB		NULL, "
			"enc_ssl_cert_hash	  	CHAR(%d)  		NULL)"
			, ESA__ADMINS, USER_NAME_LENGTH, SHA1_DIGEST_LENGTH, SALT_VALUE_LENGTH, 
			EMAIL_ADDRESS_LENGTH, PASSWD_RESETTING_CODE_LENGTH, SHA1_DIGEST_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an ESA__USERS table
	sprintf(stat, "CREATE TABLE %s("
			"user_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
		      	"username	  		VARCHAR(%d)  		NOT NULL, "
			"salted_passwd_hash	  	CHAR(%d)  		NOT NULL, "
			"salt_value	  		CHAR(%d)  		NOT NULL, "
			"email_address	  		VARCHAR(%d)  		NOT NULL, "
			"passwd_resetting_code	  	CHAR(%d)  		NOT NULL, "
			"enc_ssl_cert			MEDIUMBLOB		NULL, "
			"enc_ssl_cert_hash	  	CHAR(%d)  		NULL)"
			, ESA__USERS, USER_NAME_LENGTH, SHA1_DIGEST_LENGTH, SALT_VALUE_LENGTH, 
			EMAIL_ADDRESS_LENGTH, PASSWD_RESETTING_CODE_LENGTH, SHA1_DIGEST_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an ESA__PHR_AUTHORITIES table
	sprintf(stat, "CREATE TABLE %s("
			"phr_authority_id		INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
		      	"phr_authority_name	  	VARCHAR(%d)  		NOT NULL, "
			"emergency_server_ip_addr	VARCHAR(%d)		NULL)"
			, ESA__PHR_AUTHORITIES, AUTHORITY_NAME_LENGTH, IP_ADDRESS_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	mysql_close(conn);
	return 0;
}




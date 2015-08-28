// gcc PHRDB_create_db.c -o phrdb_create_phr_db  `mysql_config --cflags --libs` -Wall

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
	sprintf(stat, "DROP DATABASE IF EXISTS %s", PHRDB_NAME);
  	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	sprintf(stat, "CREATE DATABASE %s", PHRDB_NAME);
	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Select a database
	if(mysql_select_db(conn, PHRDB_NAME) != 0)
	{
		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
	}

	// Create a UA__BASIC_AUTHORITY_INFO table
	sprintf(stat, "CREATE TABLE %s("
		      	"authority_id	  		INTEGER UNSIGNED  	NOT NULL, "
			"audit_server_ip_addr		VARCHAR(%d)		NOT NULL, "
			"phr_server_ip_addr		VARCHAR(%d)		NOT NULL, "
			"emergency_server_ip_addr	VARCHAR(%d)		NOT NULL, "
			"mail_server_url		VARCHAR(%d)		NOT NULL, "
			"authority_email_address	VARCHAR(%d)		NOT NULL, "
			"authority_email_passwd		VARCHAR(%d)		NOT NULL)"
			, UA__BASIC_AUTHORITY_INFO, IP_ADDRESS_LENGTH, IP_ADDRESS_LENGTH, IP_ADDRESS_LENGTH, URL_LENGTH, EMAIL_ADDRESS_LENGTH, PASSWD_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create a UA__AUTHORITIES table
	sprintf(stat, "CREATE TABLE %s("
			"authority_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
		      	"authority_name	  		VARCHAR(%d)  		NOT NULL, "
			"user_auth_ip_addr		VARCHAR(%d)		NOT NULL, "
			"emergency_server_ip_addr	VARCHAR(%d)		NULL, "
			"authority_join_flag		CHAR(%d)		NOT NULL)"
			, UA__AUTHORITIES, AUTHORITY_NAME_LENGTH, IP_ADDRESS_LENGTH, IP_ADDRESS_LENGTH, FLAG_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create a UA__ATTRIBUTES table
	sprintf(stat, "CREATE TABLE %s("
			"attribute_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
		      	"attribute_name	  		VARCHAR(%d)  		NOT NULL, "
			"is_numerical_attribute_flag	CHAR(%d)		NOT NULL, "
			"authority_id			INTEGER UNSIGNED	NOT NULL)"
			, UA__ATTRIBUTES, ATTRIBUTE_NAME_LENGTH, FLAG_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create a UA__ADMINS table
	sprintf(stat, "CREATE TABLE %s("
			"admin_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
		      	"username	  		VARCHAR(%d)  		NOT NULL, "
			"salted_passwd_hash	  	CHAR(%d)  		NOT NULL, "
			"salt_value	  		CHAR(%d)  		NOT NULL, "
			"email_address	  		VARCHAR(%d)  		NOT NULL, "
			"passwd_resetting_code	  	CHAR(%d)  		NOT NULL, "
			"enc_ssl_cert			MEDIUMBLOB		NULL, "
			"enc_ssl_cert_hash	  	CHAR(%d)  		NULL)"
			, UA__ADMINS, USER_NAME_LENGTH, SHA1_DIGEST_LENGTH, SALT_VALUE_LENGTH, 
			EMAIL_ADDRESS_LENGTH, PASSWD_RESETTING_CODE_LENGTH, SHA1_DIGEST_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create a UA__USERS table
	sprintf(stat, "CREATE TABLE %s("
			"user_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
		      	"username	  		VARCHAR(%d)  		NOT NULL, "
			"salted_passwd_hash	  	CHAR(%d)  		NOT NULL, "
			"salt_value	  		CHAR(%d)  		NOT NULL, "
			"email_address	  		VARCHAR(%d)  		NOT NULL, "
			"passwd_resetting_code	  	CHAR(%d)  		NOT NULL, "
			"ssl_pub_key			VARCHAR(%d)		NULL, "
			"enc_ssl_cert			MEDIUMBLOB		NULL, "
			"enc_ssl_cert_hash	  	CHAR(%d)  		NULL, "
			"enc_cpabe_priv_key		MEDIUMBLOB		NULL, "
			"enc_cpabe_priv_key_hash	CHAR(%d)  		NULL)"
			, UA__USERS, USER_NAME_LENGTH, SHA1_DIGEST_LENGTH, SALT_VALUE_LENGTH, EMAIL_ADDRESS_LENGTH, 
			PASSWD_RESETTING_CODE_LENGTH, SSL_PUB_KEY_LENGTH, SHA1_DIGEST_LENGTH, SHA1_DIGEST_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create a UA__USER_ATTRIBUTES table
	sprintf(stat, "CREATE TABLE %s("
			"user_attribute_id		INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
			"user_id			INTEGER UNSIGNED	NOT NULL, "
			"attribute_id			INTEGER UNSIGNED	NOT NULL, "
			"attribute_value		INTEGER UNSIGNED	NULL)"
			, UA__USER_ATTRIBUTES);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create a UA__ACCESS_PERMISSIONS table
	sprintf(stat, "CREATE TABLE %s("
			"access_permission_id		INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
			"user_id			INTEGER UNSIGNED	NOT NULL, "
			"phr_owner_id			INTEGER UNSIGNED	NOT NULL, "
			"phr_owner_authority_id		INTEGER UNSIGNED	NOT NULL, "
			"upload_permission_flag		CHAR(%d)		NOT NULL, "
			"download_permission_flag	CHAR(%d)		NOT NULL, "
			"delete_permission_flag		CHAR(%d)		NOT NULL)"
			, UA__ACCESS_PERMISSIONS, FLAG_LENGTH, FLAG_LENGTH, FLAG_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create a UA__PERMISSIONS_ASSIGNED_TO_OTHERS table
	sprintf(stat, "CREATE TABLE %s("
			"assigned_permission_id		INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
			"user_id			INTEGER UNSIGNED	NOT NULL, "
			"object_user_id			INTEGER UNSIGNED	NOT NULL, "
			"object_user_authority_id	INTEGER UNSIGNED	NOT NULL, "
			"upload_permission_flag		CHAR(%d)		NOT NULL, "
			"download_permission_flag	CHAR(%d)		NOT NULL, "
			"delete_permission_flag		CHAR(%d)		NOT NULL)"
			, UA__PERMISSIONS_ASSIGNED_TO_OTHERS, FLAG_LENGTH, FLAG_LENGTH, FLAG_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create a UA__USERS_IN_OTHER_AUTHORITIES table
	sprintf(stat, "CREATE TABLE %s("
			"user_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
			"authority_id			INTEGER UNSIGNED	NOT NULL, "
		      	"username	  		VARCHAR(%d)  		NOT NULL, "
			"email_address			VARCHAR(%d)		NOT NULL, "
			"ssl_pub_key			VARCHAR(%d)		NOT NULL)"
			, UA__USERS_IN_OTHER_AUTHORITIES, USER_NAME_LENGTH, EMAIL_ADDRESS_LENGTH, SSL_PUB_KEY_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an AS__BASIC_AUTHORITY_INFO table
	sprintf(stat, "CREATE TABLE %s("
		      	"authority_id	  		INTEGER UNSIGNED  	NOT NULL)"
			, AS__BASIC_AUTHORITY_INFO);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an AS__AUTHORITIES table
	sprintf(stat, "CREATE TABLE %s("
			"authority_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
		      	"authority_name	  		VARCHAR(%d)  		NOT NULL)"
			, AS__AUTHORITIES, AUTHORITY_NAME_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an AS__USERS table
	sprintf(stat, "CREATE TABLE %s("
			"user_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
			"authority_id			INTEGER UNSIGNED	NOT NULL, "
		      	"username	  		VARCHAR(%d)  		NOT NULL, "
			"is_admin_flag			CHAR(%d)		NOT NULL)"
			, AS__USERS, USER_NAME_LENGTH, FLAG_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an AS__LOGIN_LOGS table
	sprintf(stat, "CREATE TABLE %s("
			"login_log_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
			"user_id			INTEGER UNSIGNED	NOT NULL, "
			"date_time			TIMESTAMP 		NOT NULL, "
			"ip_address			VARCHAR(%d)		NOT NULL, "
			"is_logout_flag			CHAR(%d)		NOT NULL)"
			, AS__LOGIN_LOGS, IP_ADDRESS_LENGTH, FLAG_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an AS__EVENT_LOGS table
	sprintf(stat, "CREATE TABLE %s("
			"event_log_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
			"actor_id			INTEGER UNSIGNED	NOT NULL, "
			"object_owner_id		INTEGER UNSIGNED	NOT NULL, "
			"affected_user_id		INTEGER UNSIGNED	NOT NULL, "
			"object_description		VARCHAR(%d)		NOT NULL, "
			"event_description		VARCHAR(%d)		NOT NULL, "
			"date_time			TIMESTAMP 		NOT NULL DEFAULT CURRENT_TIMESTAMP, "
			"actor_ip_address		VARCHAR(%d)		NOT NULL, "
			"sync_flag			CHAR(%d)		NOT NULL)"
			, AS__EVENT_LOGS, DATA_DESCRIPTION_LENGTH*2+1/* support for taking the escaped SQL string */, 
			EVENT_DESCRIPTION_LENGTH*2+1/* support for taking the escaped SQL string */, IP_ADDRESS_LENGTH, FLAG_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create a PHRSV__AUTHORITIES table
	sprintf(stat, "CREATE TABLE %s("
			"authority_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
		      	"authority_name	  		VARCHAR(%d)  		NOT NULL)"
			, PHRSV__AUTHORITIES, AUTHORITY_NAME_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create a PHRSV__PHR_OWNERS table
	sprintf(stat, "CREATE TABLE %s("
			"phr_owner_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
			"authority_id			INTEGER UNSIGNED	NOT NULL, "
		      	"username	  		VARCHAR(%d)  		NOT NULL)"
			, PHRSV__PHR_OWNERS, USER_NAME_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create a PHRSV__DATA table
	sprintf(stat, "CREATE TABLE %s("
			"phr_id				INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
			"phr_owner_id			INTEGER UNSIGNED	NOT NULL, "
			"data_description		VARCHAR(%d)		NULL, "
			"filename_index			CHAR(%d)		NOT NULL, "
			"file_size			INTEGER UNSIGNED	NULL, "
			"phr_conf_level_flag		CHAR(%d)		NOT NULL, "         // 0 - secure level, 1 - restricted level, 2 - exclusive level
			"hidden_flag			CHAR(%d)		NOT NULL)"
			, PHRSV__DATA, DATA_DESCRIPTION_LENGTH*2+1/* support for taking the escaped SQL string */, SHA1_DIGEST_LENGTH, FLAG_LENGTH, FLAG_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an EMS__BASIC_AUTHORITY_INFO table
	sprintf(stat, "CREATE TABLE %s("
			"authority_id	  		INTEGER UNSIGNED  	NOT NULL, "
			"user_auth_ip_addr		VARCHAR(%d)		NOT NULL, "
			"audit_server_ip_addr		VARCHAR(%d)		NOT NULL, "
			"phr_server_ip_addr		VARCHAR(%d)		NOT NULL, "
			"mail_server_url		VARCHAR(%d)		NOT NULL, "
			"authority_email_address	VARCHAR(%d)		NOT NULL, "
			"authority_email_passwd		VARCHAR(%d)		NOT NULL)"
			, EMS__BASIC_AUTHORITY_INFO, IP_ADDRESS_LENGTH, IP_ADDRESS_LENGTH, IP_ADDRESS_LENGTH, URL_LENGTH, EMAIL_ADDRESS_LENGTH, PASSWD_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an EMS__AUTHORITIES table
	sprintf(stat, "CREATE TABLE %s("
			"authority_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
		      	"authority_name	  		VARCHAR(%d)  		NOT NULL)"
			, EMS__AUTHORITIES, AUTHORITY_NAME_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an EMS__USERS table
	sprintf(stat, "CREATE TABLE %s("
			"user_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
			"authority_id			INTEGER UNSIGNED	NOT NULL, "
		      	"username	  		VARCHAR(%d)  		NOT NULL)"
			, EMS__USERS, USER_NAME_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an EMS__DELEGATIONS table
	sprintf(stat, "CREATE TABLE %s("
			"delegation_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
			"trusted_user_id		INTEGER UNSIGNED	NOT NULL, "
			"rejection_by_trusted_user_flag	CHAR(%d)		NOT NULL, "
		      	"phr_owner_id			INTEGER UNSIGNED	NOT NULL)"
			, EMS__DELEGATIONS, FLAG_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an EMS__SECRET_KEYS table
	sprintf(stat, "CREATE TABLE %s("
			"delegation_id			INTEGER UNSIGNED	NOT NULL, "
		      	"remote_site_phr_id		INTEGER UNSIGNED	NOT NULL, "
			"enc_secret_key			MEDIUMBLOB		NOT NULL)"
			, EMS__SECRET_KEYS);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an EMS__RESTRICTED_LEVEL_PHRS table
	sprintf(stat, "CREATE TABLE %s("
			"remote_site_phr_id		INTEGER UNSIGNED	NOT NULL, "   // Pointer to the "PHR id" field of a PHRSV__DATA table (remote site)
			"phr_owner_id			INTEGER UNSIGNED	NOT NULL, "
			"enc_emergency_key		MEDIUMBLOB		NULL, "       // Contain the emergency (CP-ABE) key encrypted by an 3DES algorithm
			"enc_recovery_emergency_key	MEDIUMBLOB		NULL, "       // Contain the emergency (CP-ABE) key encrypted by the PHR owner's SSL pub key
											      // for recovering when a set of trusted users is changed (add or remove)
			"enc_threshold_msg		MEDIUMBLOB		NULL, "       // Contain the 3DES password for decrypting the emergency key
			"threshold_value		TINYINT UNSIGNED	NOT NULL)"
			, EMS__RESTRICTED_LEVEL_PHRS);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an EMS__RESTRICTED_LEVEL_PHR_REQUESTS table
	sprintf(stat, "CREATE TABLE %s("
			"phr_request_id			INTEGER UNSIGNED	NOT NULL AUTO_INCREMENT UNIQUE, "
			"remote_site_phr_id		INTEGER UNSIGNED	NOT NULL, "
			"approval_notification_flag	CHAR(%d)		NOT NULL, "
			"emergency_unit_name	  	VARCHAR(%d)  		NOT NULL, "
			"emergency_staff_name	  	VARCHAR(%d)  		NOT NULL, "
			"emergency_staff_email_address	VARCHAR(%d)  		NOT NULL)"
			, EMS__RESTRICTED_LEVEL_PHR_REQUESTS, FLAG_LENGTH, EMERGENCY_UNIT_NAME_LENGTH, EMERGENCY_STAFF_NAME_LENGTH, EMAIL_ADDRESS_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Create an EMS__SECRET_KEY_APPROVALS table
	sprintf(stat, "CREATE TABLE %s("
			"trusted_user_id		INTEGER UNSIGNED	NOT NULL, "
			"phr_request_id			INTEGER UNSIGNED	NOT NULL, "
			"approval_flag			CHAR(%d)		NOT NULL, "
			"buffer_secret_key		MEDIUMBLOB		NULL)"
			, EMS__SECRET_KEY_APPROVALS, FLAG_LENGTH);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

  	mysql_close(conn);
	return 0;
}




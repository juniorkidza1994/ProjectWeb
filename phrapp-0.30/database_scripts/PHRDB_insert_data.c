// gcc PHRDB_insert_data.c -o phrdb_insert_data  `mysql_config --cflags --libs` -Wall

#include "common.h"

int main(int argc, char **argv)
{
	MYSQL *conn;
	char stat[SQL_STATEMENT_LENGTH + 1];

	FILE *fp_enc_ssl_cert;
	int len, enc_ssl_cert_size;
	char enc_ssl_cert_data[1000*1024];
	char enc_ssl_cert_chunk[sizeof(enc_ssl_cert_data)*2+1];
  	char query[sizeof(enc_ssl_cert_chunk)+sizeof(stat)+1];

	FILE *fp_enc_ssl_cert_hash;
	char enc_ssl_cert_hash[SHA1_DIGEST_LENGTH + 1];

  	conn = mysql_init(NULL);
  	if(!conn) 
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Connect a database
  	if(mysql_real_connect(conn, DB_IP, DB_USERNAME, DB_PASSWD, PHRDB_NAME, 0, NULL, 0) == NULL) 
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Read an SSL certificate from file
	fp_enc_ssl_cert = fopen("../Certs/admin.pem", "rb");
	if(fp_enc_ssl_cert == NULL)
	{
		printf("Could not open file \"enc_admin_ssl_cert\"\n");
      		exit(1);
	}

  	enc_ssl_cert_size = fread(enc_ssl_cert_data, 1, sizeof(enc_ssl_cert_data), fp_enc_ssl_cert);
	fclose(fp_enc_ssl_cert);

	// Read an SSL certificate hash from file
	fp_enc_ssl_cert_hash = fopen("../Certs/enc_admin_ssl_cert_hash", "rb");
	if(fp_enc_ssl_cert == NULL)
	{
		printf("Could not open file \"enc_admin_ssl_cert_hash\"\n");
      		exit(1);
	}

  	fread(enc_ssl_cert_hash, 1, SHA1_DIGEST_LENGTH, fp_enc_ssl_cert_hash);
	fclose(fp_enc_ssl_cert_hash);

	// Insert data into a UA__AUTHORITIES table
	sprintf(stat, "INSERT INTO %s(authority_name, user_auth_ip_addr, emergency_server_ip_addr, authority_join_flag) "
		"VALUES('Personal', '127.0.0.1', '127.0.0.1', '1')", UA__AUTHORITIES);
	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

/*////////////

	sprintf(stat, "INSERT INTO %s(authority_name, user_auth_ip_addr) VALUES('Healthcare', '127.0.0.1')", UA__AUTHORITIES);
	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	sprintf(stat, "INSERT INTO %s(attribute_name, is_numerical_attribute_flag, authority_id) VALUES('doctor', '0', 3)", UA__ATTRIBUTES);
	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	sprintf(stat, "INSERT INTO %s(attribute_name, is_numerical_attribute_flag, authority_id) VALUES('position_level', '1', 3')", UA__ATTRIBUTES);
	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

////////////*/

	// Insert data into a UA__BASIC_AUTHORITY_INFO table
/*	sprintf(stat, "INSERT INTO %s(authority_id, audit_server_ip_addr, phr_server_ip_addr, emergency_server_ip_addr, mail_server_url, authority_email_address, "
		"authority_email_passwd) VALUES(1, '127.0.0.1', '127.0.0.1', '127.0.0.1', 'smtp://smtp.live.com:587', 'personal_authority@live.com', 'bright23')", 
		UA__BASIC_AUTHORITY_INFO);*/
	sprintf(stat, "INSERT INTO %s(authority_id, audit_server_ip_addr, phr_server_ip_addr, emergency_server_ip_addr, mail_server_url, authority_email_address, "
		"authority_email_passwd) VALUES(1, '127.0.0.1', '127.0.0.1', '127.0.0.1', 'smtp://smtp.gmail.com:587', 'personal.authority@gmail.com', 'bright23')", 
		UA__BASIC_AUTHORITY_INFO);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Insert data into a UA__ADMINS table (echo \"bright23qwertyui\" | sha1sum)
	mysql_real_escape_string(conn, enc_ssl_cert_chunk, enc_ssl_cert_data, enc_ssl_cert_size);
	sprintf(stat, "INSERT INTO %s(username, salted_passwd_hash, salt_value, email_address, passwd_resetting_code, enc_ssl_cert, enc_ssl_cert_hash) "
		      "VALUES('admin', '1deb859d0bc645529deccf254815a7d1c3700d5c', 'qwertyui', 'mr.thummavet@gmail.com', '', '%%s', '%s')", UA__ADMINS, enc_ssl_cert_hash);

	len = snprintf(query, sizeof(stat)+sizeof(enc_ssl_cert_chunk), stat, enc_ssl_cert_chunk);
  	if(mysql_real_query(conn, query, len))
	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Insert data into an AS__AUTHORITIES table
	sprintf(stat, "INSERT INTO %s(authority_name) VALUES('Personal')", AS__AUTHORITIES);
	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Insert data into an AS__BASIC_AUTHORITY_INFO table
	sprintf(stat, "INSERT INTO %s(authority_id) VALUES(1)", AS__BASIC_AUTHORITY_INFO);
	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Insert data into an AS__USERS table
	sprintf(stat, "INSERT INTO %s(authority_id, username, is_admin_flag) VALUES(1, '%s', '0')", AS__USERS, NO_REFERENCE_USERNAME);
	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	sprintf(stat, "INSERT INTO %s(authority_id, username, is_admin_flag) VALUES(2, '%s', '0')", AS__USERS, REFERENCE_TO_ALL_ADMIN_NAMES);
	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Insert data into an EMS__BASIC_INFO table
	sprintf(stat, "INSERT INTO %s(authority_id, user_auth_ip_addr, audit_server_ip_addr, phr_server_ip_addr, mail_server_url, authority_email_address, "
		"authority_email_passwd) VALUES(1, '127.0.0.1', '127.0.0.1', '127.0.0.1', 'smtp://smtp.gmail.com:587', 'personal.authority@gmail.com'" 
		/*'phr.emergency.server@gmail.com'*/", 'bright23')", EMS__BASIC_AUTHORITY_INFO);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Insert data into an EMS__AUTHORITIES table
	sprintf(stat, "INSERT INTO %s(authority_name) VALUES('Personal')", EMS__AUTHORITIES);
	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

  	mysql_close(conn);
	return 0;
}





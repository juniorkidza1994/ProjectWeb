// gcc EmUDB_insert_data.c -o emudb_insert_data  `mysql_config --cflags --libs` -Wall

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
  	if(mysql_real_connect(conn, DB_IP, DB_USERNAME, DB_PASSWD, EMUDB_NAME, 0, NULL, 0) == NULL) 
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Read an SSL certificate from file
	fp_enc_ssl_cert = fopen("../Certs/EmU_admin.pem", "rb");
	if(fp_enc_ssl_cert == NULL)
	{
		printf("Could not open file \"enc_EmU_admin_ssl_cert\"\n");
      		exit(1);
	}

  	enc_ssl_cert_size = fread(enc_ssl_cert_data, 1, sizeof(enc_ssl_cert_data), fp_enc_ssl_cert);
	fclose(fp_enc_ssl_cert);

	// Read an SSL certificate hash from file
	fp_enc_ssl_cert_hash = fopen("../Certs/enc_EmU_admin_ssl_cert_hash", "rb");
	if(fp_enc_ssl_cert == NULL)
	{
		printf("Could not open file \"enc_EmU_admin_ssl_cert_hash\"\n");
      		exit(1);
	}

  	fread(enc_ssl_cert_hash, 1, SHA1_DIGEST_LENGTH, fp_enc_ssl_cert_hash);
	fclose(fp_enc_ssl_cert_hash);

	// Insert data into an ESA__BASIC_AUTHORITY_INFO table
	sprintf(stat, "INSERT INTO %s(authority_name, mail_server_url, authority_email_address, authority_email_passwd) "
		"VALUES('Emergency', 'smtp://smtp.gmail.com:587', 'emergency.staff.authority@gmail.com', 'bright23')", 
		ESA__BASIC_AUTHORITY_INFO);

	if(mysql_query(conn, stat))
  	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

	// Insert data into an ESA__ADMINS table (echo \"bright23qwertyui\" | sha1sum)
	mysql_real_escape_string(conn, enc_ssl_cert_chunk, enc_ssl_cert_data, enc_ssl_cert_size);
	sprintf(stat, "INSERT INTO %s(username, salted_passwd_hash, salt_value, email_address, passwd_resetting_code, enc_ssl_cert, enc_ssl_cert_hash) "
		      "VALUES('admin', '1deb859d0bc645529deccf254815a7d1c3700d5c', 'qwertyui', 'mr.thummavet@gmail.com', '', '%%s', '%s')", ESA__ADMINS, enc_ssl_cert_hash);

	len = snprintf(query, sizeof(stat)+sizeof(enc_ssl_cert_chunk), stat, enc_ssl_cert_chunk);
  	if(mysql_real_query(conn, query, len))
	{
      		printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
      		exit(1);
  	}

  	mysql_close(conn);
	return 0;
}




#include "mysql_common.h"

#define MAX_NTRY_TO_RECONNECT 15

void connect_db(MYSQL **db_conn_ret, char *ip, char *username, char *passwd, char *db_name)
{
  	*db_conn_ret = mysql_init(NULL);
  	if(*db_conn_ret == NULL) 
  	{
		fprintf(stderr, "error \"%u\": \"%s\"\n", mysql_errno(*db_conn_ret), mysql_error(*db_conn_ret));
		int_error("Initial mysql failed");
  	}

	unsigned int ntry_to_reconnect = 0;
	while(1)
	{
	  	if(mysql_real_connect(*db_conn_ret, ip, username, passwd, db_name, 0, NULL, 0))
			break;
 
	      	fprintf(stderr, "error \"%u\": \"%s\"\n", mysql_errno(*db_conn_ret), mysql_error(*db_conn_ret));
		if(strcmp(mysql_error(*db_conn_ret), "Too many connections") == 0)
		{
			ntry_to_reconnect++;
			if(ntry_to_reconnect > MAX_NTRY_TO_RECONNECT)
				int_error("Connecting database failed");

			fprintf(stderr, "Try to reconnect in next 10 sec...");
			sleep(10);
			continue;
		}
		else
		{
			int_error("Connecting database failed");
		}
	}
}

void disconnect_db(MYSQL **db_conn_ret)
{
	if(*db_conn_ret)
	{
		mysql_close(*db_conn_ret);
		*db_conn_ret = NULL;
	}
}




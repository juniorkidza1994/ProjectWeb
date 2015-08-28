#pragma once
#ifndef MYSQL_COMMON_H
#define MYSQL_COMMON_H

#include <my_global.h>
#include <mysql.h>
#include "common.h"

void connect_db(MYSQL **db_conn_ret, char *ip, char *username, char *passwd, char *db_name);
void disconnect_db(MYSQL **db_conn_ret);

#endif

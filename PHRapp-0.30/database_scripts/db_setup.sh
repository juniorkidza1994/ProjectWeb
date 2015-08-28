#!/bin/bash
# run: sh ./db_setup.sh

gcc PHRDB_create_db.c -o phrdb_create_phr_db  `mysql_config --cflags --libs` -Wall
gcc PHRDB_insert_data.c -o phrdb_insert_data  `mysql_config --cflags --libs` -Wall
gcc EmUDB_create_db.c -o emudb_create_phr_db  `mysql_config --cflags --libs` -Wall
gcc EmUDB_insert_data.c -o emudb_insert_data  `mysql_config --cflags --libs` -Wall

./phrdb_create_phr_db
./phrdb_insert_data
./emudb_create_phr_db
./emudb_insert_data


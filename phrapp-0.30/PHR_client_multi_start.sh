#!/bin/sh

cd bin 

CLIENT_DIR_PREFIX=Client_cache
CERTS_AND_KEYS_POOL_DIR=Certs_and_keys_pool

CPABE_PUB_KEY_PATH=../phrapp-0.30/backend_src/CPABE_modules_src/pub_key
UA_PUB_CERTFILE_PATH=../phrapp-0.30/Certs/user_auth_cert.pem
PHR_ROOT_CA_PUB_CERTFILE_PATH=../phrapp-0.30/Certs/rootCA_cert.pem

CPABE_ENC_SRC_PATH=../phrapp-0.30/backend_src/CPABE_modules_src/cpabe_enc
CPABE_DEC_SRC_PATH=../phrapp-0.30/backend_src/CPABE_modules_src/cpabe_dec

client_id=1
client_dir_main=$CLIENT_DIR_PREFIX$client_id

while test -d $client_dir_main; do

	client_id=$(( client_id+1 ))
	client_dir_main=$CLIENT_DIR_PREFIX$client_id

done

mkdir $client_dir_main
mkdir -p $client_dir_main/$CERTS_AND_KEYS_POOL_DIR

# certs_and_keys_client_side:
cp $CPABE_PUB_KEY_PATH $client_dir_main/$CERTS_AND_KEYS_POOL_DIR
cp $UA_PUB_CERTFILE_PATH $client_dir_main/$CERTS_AND_KEYS_POOL_DIR
cp $PHR_ROOT_CA_PUB_CERTFILE_PATH $client_dir_main/$CERTS_AND_KEYS_POOL_DIR

# CP-ABE modules
cp $CPABE_ENC_SRC_PATH $client_dir_main
cp $CPABE_DEC_SRC_PATH $client_dir_main

cd $client_dir_main

echo $client_id
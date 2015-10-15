# Pre-Processing (begin)
CC      = gcc
LIB_MKR = ld
JC	= javac

MYSQL_CFLAGS          = `mysql_config --cflags`
MYSQL_LFLAGS          = `mysql_config --libs`

cURL_LFLAGS           = -lcurl

CFLAGS         	      = -Wall -c -I/usr/local/ssl/include \
			-I/usr/local/openssl/include \
			-I/usr/lib/jvm/java-6-openjdk/include \
			$(MYSQL_CFLAGS)

CLIENT_COMPILE_LFLAGS = -ldl -lpthread
CLIENT_LINK_LFLAGS    = /usr/lib/libssl.a \
			/usr/lib/libcrypto.a \
			-lc -lpthread

SERVER_COMPILE_LFLAGS = $(MYSQL_LFLAGS) -ldl -lpthread
SERVER_LINK_LFLAGS    = $(MYSQL_LFLAGS) -ldl -lpthread \
		 	-Wl,--start-group \
			/usr/lib/libssl.a \
			/usr/lib/libcrypto.a \
		 	-Wl,--end-group

USER_AUTH_OUTPUT            = user_auth
AUD_SERV_OUTPUT             = aud_serv
PHR_SERV_OUTPUT             = phr_serv
EMERGENCY_SERV_OUTPUT       = emergency_serv
EMERGENCY_STAFF_AUTH_OUTPUT = emergency_staff_auth

LIB_PHR_APP_LOGIN_JNI_OUTPUT = libPHRapp_Login_JNI.so
LIB_PHR_APP_ADMIN_JNI_OUTPUT = libPHRapp_Admin_JNI.so
LIB_PHR_APP_USER_JNI_OUTPUT  = libPHRapp_User_JNI.so

LIB_PHR_APP_EMU_LOGIN_JNI_OUTPUT = libPHRapp_EmU_Login_JNI.so
LIB_PHR_APP_EMU_ADMIN_JNI_OUTPUT = libPHRapp_EmU_Admin_JNI.so
LIB_PHR_APP_EMU_USER_JNI_OUTPUT  = libPHRapp_EmU_User_JNI.so

CPABE_KEYGEN_OUTPUT = cpabe_keygen
CPABE_ENC_OUTPUT    = cpabe_enc
CPABE_DEC_OUTPUT    = cpabe_dec

CPABE_KEYGEN_SRC_PATH = '../backend_src/CPABE_modules_src/cpabe_keygen'
CPABE_ENC_SRC_PATH    = '../backend_src/CPABE_modules_src/cpabe_enc'
CPABE_DEC_SRC_PATH    = '../backend_src/CPABE_modules_src/cpabe_dec'

CERTS_AND_KEYS_POOL_DIR_PATH       = 'Certs_and_keys_pool'

UA_CERTFILE_PATH                   = '../Certs/user_auth.pem'
AS_CERTFILE_PATH                   = '../Certs/aud_serv.pem'
EMS_CERTFILE_PATH                  = '../Certs/emergency_serv.pem'
EMS_EMERGENCY_ACCESS_CERTFILE_PATH = '../Certs/emergency_serv_emergency_access.pem'
PHRSV_CERTFILE_PATH                = '../Certs/phr_serv.pem'
ESA_CERTFILE_PATH                  = '../Certs/emergency_staff_auth.pem'

CPABE_PUB_KEY_PATH                 = '../backend_src/CPABE_modules_src/pub_key'
CPABE_MASTER_KEY_PATH              = '../backend_src/CPABE_modules_src/master_key'

OPENSSL_PHRAPP_CNF_PATH            = '../Certs/PHRapp_OpenSSL.cnf'
UA_PUB_CERTFILE_PATH               = '../Certs/user_auth_cert.pem'
SERVER_CA_PUB_CERTFILE_PATH        = '../Certs/serverCA_cert.pem'
PHR_ROOT_CA_PUB_CERTFILE_PATH      = '../Certs/rootCA_cert.pem'
USER_CA_PUB_CERTFILE_PATH          = '../Certs/userCA_cert.pem'

USER_CA_FULL_CERTFILE_PATH         = '../Certs/userCA.pem'

EMS_KEY_PATH                       = '../EmS_key/Enc_EmS_key'

ESA_PUB_CERTFILE_PATH              = '../Certs/emergency_staff_auth_cert.pem'
EMU_SERVER_CA_PUB_CERTFILE_PATH    = '../Certs/EmU_serverCA_cert.pem'
EMU_ROOT_CA_PUB_CERTFILE_PATH      = '../Certs/EmU_rootCA_cert.pem'
EMU_USER_CA_PUB_CERTFILE_PATH      = '../Certs/EmU_userCA_cert.pem'

EMU_USER_CA_FULL_CERTFILE_PATH     = '../Certs/EmU_userCA.pem'

DH512_FILE_PATH                    = '../DH_params/dh512.pem'
DH1024_FILE_PATH                   = '../DH_params/dh1024.pem'
# Pre-Processing (end)



main: \
	client_main \
	server_main

client_main: \
	cp_cpabe_client_side_module \
	cp_certs_and_keys_client_side \
	cp_certs_and_keys_EmU_client_side \
	common.o \
	client_frontend \
	login \
	user \
	admin \
	EmU_client_frontend \
	EmU_login \
	EmU_admin \
	EmU_user

server_main: \
	cp_cpabe_server_side_module \
	cp_threshold_encryption_server_side_module \
	cp_certs_and_keys_UA_server_side \
	cp_certs_and_keys_AS_server_side \
	cp_certs_and_keys_EmS_server_side \
	cp_certs_and_keys_PHR_server_side \
	cp_certs_and_keys_ESA_server_side \
	common.o \
	mysql_common.o \
	simclist.o \
	$(USER_AUTH_OUTPUT) \
	$(AUD_SERV_OUTPUT) \
	$(PHR_SERV_OUTPUT) \
	$(EMERGENCY_SERV_OUTPUT) \
	$(EMERGENCY_STAFF_AUTH_OUTPUT)



# USER_AUTH (begin)
$(USER_AUTH_OUTPUT): \
	UA_user_authentication.o \
	UA_attribute_management.o \
	UA_attribute_list_loading.o \
	UA_user_management.o \
	UA_user_list_loading.o \
	UA_authority_management.o \
	UA_authority_list_loading.o \
	UA_access_permission_management.o \
	UA_assigned_access_permission_list_loading.o \
	UA_user_existence_checking.o \
	UA_access_granting_ticket_responding.o \
	UA_user_attribute_list_loading.o \
	UA_user_info_management.o \
	UA_user_passwd_resetting.o \
	UA_pub_key_serving.o \
	UA_synchronization_requesting.o \
	UA_synchronization_responding.o \
	UA_server_info_management.o \
	UA_smtp_tls.o \
	UA_emergency_key_management.o \
	UA_emergency_address_serving.o \
	UA_main.o \
	UA_common.o
		@$(CC) -O2 -o $(USER_AUTH_OUTPUT) \
		UA_user_authentication.o \
		UA_attribute_management.o \
		UA_attribute_list_loading.o \
		UA_user_management.o \
		UA_user_list_loading.o \
		UA_authority_management.o \
		UA_authority_list_loading.o \
		UA_access_permission_management.o \
		UA_assigned_access_permission_list_loading.o \
		UA_user_existence_checking.o \
		UA_access_granting_ticket_responding.o \
		UA_user_attribute_list_loading.o \
		UA_user_info_management.o \
		UA_user_passwd_resetting.o \
		UA_pub_key_serving.o \
		UA_synchronization_requesting.o \
		UA_synchronization_responding.o \
		UA_server_info_management.o \
		UA_smtp_tls.o \
		UA_emergency_key_management.o \
		UA_emergency_address_serving.o \
		UA_main.o \
		UA_common.o \
		common.o \
		mysql_common.o \
		simclist.o \
		$(SERVER_LINK_LFLAGS) $(cURL_LFLAGS)

UA_user_authentication.o: \
	../backend_src/UA_user_authentication.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_user_authentication.c

UA_attribute_management.o: \
	../backend_src/UA_attribute_management.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_attribute_management.c

UA_attribute_list_loading.o: \
	../backend_src/UA_attribute_list_loading.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_attribute_list_loading.c

UA_user_management.o: \
	../backend_src/UA_user_management.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h \
	../backend_src/simclist.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_user_management.c

UA_user_list_loading.o: \
	../backend_src/UA_user_list_loading.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_user_list_loading.c

UA_authority_management.o: \
	../backend_src/UA_authority_management.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_authority_management.c

UA_authority_list_loading.o: \
	../backend_src/UA_authority_list_loading.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_authority_list_loading.c

UA_access_permission_management.o: \
	../backend_src/UA_access_permission_management.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_access_permission_management.c

UA_assigned_access_permission_list_loading.o: \
	../backend_src/UA_assigned_access_permission_list_loading.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_assigned_access_permission_list_loading.c

UA_user_existence_checking.o: \
	../backend_src/UA_user_existence_checking.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_user_existence_checking.c

UA_access_granting_ticket_responding.o: \
	../backend_src/UA_access_granting_ticket_responding.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_access_granting_ticket_responding.c

UA_user_attribute_list_loading.o: \
	../backend_src/UA_user_attribute_list_loading.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_user_attribute_list_loading.c

UA_user_info_management.o: \
	../backend_src/UA_user_info_management.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_user_info_management.c

UA_user_passwd_resetting.o: \
	../backend_src/UA_user_passwd_resetting.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_user_passwd_resetting.c

UA_pub_key_serving.o: \
	../backend_src/UA_pub_key_serving.c \
	../backend_src/UA_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_pub_key_serving.c

UA_synchronization_requesting.o: \
	../backend_src/UA_synchronization_requesting.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/simclist.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_synchronization_requesting.c

UA_synchronization_responding.o: \
	../backend_src/UA_synchronization_responding.c \
	../backend_src/UA_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_synchronization_responding.c

UA_server_info_management.o: \
	../backend_src/UA_server_info_management.c \
	../backend_src/UA_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_server_info_management.c

UA_smtp_tls.o: \
	../backend_src/UA_smtp_tls.c \
	../backend_src/UA_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_smtp_tls.c

UA_emergency_key_management.o: \
	../backend_src/UA_emergency_key_management.c \
	../backend_src/UA_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_emergency_key_management.c

UA_emergency_address_serving.o: \
	../backend_src/UA_emergency_address_serving.c \
	../backend_src/UA_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_emergency_address_serving.c

UA_main.o: \
	../backend_src/UA_main.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_main.c

UA_common.o: \
	../backend_src/UA_common.c \
	../backend_src/UA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/UA_common.c
# USER_AUTH (end)



# AUD_SERV (begin)
$(AUD_SERV_OUTPUT): \
	AS_transaction_log_recording.o \
	AS_transaction_log_auditing.o \
	AS_phr_transaction_log_synchronization.o \
	AS_main.o \
	AS_common.o
		@$(CC) -O2 -o $(AUD_SERV_OUTPUT) \
		AS_transaction_log_recording.o \
		AS_transaction_log_auditing.o \
		AS_phr_transaction_log_synchronization.o \
		AS_main.o \
		AS_common.o \
		common.o \
		mysql_common.o \
		$(SERVER_LINK_LFLAGS)

AS_transaction_log_recording.o: \
	../backend_src/AS_transaction_log_recording.c \
	../backend_src/AS_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/AS_transaction_log_recording.c

AS_transaction_log_auditing.o: \
	../backend_src/AS_transaction_log_auditing.c \
	../backend_src/AS_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/AS_transaction_log_auditing.c

AS_phr_transaction_log_synchronization.o: \
	../backend_src/AS_phr_transaction_log_synchronization.c \
	../backend_src/AS_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/AS_phr_transaction_log_synchronization.c

AS_main.o: \
	../backend_src/AS_main.c \
	../backend_src/AS_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/AS_main.c

AS_common.o: \
	../backend_src/AS_common.c \
	../backend_src/AS_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/AS_common.c
# AUD_SERV (end)



# PHR_SERV (begin)
$(PHR_SERV_OUTPUT): \
	PHRsv_authorized_phr_list_loading.o \
	PHRsv_inactive_node_release.o \
	PHRsv_phr_services.o \
	PHRsv_confidentiality_level_changing.o \
	PHRsv_emergency_phr_list_loading.o \
	PHRsv_main.o \
	PHRsv_common.o
		@$(CC) -O2 -o $(PHR_SERV_OUTPUT) \
		PHRsv_authorized_phr_list_loading.o \
		PHRsv_inactive_node_release.o \
		PHRsv_phr_services.o \
		PHRsv_confidentiality_level_changing.o \
		PHRsv_emergency_phr_list_loading.o \
		PHRsv_main.o \
		PHRsv_common.o \
		common.o \
		mysql_common.o \
		simclist.o \
		$(SERVER_LINK_LFLAGS)

PHRsv_authorized_phr_list_loading.o: \
	../backend_src/PHRsv_authorized_phr_list_loading.c \
	../backend_src/PHRsv_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/PHRsv_authorized_phr_list_loading.c

PHRsv_inactive_node_release.o: \
	../backend_src/PHRsv_inactive_node_release.c \
	../backend_src/PHRsv_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h \
	../backend_src/simclist.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/PHRsv_inactive_node_release.c

PHRsv_phr_services.o: \
	../backend_src/PHRsv_phr_services.c \
	../backend_src/PHRsv_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h \
	../backend_src/simclist.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/PHRsv_phr_services.c

PHRsv_confidentiality_level_changing.o: \
	../backend_src/PHRsv_confidentiality_level_changing.c \
	../backend_src/PHRsv_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/PHRsv_confidentiality_level_changing.c

PHRsv_emergency_phr_list_loading.o: \
	../backend_src/PHRsv_emergency_phr_list_loading.c \
	../backend_src/PHRsv_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/PHRsv_emergency_phr_list_loading.c

PHRsv_main.o: \
	../backend_src/PHRsv_main.c \
	../backend_src/PHRsv_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h \
	../backend_src/simclist.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/PHRsv_main.c

PHRsv_common.o: \
	../backend_src/PHRsv_common.c \
	../backend_src/PHRsv_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h \
	../backend_src/simclist.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/PHRsv_common.c
# PHR_SERV (end)



# EMERGENCY_SERV (begin)
$(EMERGENCY_SERV_OUTPUT): \
	EmS_server_info_management.o \
	EmS_emergency_trusted_user_management.o \
	EmS_emergency_delegation_list_loading.o \
	EmS_restricted_level_phr_key_params_management.o \
	EmS_phr_owner_existence_checking.o \
	EmS_emergency_phr_list_loading.o \
	EmS_smtp_tls.o \
	EmS_synchronization_receiving.o \
	EmS_synchronization_responding.o \
	EmS_emergency_phr_accessing.o \
	EmS_restricted_level_phr_access_requesting.o \
	EmS_restricted_level_phr_access_request_list_loading.o \
	EmS_restricted_level_phr_access_request_responding.o \
	EmS_main.o \
	EmS_common.o \
	EmS_ThresholdDecryption
		@$(CC) -O2 -o $(EMERGENCY_SERV_OUTPUT) \
		EmS_server_info_management.o \
		EmS_emergency_trusted_user_management.o \
		EmS_emergency_delegation_list_loading.o \
		EmS_restricted_level_phr_key_params_management.o \
		EmS_phr_owner_existence_checking.o \
		EmS_emergency_phr_list_loading.o \
		EmS_smtp_tls.o \
		EmS_synchronization_receiving.o \
		EmS_synchronization_responding.o \
		EmS_emergency_phr_accessing.o \
		EmS_restricted_level_phr_access_requesting.o \
		EmS_restricted_level_phr_access_request_list_loading.o \
		EmS_restricted_level_phr_access_request_responding.o \
		EmS_main.o \
		EmS_common.o \
		common.o \
		mysql_common.o \
		simclist.o \
		$(SERVER_LINK_LFLAGS) $(cURL_LFLAGS)

EmS_server_info_management.o: \
	../backend_src/EmS_server_info_management.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_server_info_management.c

EmS_emergency_trusted_user_management.o: \
	../backend_src/EmS_emergency_trusted_user_management.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_emergency_trusted_user_management.c

EmS_emergency_delegation_list_loading.o: \
	../backend_src/EmS_emergency_delegation_list_loading.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_emergency_delegation_list_loading.c

EmS_restricted_level_phr_key_params_management.o: \
	../backend_src/EmS_restricted_level_phr_key_params_management.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_restricted_level_phr_key_params_management.c

EmS_phr_owner_existence_checking.o: \
	../backend_src/EmS_phr_owner_existence_checking.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_phr_owner_existence_checking.c

EmS_emergency_phr_list_loading.o: \
	../backend_src/EmS_emergency_phr_list_loading.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_emergency_phr_list_loading.c

EmS_smtp_tls.o: \
	../backend_src/EmS_smtp_tls.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_smtp_tls.c

EmS_synchronization_receiving.o: \
	../backend_src/EmS_synchronization_receiving.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h \
	../backend_src/simclist.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_synchronization_receiving.c

EmS_synchronization_responding.o: \
	../backend_src/EmS_synchronization_responding.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h 
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_synchronization_responding.c

EmS_emergency_phr_accessing.o: \
	../backend_src/EmS_emergency_phr_accessing.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h 
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_emergency_phr_accessing.c

EmS_restricted_level_phr_access_requesting.o: \
	../backend_src/EmS_restricted_level_phr_access_requesting.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_restricted_level_phr_access_requesting.c

EmS_restricted_level_phr_access_request_list_loading.o: \
	../backend_src/EmS_restricted_level_phr_access_request_list_loading.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_restricted_level_phr_access_request_list_loading.c

EmS_restricted_level_phr_access_request_responding.o: \
	../backend_src/EmS_restricted_level_phr_access_request_responding.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_restricted_level_phr_access_request_responding.c

EmS_main.o: \
	../backend_src/EmS_main.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_main.c

EmS_common.o: \
	../backend_src/EmS_common.c \
	../backend_src/EmS_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/EmS_common.c

EmS_ThresholdDecryption:
	@$(JC) -sourcepath '../backend_src/' -d '.' \
	-cp '../frontend_src/paillier.jar' \
	'../backend_src/EmS_ThresholdDecryption.java' -Xlint  # We use the '../frontend_src/paillier.jar' as a class path library
# EMERGENCY_SERV (end)



# EMERGENCY_STAFF_AUTH (begin)
$(EMERGENCY_STAFF_AUTH_OUTPUT): \
	ESA_user_authentication.o \
	ESA_pub_key_serving.o \
	ESA_user_management.o \
	ESA_user_info_management.o \
	ESA_server_info_management.o \
	ESA_smtp_tls.o \
	ESA_user_list_loading.o \
	ESA_phr_authority_list_loading.o \
	ESA_phr_authority_management.o \
	ESA_user_passwd_resetting.o \
	ESA_main.o \
	ESA_common.o
		@$(CC) -O2 -o $(EMERGENCY_STAFF_AUTH_OUTPUT) \
		ESA_user_authentication.o \
		ESA_pub_key_serving.o \
		ESA_user_management.o \
		ESA_user_info_management.o \
		ESA_server_info_management.o \
		ESA_smtp_tls.o \
		ESA_user_list_loading.o \
		ESA_phr_authority_list_loading.o \
		ESA_phr_authority_management.o \
		ESA_user_passwd_resetting.o \
		ESA_main.o \
		ESA_common.o \
		common.o \
		mysql_common.o \
		$(SERVER_LINK_LFLAGS) $(cURL_LFLAGS)

ESA_user_authentication.o: \
	../backend_src/ESA_user_authentication.c \
	../backend_src/ESA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/ESA_user_authentication.c

ESA_pub_key_serving.o: \
	../backend_src/ESA_pub_key_serving.c \
	../backend_src/ESA_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/ESA_pub_key_serving.c

ESA_user_management.o: \
	../backend_src/ESA_user_management.c \
	../backend_src/ESA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/ESA_user_management.c

ESA_user_info_management.o: \
	../backend_src/ESA_user_info_management.c \
	../backend_src/ESA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/ESA_user_info_management.c

ESA_server_info_management.o: \
	../backend_src/ESA_server_info_management.c \
	../backend_src/ESA_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/ESA_server_info_management.c

ESA_smtp_tls.o: \
	../backend_src/ESA_smtp_tls.c \
	../backend_src/ESA_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/ESA_smtp_tls.c

ESA_user_list_loading.o: \
	../backend_src/ESA_user_list_loading.c \
	../backend_src/ESA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/ESA_user_list_loading.c

ESA_phr_authority_list_loading.o: \
	../backend_src/ESA_phr_authority_list_loading.c \
	../backend_src/ESA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/ESA_phr_authority_list_loading.c

ESA_phr_authority_management.o: \
	../backend_src/ESA_phr_authority_management.c \
	../backend_src/ESA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/ESA_phr_authority_management.c

ESA_user_passwd_resetting.o: \
	../backend_src/ESA_user_passwd_resetting.c \
	../backend_src/ESA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/ESA_user_passwd_resetting.c

ESA_main.o: \
	../backend_src/ESA_main.c \
	../backend_src/ESA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/ESA_main.c

ESA_common.o: \
	../backend_src/ESA_common.c \
	../backend_src/ESA_common.h \
	../backend_src/common.h \
	../backend_src/mysql_common.h
		@$(CC) -O2 $(CFLAGS) $(SERVER_COMPILE_LFLAGS) \
		../backend_src/ESA_common.c
# EMERGENCY_STAFF_AUTH (end)



# LOGIN (begin)
login: \
	client_login_jni.o \
	client_login_authentication.o \
	client_passwd_resetting.o \
	client_ua_pub_key_loading.o
		@$(LIB_MKR) -G -o $(LIB_PHR_APP_LOGIN_JNI_OUTPUT)\
		client_login_jni.o \
		client_login_authentication.o \
		client_passwd_resetting.o \
		client_ua_pub_key_loading.o \
		common.o \
		$(CLIENT_LINK_LFLAGS)

client_login_jni.o: \
	../backend_src/client_login_jni.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_login_jni.c

client_login_authentication.o: \
	../backend_src/client_login_authentication.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_login_authentication.c

client_passwd_resetting.o: \
	../backend_src/client_passwd_resetting.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_passwd_resetting.c

client_ua_pub_key_loading.o: \
	../backend_src/client_ua_pub_key_loading.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_ua_pub_key_loading.c
# LOGIN (end)



# USER (begin)
user: \
	client_user_main_jni.o \
	client_transaction_logout_log_recording.o \
	client_authority_list_update.o \
	client_access_permission_management.o \
	client_assigned_access_permission_list_update.o \
	client_attribute_list_update.o \
	client_user_existence_checking.o \
	client_access_permission_verification.o \
	client_phr_encrypting.o \
	client_phr_uploading.o \
	client_phr_transaction_log_recording.o \
	client_authorized_phr_list_loading.o \
	client_phr_downloading.o \
	client_phr_decrypting.o \
	client_phr_deletion.o \
	client_user_attribute_list_update.o \
	client_user_transaction_auditing.o \
	client_emergency_trusted_user_management.o \
	client_user_info_management.o \
	client_emergency_delegation_list_update.o \
	client_emergency_key_management.o \
	client_restricted_level_phr_access_request_list_update.o \
	client_restricted_level_phr_access_request_responding.o
		@$(LIB_MKR) -G -o $(LIB_PHR_APP_USER_JNI_OUTPUT)\
		client_user_main_jni.o \
		client_transaction_logout_log_recording.o \
		client_authority_list_update.o \
		client_access_permission_management.o \
		client_assigned_access_permission_list_update.o \
		client_attribute_list_update.o \
		client_user_existence_checking.o \
		client_access_permission_verification.o \
		client_phr_encrypting.o \
		client_phr_uploading.o \
		client_phr_transaction_log_recording.o \
		client_authorized_phr_list_loading.o \
		client_phr_downloading.o \
		client_phr_decrypting.o \
		client_phr_deletion.o \
		client_user_attribute_list_update.o \
		client_user_transaction_auditing.o \
		client_user_info_management.o \
		client_emergency_trusted_user_management.o \
		client_emergency_delegation_list_update.o \
		client_emergency_key_management.o \
		client_restricted_level_phr_access_request_list_update.o \
		client_restricted_level_phr_access_request_responding.o \
		common.o \
		$(CLIENT_LINK_LFLAGS)

client_user_main_jni.o: \
	../backend_src/client_user_main_jni.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_user_main_jni.c

client_access_permission_management.o: \
	../backend_src/client_access_permission_management.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_access_permission_management.c

client_assigned_access_permission_list_update.o: \
	../backend_src/client_assigned_access_permission_list_update.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_assigned_access_permission_list_update.c

client_attribute_list_update.o: \
	../backend_src/client_attribute_list_update.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_attribute_list_update.c

client_user_existence_checking.o: \
	../backend_src/client_user_existence_checking.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_user_existence_checking.c

client_access_permission_verification.o: \
	../backend_src/client_access_permission_verification.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 -D_XOPEN_SOURCE $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_access_permission_verification.c

client_phr_encrypting.o: \
	../backend_src/client_phr_encrypting.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_phr_encrypting.c

client_phr_uploading.o: \
	../backend_src/client_phr_uploading.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_phr_uploading.c

client_phr_transaction_log_recording.o: \
	../backend_src/client_phr_transaction_log_recording.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_phr_transaction_log_recording.c

client_authorized_phr_list_loading.o: \
	../backend_src/client_authorized_phr_list_loading.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_authorized_phr_list_loading.c

client_phr_downloading.o: \
	../backend_src/client_phr_downloading.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_phr_downloading.c

client_phr_decrypting.o: \
	../backend_src/client_phr_decrypting.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_phr_decrypting.c

client_phr_deletion.o: \
	../backend_src/client_phr_deletion.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_phr_deletion.c

client_user_attribute_list_update.o: \
	../backend_src/client_user_attribute_list_update.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_user_attribute_list_update.c

client_user_transaction_auditing.o: \
	../backend_src/client_user_transaction_auditing.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_user_transaction_auditing.c

client_emergency_trusted_user_management.o: \
	../backend_src/client_emergency_trusted_user_management.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_emergency_trusted_user_management.c

client_emergency_delegation_list_update.o: \
	../backend_src/client_emergency_delegation_list_update.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_emergency_delegation_list_update.c

client_emergency_key_management.o: \
	../backend_src/client_emergency_key_management.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_emergency_key_management.c

client_restricted_level_phr_access_request_list_update.o: \
	../backend_src/client_restricted_level_phr_access_request_list_update.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_restricted_level_phr_access_request_list_update.c

client_restricted_level_phr_access_request_responding.o: \
	../backend_src/client_restricted_level_phr_access_request_responding.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_restricted_level_phr_access_request_responding.c
# USER (end)



# ADMIN (begin)
admin: \
	client_admin_main_jni.o \
	client_attribute_management.o \
	client_attribute_list_update.o \
	client_user_management.o \
	client_user_list_update.o \
	client_transaction_logout_log_recording.o \
	client_admin_list_update.o \
	client_authority_management.o \
	client_admin_transaction_auditing.o \
	client_authority_list_update.o \
	client_user_info_management.o \
	client_server_info_management.o
		@$(LIB_MKR) -G -o $(LIB_PHR_APP_ADMIN_JNI_OUTPUT)\
		client_admin_main_jni.o \
		client_attribute_management.o \
		client_attribute_list_update.o \
		client_user_management.o \
		client_user_list_update.o \
		client_transaction_logout_log_recording.o \
		client_admin_list_update.o \
		client_authority_management.o \
		client_admin_transaction_auditing.o \
		client_authority_list_update.o \
		client_user_info_management.o \
		client_server_info_management.o \
		common.o \
		$(CLIENT_LINK_LFLAGS)

client_admin_main_jni.o: \
	../backend_src/client_admin_main_jni.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_admin_main_jni.c

client_attribute_management.o: \
	../backend_src/client_attribute_management.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_attribute_management.c

client_user_management.o: \
	../backend_src/client_user_management.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_user_management.c

client_user_list_update.o: \
	../backend_src/client_user_list_update.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_user_list_update.c

client_admin_list_update.o: \
	../backend_src/client_admin_list_update.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_admin_list_update.c

client_authority_management.o: \
	../backend_src/client_authority_management.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_authority_management.c

client_admin_transaction_auditing.o: \
	../backend_src/client_admin_transaction_auditing.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_admin_transaction_auditing.c

client_server_info_management.o: \
	../backend_src/client_server_info_management.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_server_info_management.c
# ADMIN (end)



# EmU LOGIN (begin)
EmU_login: \
	EmU_client_login_jni.o \
	EmU_client_login_authentication.o \
	EmU_client_passwd_resetting.o \
	EmU_client_esa_pub_key_loading.o
		@$(LIB_MKR) -G -o $(LIB_PHR_APP_EMU_LOGIN_JNI_OUTPUT)\
		EmU_client_login_jni.o \
		EmU_client_login_authentication.o \
		EmU_client_passwd_resetting.o \
		EmU_client_esa_pub_key_loading.o \
		common.o \
		$(CLIENT_LINK_LFLAGS)

EmU_client_login_jni.o: \
	../backend_src/EmU_client_login_jni.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_login_jni.c

EmU_client_login_authentication.o: \
	../backend_src/EmU_client_login_authentication.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_login_authentication.c

EmU_client_passwd_resetting.o: \
	../backend_src/EmU_client_passwd_resetting.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_passwd_resetting.c

EmU_client_esa_pub_key_loading.o: \
	../backend_src/EmU_client_esa_pub_key_loading.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_esa_pub_key_loading.c
# EmU LOGIN (end)



# EmU ADMIN (begin)
EmU_admin: \
	EmU_client_admin_main_jni.o \
	EmU_client_user_info_management.o \
	EmU_client_server_info_management.o \
	EmU_client_user_and_admin_list_update.o \
	EmU_client_phr_authority_list_update.o \
	EmU_client_user_management.o \
	EmU_client_phr_authority_management.o
		@$(LIB_MKR) -G -o $(LIB_PHR_APP_EMU_ADMIN_JNI_OUTPUT)\
		EmU_client_admin_main_jni.o \
		EmU_client_user_info_management.o \
		EmU_client_server_info_management.o \
		EmU_client_user_and_admin_list_update.o \
		EmU_client_phr_authority_list_update.o \
		EmU_client_user_management.o \
		EmU_client_phr_authority_management.o \
		common.o \
		$(CLIENT_LINK_LFLAGS)

EmU_client_admin_main_jni.o: \
	../backend_src/EmU_client_admin_main_jni.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_admin_main_jni.c

EmU_client_server_info_management.o: \
	../backend_src/EmU_client_server_info_management.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_server_info_management.c

EmU_client_user_and_admin_list_update.o: \
	../backend_src/EmU_client_user_and_admin_list_update.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_user_and_admin_list_update.c

EmU_client_user_management.o: \
	../backend_src/EmU_client_user_management.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_user_management.c

EmU_client_phr_authority_management.o: \
	../backend_src/EmU_client_phr_authority_management.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_phr_authority_management.c
# EmU ADMIN (end)



# EmU USER (begin)
EmU_user: \
	EmU_client_user_main_jni.o \
	EmU_client_user_info_management.o \
	EmU_client_phr_authority_list_update.o \
	EmU_client_phr_owner_existence_checking.o \
	EmU_client_emergency_phr_list_loading.o \
	EmU_client_emergency_phr_downloading.o \
	EmU_client_emergency_phr_extracting.o \
	EmU_client_restricted_level_phr_access_requesting.o
		@$(LIB_MKR) -G -o $(LIB_PHR_APP_EMU_USER_JNI_OUTPUT)\
		EmU_client_user_main_jni.o \
		EmU_client_user_info_management.o \
		EmU_client_phr_authority_list_update.o \
		EmU_client_phr_owner_existence_checking.o \
		EmU_client_emergency_phr_list_loading.o \
		EmU_client_emergency_phr_downloading.o \
		EmU_client_emergency_phr_extracting.o \
		EmU_client_restricted_level_phr_access_requesting.o \
		common.o \
		$(CLIENT_LINK_LFLAGS)

EmU_client_user_main_jni.o: \
	../backend_src/EmU_client_user_main_jni.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_user_main_jni.c

EmU_client_phr_owner_existence_checking.o: \
	../backend_src/EmU_client_phr_owner_existence_checking.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_phr_owner_existence_checking.c

EmU_client_emergency_phr_list_loading.o: \
	../backend_src/EmU_client_emergency_phr_list_loading.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_emergency_phr_list_loading.c

EmU_client_emergency_phr_downloading.o: \
	../backend_src/EmU_client_emergency_phr_downloading.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_emergency_phr_downloading.c

EmU_client_emergency_phr_extracting.o: \
	../backend_src/EmU_client_emergency_phr_extracting.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_emergency_phr_extracting.c

EmU_client_restricted_level_phr_access_requesting.o: \
	../backend_src/EmU_client_restricted_level_phr_access_requesting.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_restricted_level_phr_access_requesting.c
# EmU USER (end)



# common (begin)
common.o: \
	../backend_src/common.c \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) \
		../backend_src/common.c

mysql_common.o: \
	../backend_src/mysql_common.c \
	../backend_src/mysql_common.h \
	../backend_src/common.h
		@$(CC) -O2 $(CFLAGS) $(MYSQL_LFLAGS) \
		../backend_src/mysql_common.c

simclist.o: \
	../backend_src/simclist.c \
	../backend_src/simclist.h
		@$(CC) -O2 $(CFLAGS) \
		../backend_src/simclist.c

client_transaction_logout_log_recording.o: \
	../backend_src/client_transaction_logout_log_recording.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_transaction_logout_log_recording.c

client_user_info_management.o: \
	../backend_src/client_user_info_management.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_user_info_management.c

client_authority_list_update.o: \
	../backend_src/client_authority_list_update.c \
	../backend_src/common.h \
	../backend_src/client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/client_authority_list_update.c

EmU_client_user_info_management.o: \
	../backend_src/EmU_client_user_info_management.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_user_info_management.c

EmU_client_phr_authority_list_update.o: \
	../backend_src/EmU_client_phr_authority_list_update.c \
	../backend_src/common.h \
	../backend_src/EmU_client_common.h
		@$(CC) -O2 $(CFLAGS) $(CLIENT_COMPILE_LFLAGS) \
		../backend_src/EmU_client_phr_authority_list_update.c
# common (end)



# CLIENT_FRONTEND (begin)
client_frontend: \
	admin_main \
	user_main \
	login_main \
	cp_lib

admin_main:
	@$(JC) -sourcepath '../frontend_src/' -d '.' \
	-cp '../frontend_src/swingx-all-1.6.3.jar:../frontend_src/commons-lang3-3.1.jar:../frontend_src/org-json.jar:../frontend_src/paillier.jar' \
	'../frontend_src/AdminMain.java' '../frontend_src/AttributeRegistration.java' \
	'../frontend_src/UserManagement.java' '../frontend_src/UserTreeTable.java' \
	'../frontend_src/UserTreeTableModel.java' '../frontend_src/UserTreeTableNode.java' \
	'../frontend_src/ShutdownHook.java' '../frontend_src/AdminManagement.java' \
	'../frontend_src/AuthorityManagement.java' '../frontend_src/AdminTransactionAuditing.java' \
	'../frontend_src/NumericalAttributeValueEditing.java' '../frontend_src/NewPasswordChanging.java' \
	'../frontend_src/EmailAddressChanging.java' '../frontend_src/ServerAddressesConfigurationChanging.java' \
	'../frontend_src/MailServerConfigurationChanging.java' '../frontend_src/ConstantVars.java' \
	'../frontend_src/SpringUtilities.java' -Xlint

user_main:
	@$(JC) -sourcepath '../frontend_src/' -d '.' \
	-cp '../frontend_src/swingx-all-1.6.3.jar:../frontend_src/commons-lang3-3.1.jar:../frontend_src/org-json.jar:../frontend_src/paillier.jar' \
	'../frontend_src/UserMain.java' '../frontend_src/ShutdownHook.java' \
	'../frontend_src/AccessPermissionManagement.java' '../frontend_src/AccessPolicyTree.java' \
	'../frontend_src/ComparisonOperation.java' '../frontend_src/NumericalAttributeInformationEntry.java' \
	'../frontend_src/UserTransactionAuditing.java' '../frontend_src/NewPasswordChanging.java' \
	'../frontend_src/EmailAddressChanging.java' '../frontend_src/EmergencyTrustedUserAdding.java' \
	'../frontend_src/ConstantVars.java' '../frontend_src/SpringUtilities.java' \
	'../frontend_src/ConfirmSignal.java' -Xlint

login_main:
	@$(JC) -sourcepath '../frontend_src/' -d '.' \
	-cp '../frontend_src/swingx-all-1.6.3.jar:../frontend_src/commons-lang3-3.1.jar:../frontend_src/org-json.jar:../frontend_src/paillier.jar' \
	'../frontend_src/Login.java' '../frontend_src/ForgetPassword.java' \
	'../frontend_src/ConstantVars.java' '../frontend_src/SpringUtilities.java' -Xlint

cp_lib:
	@cp '../frontend_src/swingx-all-1.6.3.jar' '.'
	@cp '../frontend_src/commons-lang3-3.1.jar' '.'
	@cp '../frontend_src/paillier.jar' '.'
# CLIENT_FRONTEND (end)



# EmU CLIENT_FRONTEND (begin)
EmU_client_frontend: \
	EmU_admin_main \
	EmU_user_main \
	EmU_login_main \
	EmU_cp_lib

EmU_admin_main:
	@$(JC) -sourcepath '../frontend_src/' -d '.' \
	-cp '../frontend_src/swingx-all-1.6.3.jar:../frontend_src/commons-lang3-3.1.jar:../frontend_src/paillier.jar' \
	'../frontend_src/EmU_AdminMain.java' '../frontend_src/EmU_ShutdownHook.java' \
	'../frontend_src/NewPasswordChanging.java' '../frontend_src/EmailAddressChanging.java' \
	'../frontend_src/MailServerConfigurationChanging.java' '../frontend_src/EmU_UserAndAdminManagement.java' \
	'../frontend_src/EmU_PHRAuthorityManagement.java' '../frontend_src/ConstantVars.java' \
	'../frontend_src/SpringUtilities.java' -Xlint

EmU_user_main:
	@$(JC) -sourcepath '../frontend_src/' -d '.' \
	-cp '../frontend_src/swingx-all-1.6.3.jar:../frontend_src/commons-lang3-3.1.jar:../frontend_src/paillier.jar' \
	'../frontend_src/EmU_UserMain.java' '../frontend_src/EmU_ShutdownHook.java' \
	'../frontend_src/NewPasswordChanging.java' '../frontend_src/EmailAddressChanging.java' \
	'../frontend_src/ConstantVars.java' '../frontend_src/SpringUtilities.java' -Xlint

EmU_login_main:
	@$(JC) -sourcepath '../frontend_src/' -d '.' \
	-cp '../frontend_src/swingx-all-1.6.3.jar:../frontend_src/commons-lang3-3.1.jar:../frontend_src/paillier.jar' \
	'../frontend_src/EmU_Login.java' '../frontend_src/EmU_ForgetPassword.java' \
	'../frontend_src/ConstantVars.java' '../frontend_src/SpringUtilities.java' -Xlint

EmU_cp_lib:
	@cp '../frontend_src/swingx-all-1.6.3.jar' '.'
	@cp '../frontend_src/commons-lang3-3.1.jar' '.'
	@cp '../frontend_src/paillier.jar' '.'
# EmU CLIENT_FRONTEND (end)



# ENCRYPTION_MODULES (begin)
cp_cpabe_server_side_module:
	@cp $(CPABE_KEYGEN_SRC_PATH) '.'
	@cp $(CPABE_DEC_SRC_PATH) '.'

cp_threshold_encryption_server_side_module:
	@cp '../frontend_src/paillier.jar' '.'  # We use the '../frontend_src/paillier.jar' as a class path library for the EmS_ThresholdDecryption class

cp_cpabe_client_side_module:
	@cp $(CPABE_ENC_SRC_PATH) '.'
	@cp $(CPABE_DEC_SRC_PATH) '.'
# ENCRYPTION_MODULES (end)



# CERTS_AND_KEYS (begin)	
cp_certs_and_keys_UA_server_side:
	@mkdir -p $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(UA_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(CPABE_PUB_KEY_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(CPABE_MASTER_KEY_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(OPENSSL_PHRAPP_CNF_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(UA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(PHR_ROOT_CA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(USER_CA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(USER_CA_FULL_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(DH512_FILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(DH1024_FILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)

cp_certs_and_keys_AS_server_side:
	@mkdir -p $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(AS_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(PHR_ROOT_CA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(DH512_FILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(DH1024_FILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)

cp_certs_and_keys_EmS_server_side:
	@mkdir -p $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(EMS_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(EMS_EMERGENCY_ACCESS_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(EMS_KEY_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(SERVER_CA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(PHR_ROOT_CA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(CPABE_PUB_KEY_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(DH512_FILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(DH1024_FILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)

cp_certs_and_keys_PHR_server_side:
	@mkdir -p $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(PHRSV_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(SERVER_CA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(PHR_ROOT_CA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(DH512_FILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(DH1024_FILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)

cp_certs_and_keys_client_side:
	@mkdir -p $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(CPABE_PUB_KEY_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(UA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(PHR_ROOT_CA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)

cp_certs_and_keys_ESA_server_side:
	@mkdir -p $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(ESA_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(OPENSSL_PHRAPP_CNF_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(ESA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(EMU_ROOT_CA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(EMU_USER_CA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(EMU_USER_CA_FULL_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(DH512_FILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(DH1024_FILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)

cp_certs_and_keys_EmU_client_side:
	@mkdir -p $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(ESA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
	@cp $(EMU_ROOT_CA_PUB_CERTFILE_PATH) $(CERTS_AND_KEYS_POOL_DIR_PATH)
# CERTS_AND_KEYS (end)



clean:
	@rm -f *.o \
	@rm $(USER_AUTH_OUTPUT) \
	@rm $(AUD_SERV_OUTPUT) \
	@rm $(PHR_SERV_OUTPUT) \
	@rm $(EMERGENCY_SERV_OUTPUT) \
	@rm $(EMERGENCY_STAFF_AUTH_OUTPUT) \
	@rm $(LIB_PHR_APP_LOGIN_JNI_OUTPUT) \
	@rm $(LIB_PHR_APP_ADMIN_JNI_OUTPUT) \
	@rm $(LIB_PHR_APP_USER_JNI_OUTPUT) \
	@rm $(LIB_PHR_APP_EMU_LOGIN_JNI_OUTPUT) \
	@rm $(LIB_PHR_APP_EMU_ADMIN_JNI_OUTPUT) \
	@rm $(LIB_PHR_APP_EMU_USER_JNI_OUTPUT) \
	@rm -f *.class \
	@rm -f *.jar \
	@rm $(CPABE_KEYGEN_OUTPUT) \
	@rm $(CPABE_ENC_OUTPUT) \
	@rm $(CPABE_DEC_OUTPUT) \
	@rm -rf $(CERTS_AND_KEYS_POOL_DIR_PATH)




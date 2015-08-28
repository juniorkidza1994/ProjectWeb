#!/bin/bash
# run: sh ./cert_gen.sh

# --------------------------------------------------------------------------
# For the PHR system
#---------------------------------------------------------------------------

# To create the root CA
openssl req -newkey rsa:1024 -sha1 -keyout rootCA_key.pem -out rootCA_req.pem -passout pass:bright \
	-subj '/CN=Root CA/ST=Songkla/C=TH/emailAddress=rootca@phrapp.org/O=PSU/OU=PSU'
openssl x509 -req -days 3650 -in rootCA_req.pem -sha1 -extfile PHRapp_OpenSSL.cnf -extensions v3_ca -signkey \
	rootCA_key.pem -out rootCA_cert.pem -passin pass:bright
cat rootCA_cert.pem rootCA_key.pem > rootCA.pem 
openssl x509 -subject -issuer -noout -in rootCA.pem

# To create the Server CA and sign it with the Root CA
openssl req -newkey rsa:1024 -sha1 -keyout serverCA_key.pem -out serverCA_req.pem -passout pass:bright \
	-subj '/CN=Server CA/ST=Songkla/C=TH/emailAddress=serverca@phrapp.org/O=PSU/OU=PSU'
openssl x509 -req -days 3650 -in serverCA_req.pem -sha1 -extfile PHRapp_OpenSSL.cnf -extensions v3_ca -CA rootCA.pem \
	-CAkey rootCA.pem -CAcreateserial -out serverCA_cert.pem -passin pass:bright
cat serverCA_cert.pem serverCA_key.pem rootCA_cert.pem > serverCA.pem
openssl x509 -subject -issuer -noout -in serverCA.pem

# To create the User Authority's certificate and sign it with the Server CA
openssl req -newkey rsa:1024 -sha1 -keyout user_auth_key.pem -out user_auth_req.pem -passout pass:bright \
	-subj '/CN=Personal.User Authority/ST=Songkla/C=TH/emailAddress=user_auth@phrapp.org/O=PSU/OU=PSU'
openssl x509 -req -days 3650 -in user_auth_req.pem -sha1 -extfile PHRapp_OpenSSL.cnf -extensions usr_cert -CA serverCA.pem \
	-CAkey serverCA.pem -CAcreateserial -out user_auth_cert.pem -passin pass:bright
cat user_auth_cert.pem user_auth_key.pem serverCA_cert.pem rootCA_cert.pem > user_auth.pem
cat user_auth_cert.pem serverCA_cert.pem rootCA_cert.pem >> user_auth_cert.pem   # Append the UA certificate with the ServerCA and RootCA certificates
openssl x509 -subject -issuer -noout -in user_auth.pem

# To create the Audit Server's certificate and sign it with the Server CA
openssl req -newkey rsa:1024 -sha1 -keyout aud_serv_key.pem -out aud_serv_req.pem -passout pass:bright \
	-subj '/CN=Personal.Audit Server/ST=Songkla/C=TH/emailAddress=aud_serv@phrapp.org/O=PSU/OU=PSU'
openssl x509 -req -days 3650 -in aud_serv_req.pem -sha1 -extfile PHRapp_OpenSSL.cnf -extensions usr_cert -CA serverCA.pem \
	-CAkey serverCA.pem -CAcreateserial -out aud_serv_cert.pem -passin pass:bright
cat aud_serv_cert.pem aud_serv_key.pem serverCA_cert.pem rootCA_cert.pem > aud_serv.pem
cat aud_serv_cert.pem serverCA_cert.pem rootCA_cert.pem >> aud_serv_cert.pem   # Append the AS certificate with the ServerCA and RootCA certificates
openssl x509 -subject -issuer -noout -in aud_serv.pem

# To create the PHR Server's certificate and sign it with the Server CA
openssl req -newkey rsa:1024 -sha1 -keyout phr_serv_key.pem -out phr_serv_req.pem -passout pass:bright \
	-subj '/CN=PHR Server/ST=Songkla/C=TH/emailAddress=phr_serv@phrapp.org/O=PSU/OU=PSU'
openssl x509 -req -days 3650 -in phr_serv_req.pem -sha1 -extfile PHRapp_OpenSSL.cnf -extensions usr_cert -CA serverCA.pem \
	-CAkey serverCA.pem -CAcreateserial -out phr_serv_cert.pem -passin pass:bright
cat phr_serv_cert.pem phr_serv_key.pem serverCA_cert.pem rootCA_cert.pem > phr_serv.pem
cat phr_serv_cert.pem serverCA_cert.pem rootCA_cert.pem >> phr_serv_cert.pem   # Append the PHR server certificate with the ServerCA and RootCA certificates
openssl x509 -subject -issuer -noout -in phr_serv.pem

# To create the Emergency Server's certificate and sign it with the Server CA
openssl req -newkey rsa:1024 -sha1 -keyout emergency_serv_key.pem -out emergency_serv_req.pem -passout pass:bright \
	-subj '/CN=Personal.Emergency Server/ST=Songkla/C=TH/emailAddress=emergency_serv@phrapp.org/O=PSU/OU=PSU'
openssl x509 -req -days 3650 -in emergency_serv_req.pem -sha1 -extfile PHRapp_OpenSSL.cnf -extensions usr_cert -CA serverCA.pem \
	-CAkey serverCA.pem -CAcreateserial -out emergency_serv_cert.pem -passin pass:bright
cat emergency_serv_cert.pem emergency_serv_key.pem serverCA_cert.pem rootCA_cert.pem > emergency_serv.pem
cat emergency_serv_cert.pem serverCA_cert.pem rootCA_cert.pem >> emergency_serv_cert.pem   # Append the EmS certificate with the ServerCA and RootCA certificates
openssl x509 -subject -issuer -noout -in emergency_serv.pem

# To create the User CA and sign it with the Root CA
openssl req -newkey rsa:1024 -sha1 -keyout userCA_key.pem -out userCA_req.pem -passout pass:bright \
	-subj '/CN=User CA/ST=Songkla/C=TH/emailAddress=userca@phrapp.org/O=PSU/OU=PSU'
openssl x509 -req -days 3650 -in userCA_req.pem -sha1 -extfile PHRapp_OpenSSL.cnf -extensions v3_ca -CA rootCA.pem -CAkey rootCA.pem \
	-CAcreateserial -out userCA_cert.pem -passin pass:bright
cat userCA_cert.pem userCA_key.pem rootCA_cert.pem > userCA.pem
openssl x509 -subject -issuer -noout -in userCA.pem

# To create the Admin's certificate and sign it with the User CA
openssl req -newkey rsa:1024 -sha1 -keyout admin_key.pem -out admin_req.pem -passout pass:bright23 \
	-subj '/CN=Personal.admin(Admin)/ST=Songkla/C=TH/emailAddress=admin@phrapp.org/O=PSU/OU=PSU'
openssl x509 -req -days 365 -in admin_req.pem -sha1 -extfile PHRapp_OpenSSL.cnf -extensions usr_cert -CA userCA.pem -CAkey userCA.pem \
	-CAcreateserial -out admin_cert.pem -passin pass:bright
cat admin_cert.pem admin_key.pem userCA_cert.pem rootCA_cert.pem > admin.pem
openssl x509 -subject -issuer -noout -in admin.pem
sha1sum admin.pem > enc_admin_ssl_cert_hash
rm admin_key.pem
rm admin_cert.pem
rm admin_req.pem

# --------------------------------------------------------------------------
# For the emergency unit (EmU)
#---------------------------------------------------------------------------

# To create the EmU root CA
openssl req -newkey rsa:1024 -sha1 -keyout EmU_rootCA_key.pem -out EmU_rootCA_req.pem -passout pass:bright \
	-subj '/CN=EmU Root CA/ST=Songkla/C=TH/emailAddress=emu_rootca@phrapp.org/O=PSU/OU=PSU'
openssl x509 -req -days 3650 -in EmU_rootCA_req.pem -sha1 -extfile PHRapp_OpenSSL.cnf -extensions v3_ca \
	-signkey EmU_rootCA_key.pem -out EmU_rootCA_cert.pem -passin pass:bright
cat EmU_rootCA_cert.pem EmU_rootCA_key.pem > EmU_rootCA.pem
openssl x509 -subject -issuer -noout -in EmU_rootCA.pem



# To create the EmU Server CA and sign it with the EmU Root CA
openssl req -newkey rsa:1024 -sha1 -keyout EmU_serverCA_key.pem -out EmU_serverCA_req.pem -passout pass:bright \
	-subj '/CN=EmU Server CA/ST=Songkla/C=TH/emailAddress=emu_serverca@phrapp.org/O=PSU/OU=PSU'
openssl x509 -req -days 3650 -in EmU_serverCA_req.pem -sha1 -extfile PHRapp_OpenSSL.cnf -extensions v3_ca \
	-CA EmU_rootCA.pem -CAkey EmU_rootCA.pem -CAcreateserial -out EmU_serverCA_cert.pem -passin pass:bright
cat EmU_serverCA_cert.pem EmU_serverCA_key.pem EmU_rootCA_cert.pem > EmU_serverCA.pem
openssl x509 -subject -issuer -noout -in EmU_serverCA.pem



# To create the Emergency Server(for an emergency access)'s certificate and sign it with the EmU Server CA
openssl req -newkey rsa:1024 -sha1 -keyout emergency_serv_emergency_access_key.pem -out emergency_serv_emergency_access_req.pem \
	-passout pass:bright -subj '/CN=Personal.Emergency Server/ST=Songkla/C=TH/emailAddress=emergency_serv@phrapp.org/O=PSU/OU=PSU'
openssl x509 -req -days 3650 -in emergency_serv_emergency_access_req.pem -sha1 -extfile PHRapp_OpenSSL.cnf -extensions usr_cert \
	-CA EmU_serverCA.pem -CAkey EmU_serverCA.pem -CAcreateserial -out emergency_serv_emergency_access_cert.pem -passin pass:bright
cat emergency_serv_emergency_access_cert.pem emergency_serv_emergency_access_key.pem EmU_serverCA_cert.pem EmU_rootCA_cert.pem > emergency_serv_emergency_access.pem

# Append the EmSEA certificate with the EmUServerCA and EmURootCA certificates
cat emergency_serv_emergency_access_cert.pem EmU_serverCA_cert.pem EmU_rootCA_cert.pem >> emergency_serv_emergency_access_cert.pem
openssl x509 -subject -issuer -noout -in emergency_serv_emergency_access.pem



# To create the Emergency Staff Authority's certificate and sign it with the EmU Server CA
openssl req -newkey rsa:1024 -sha1 -keyout emergency_staff_auth_key.pem -out emergency_staff_auth_req.pem -passout pass:bright \
	-subj '/CN=Emergency.Emergency Staff Authority/ST=Songkla/C=TH/emailAddress=emergency_staff_auth@phrapp.org/O=PSU/OU=PSU'
openssl x509 -req -days 3650 -in emergency_staff_auth_req.pem -sha1 -extfile PHRapp_OpenSSL.cnf -extensions usr_cert \
	-CA EmU_serverCA.pem -CAkey EmU_serverCA.pem -CAcreateserial -out emergency_staff_auth_cert.pem -passin pass:bright
cat emergency_staff_auth_cert.pem emergency_staff_auth_key.pem EmU_serverCA_cert.pem EmU_rootCA_cert.pem > emergency_staff_auth.pem

# Append the ESA certificate with the EmUServerCA and EmURootCA certificates
cat emergency_staff_auth_cert.pem EmU_serverCA_cert.pem EmU_rootCA_cert.pem >> emergency_staff_auth_cert.pem
openssl x509 -subject -issuer -noout -in emergency_staff_auth.pem



# To create the EmU User CA and sign it with the EmU Root CA
openssl req -newkey rsa:1024 -sha1 -keyout EmU_userCA_key.pem -out EmU_userCA_req.pem -passout pass:bright \
	-subj '/CN=EmU User CA/ST=Songkla/C=TH/emailAddress=emu_userca@phrapp.org/O=PSU/OU=PSU'
openssl x509 -req -days 3650 -in EmU_userCA_req.pem -sha1 -extfile PHRapp_OpenSSL.cnf -extensions v3_ca \
	-CA EmU_rootCA.pem -CAkey EmU_rootCA.pem -CAcreateserial -out EmU_userCA_cert.pem -passin pass:bright
cat EmU_userCA_cert.pem EmU_userCA_key.pem EmU_rootCA_cert.pem > EmU_userCA.pem
openssl x509 -subject -issuer -noout -in EmU_userCA.pem



# To create the EmU Admin's certificate and sign it with the EmU User CA
openssl req -newkey rsa:1024 -sha1 -keyout EmU_admin_key.pem -out EmU_admin_req.pem -passout pass:bright23 \
	-subj '/CN=Emergency.admin(Admin)/ST=Songkla/C=TH/emailAddress=emu_admin@phrapp.org/O=PSU/OU=PSU'
openssl x509 -req -days 365 -in EmU_admin_req.pem -sha1 -extfile PHRapp_OpenSSL.cnf -extensions usr_cert \
	-CA EmU_userCA.pem -CAkey EmU_userCA.pem -CAcreateserial -out EmU_admin_cert.pem -passin pass:bright
cat EmU_admin_cert.pem EmU_admin_key.pem EmU_userCA_cert.pem EmU_rootCA_cert.pem > EmU_admin.pem
openssl x509 -subject -issuer -noout -in EmU_admin.pem
sha1sum EmU_admin.pem > enc_EmU_admin_ssl_cert_hash
rm EmU_admin_key.pem
rm EmU_admin_cert.pem
rm EmU_admin_req.pem

# --------------------------------------------------------------------------
# Creating symlink for rootCA and EmU_rootCA certificates
#---------------------------------------------------------------------------

sudo ln -s $(pwd)/rootCA_cert.pem /etc/ssl/certs/`openssl x509 -noout -hash -in rootCA_cert.pem`
sudo ln -s $(pwd)/EmU_rootCA_cert.pem /etc/ssl/certs/`openssl x509 -noout -hash -in EmU_rootCA_cert.pem`

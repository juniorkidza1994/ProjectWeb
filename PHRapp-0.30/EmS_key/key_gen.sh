#!/bin/bash
# run: sh ./key_gen.sh

../backend_src/CPABE_modules_src/cpabe_keygen -o EmS_key ../backend_src/CPABE_modules_src/pub_key \
	../backend_src/CPABE_modules_src/master_key 'SpecialNode__SUB__Personal__SUB__EmS'

openssl des3 -salt -in EmS_key -out Enc_EmS_key -pass pass:bright
rm EmS_key

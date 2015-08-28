#!/bin/bash
# run: sh ./dh_params_gen.sh

openssl dhparam -check -text -5 512 -out dh512.pem
openssl dhparam -check -text -5 1024 -out dh1024.pem

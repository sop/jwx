# RSA keys for unit testing

Generate private key:

    openssl genrsa -out rsa_private_key.pem &&
    openssl pkey -in rsa_private_key.pem -out private_key.pem

Extract public key:

    openssl rsa -in private_key.pem -RSAPublicKey_out -out rsa_public_key.pem &&
    openssl rsa -in private_key.pem -pubout -out public_key.pem

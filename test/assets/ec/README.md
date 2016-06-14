# Elliptic Curve Keys for Unit Testing

Generate key pairs:

    for curve in P-256 P-384 P-521; do
      openssl genpkey -out private_key_$curve.pem \
        -algorithm EC \
        -pkeyopt ec_paramgen_curve:$curve \
        -pkeyopt ec_param_enc:named_curve &&
      openssl ec -out public_key_$curve.pem \
        -in private_key_$curve.pem -pubout
    done

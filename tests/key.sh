openssl ecparam -genkey -name SM2 -out sk.pem
openssl ec -in sk.pem -pubout -out pk.pem
# https://github.com/dexidp/dex/blob/1a16aa4889607c739991fa01fbfb7b26f75a9c44/examples/k8s/gencert.sh

cat <<EOF >req.cnf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost 
IP.1 = 127.0.0.1
EOF

openssl genrsa -out ca-key.pem 2048
openssl req -x509 -new -nodes -key ca-key.pem -days 3650 -out ca.pem -subj "/CN=my-ca"

openssl genrsa -out client-key.pem 2048
openssl req -new -key client-key.pem -out csr.pem -subj "/CN=my-client"
openssl x509 -req -in csr.pem -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 3650

openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out csr.pem -subj "/CN=my-server" -config req.cnf
openssl x509 -req -in csr.pem -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 3650 -extensions v3_req -extfile req.cnf
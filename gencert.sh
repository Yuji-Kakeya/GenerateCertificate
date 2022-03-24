#!/bin/bash

#CONST
PASSWORD=1234
C=JP
ST=Kanagawa
L=Yokohama
O=example
EXPIRE_DAYS=825


#Generate Private Key and CSR
function GenKeyAndCSR(){
    openssl genrsa -passout pass:${PASSWORD} -aes256 -out $1/private_enc.pem 2048
    openssl rsa -passin pass:${PASSWORD} -in $1/private_enc.pem -out $1/private.pem
    openssl req -new -key $1/private.pem -out $1/_request.csr -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/CN=$2"
}


function IssuringCert(){
    #Issure Certificate
    WILDCARD=`echo $1 | sed -e "s/^[^.]*/*/g"`
    echo "subjectAltName=DNS:$1, DNS:${WILDCARD}" > $1/_san.conf
    case "$2" in
        1) #RootCA
            openssl ca -batch -in $1/_request.csr -out $1/public.crt -days ${EXPIRE_DAYS} -config RootCA/conf.cnf -extfile $1/_san.conf 
            ;;
        2) #IntermediateCA
            openssl ca -batch -in $1/_request.csr -out $1/public.crt -days ${EXPIRE_DAYS} -config IntermediateCA/conf.cnf -extfile $1/_san.conf 
            ;;
    esac

    #Generate PKCS12 File
    openssl pkcs12 -export -in $1/public.crt -inkey $1/private.pem -out $1/$1_pkcs12.pfx -passout pass:${PASSWORD} 
    rm -f $1/_*.* 
}

function MakeInitialFile(){
    touch $1/index.txt
    touch $1/index.txt.attr
    echo 00 > $1/serial
    mkdir $1/{certs,crl,newcerts,private}
    echo "
[ ca ]
default_ca      = CA_default  
[ CA_default ]
dir             = $1
certs           = $1/certs  
crl_dir         = $1/crl    
database        = $1/index.txt
new_certs_dir   = $1/newcerts
certificate     = $1/$1.crt 
serial          = $1/serial   
crlnumber       = $1/crlnumber       
crl             = $1/crl.pem         
private_key     = $1/private.pem
x509_extensions = usr_cert
name_opt        = ca_default
cert_opt        = ca_default                 
default_crl_days= 30                    
default_md      = sha256                               
policy          = policy_any
[ policy_any ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional
[ usr_cert ]
subjectAltName = @alt_names
basicConstraints=CA:FALSE
nsCertType = client, email, objsign, server
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
" > $1/conf.cnf
}




#initial check
if [ ! -d RootCA ]; then
    echo "*******   Initial Settings - Create RootCA   ******"
    echo "Input RootCA name:"
    read domain
    mkdir RootCA
    GenKeyAndCSR RootCA ${domain}
    openssl x509 -days ${EXPIRE_DAYS} -in RootCA/_request.csr -req -signkey RootCA/private.pem -out RootCA/RootCA.crt
    rm -f RootCA/_request.csr 
    MakeInitialFile RootCA
fi
if [ ! -d IntermediateCA ]; then
    echo "*******   Initial Settings - Create IntermediateCA   ******"
    echo "Input IntermediateCA name:"
    read domain
    mkdir IntermediateCA
    echo "
[ ca ]
default_ca      = CA_default  
[ CA_default ]
dir             = RootCA
certs           = RootCA/certs  
crl_dir         = RootCA/crl    
database        = RootCA/index.txt
new_certs_dir   = RootCA/newcerts
certificate     = RootCA/RootCA.crt 
serial          = RootCA/serial   
crlnumber       = RootCA/crlnumber       
crl             = RootCA/crl.pem         
private_key     = RootCA/private.pem
default_md      = sha256                
policy          = policy_any
[ policy_any ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional
[ ca_ext ]
keyUsage = critical,keyCertSign,cRLSign
basicConstraints = critical,CA:true
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
" > IntermediateCA/conf_for_IntermediateCA.cnf
    GenKeyAndCSR IntermediateCA ${domain}
    openssl ca -batch -in IntermediateCA/_request.csr -out IntermediateCA/IntermediateCA.crt -days ${EXPIRE_DAYS} -config IntermediateCA/conf_for_IntermediateCA.cnf 
    rm -f IntermediateCA/_request.csr 
    MakeInitialFile IntermediateCA
fi

#main
while :
    do
    clear
    echo "************************************************************"
    echo "Issuring Server Certificate Script - last updated: 2021/4/3"
    echo "************************************************************"
    echo ""
    echo "[1] Issue new server certificate signed by RootCA"
    echo "[2] Issue new server certificate signed by IntermediateCA"
    echo "[3] Show RootCA certificate and private key"
    echo "[4] Show IntermediateCA certificate and private key"
    echo "[5] View Certificate Information"
    echo "[9] Clear Serial and Index"
    echo "[q] Quit"
    echo "Choose number:"
    read choose
    case "${choose}" in
    [12])
        echo "Issue new server certificate"
        echo "Input domain name:"
        read domain
        mkdir ${domain}
        GenKeyAndCSR ${domain} ${domain}
        IssuringCert ${domain} ${choose}
        read
        ;;
    3)
        echo "Show RootCA certificate and private key"
        echo "--------- RootCA certificate -----------"
        openssl x509 -noout -text -in RootCA/RootCA.crt
        echo "--------- End of RootCA certificate -----------"
        echo ""
        echo "--------- RootCA certificate -----------"
        cat RootCA/RootCA.crt
        echo "--------- End of RootCA certificate -----------"
        echo ""
        echo "--------- RootCA private key  -----------"
        cat RootCA/private.pem
        echo "--------- End of RootCA private key -----------"
        read
        ;;
    4)
        echo "Show IntermediateCA certificate and private key"
        echo "--------- IntermediateCA certificate -----------"
        openssl x509 -noout -text -in IntermediateCA/IntermediateCA.crt
        echo "--------- End of IntermediateCA certificate -----------"
        echo ""
        echo "--------- IntermediateCA certificate -----------"
        cat IntermediateCA/IntermediateCA.crt
        echo "--------- End of IntermediateCA certificate -----------"
        echo ""
        echo "--------- IntermediateCA private key  -----------"
        cat IntermediateCA/private.pem
        echo "--------- End of IntermediateCA private key -----------"
        read
        ;;
    5)
        echo "View Certificate Information"
        ls
        echo "Input domain"
        read checkDomain
        openssl x509 -noout -text -in ${checkDomain}/public.crt
        read
        ;;
    9)
        echo "Clear Serial and Index"
        rm -f RootCA/index.txt
        touch RootCA/index.txt
        echo 00 > RootCA/serial
        rm -f IntermediateCA/index.txt
        touch IntermediateCA/index.txt
        echo 00 > IntermediateCA/serial
        read
        ;;
    q)
        exit 0
        ;;
    *)
        echo "error - exit"
        ;;
    esac
done
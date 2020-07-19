#pragma once

#include <string>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>


X509*      str_to_x509(const std::string& cert);
EVP_PKEY*  str_to_privateKey(const std::string& privatekey);


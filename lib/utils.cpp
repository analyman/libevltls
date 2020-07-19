#include "../include/evtls/utils.h"
#include "../include/evtls/internal/config__.h"


X509* str_to_x509(const std::string& str) //{
{
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, str.c_str());

    X509* ans = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);

    BIO_free(bio);
    return ans;
} //}

EVP_PKEY* str_to_privateKey(const std::string& str) //{
{
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, str.c_str());

    EVP_PKEY* ans = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);

    BIO_free(bio);
    return ans;
} //}


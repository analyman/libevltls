#include "../include/evtls/utils.h"
#include "../include/evtls/internal/config__.h"

#include <map>
#include <vector>
#include <string>

static std::map<std::string, X509*>     x509_cache;
static bool set_atexit_x509_cache_clean = false;
static std::map<std::string, EVP_PKEY*> evp_pkey_cache;
static bool set_atexit_evp_pkey_cache_clean = false;

static void clean_x509_cache() //{
{
    std::vector<X509*> list;

    for(auto& cert: x509_cache)
        list.push_back(cert.second);
    x509_cache.clear();

    for(auto& cert: list)
        X509_free(cert);
} //}
static void clean_evp_pkey_cache() //{
{
    std::vector<EVP_PKEY*> list;

    for(auto& cert: evp_pkey_cache)
        list.push_back(cert.second);
    evp_pkey_cache.clear();

    for(auto& cert: list)
        EVP_PKEY_free(cert);
} //}

X509* str_to_x509(const std::string& str) //{
{
    if(!set_atexit_x509_cache_clean) {
        atexit(clean_x509_cache);
        set_atexit_x509_cache_clean = true;
    }

    auto find_x509 = x509_cache.find(str);
    if(find_x509 != x509_cache.end())
        return find_x509->second;

    BIO* bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, str.c_str());

    X509* ans = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);

    BIO_free(bio);

    x509_cache[str] = ans;
    return ans;
} //}

EVP_PKEY* str_to_privateKey(const std::string& str) //{
{
    if(!set_atexit_evp_pkey_cache_clean) {
        atexit(clean_evp_pkey_cache);
        set_atexit_evp_pkey_cache_clean = true;
    }

    auto find_evp_pkey = evp_pkey_cache.find(str);
    if(find_evp_pkey != evp_pkey_cache.end())
        return find_evp_pkey->second;

    BIO* bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, str.c_str());

    EVP_PKEY* ans = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);

    BIO_free(bio);

    evp_pkey_cache[str] = ans;
    return ans;
} //}


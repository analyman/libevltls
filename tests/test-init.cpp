#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>

#include <iostream>
#include <memory>

#include <assert.h>


int main() {
    std::shared_ptr<BIO> bio(BIO_new(BIO_s_mem()), BIO_free);
    BIO_set_nbio(bio.get(), 0);
    char buf[] = "hello world!";
    char buf2[sizeof(buf)] = { 0 };
    assert(BIO_write(bio.get(), buf, sizeof(buf)));
    int ret = BIO_read(bio.get(), buf2, sizeof(buf2));
    if(ret == 0) {
        std::cout << "zero" << std::endl;
    } else if (ret < 0) {
        std::cout << "error" << std::endl;
    } else {
        std::cout << "what ??" << std::endl;
        std::cout << buf2 << std::endl;
    }
    return 0;
}


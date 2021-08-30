#ifndef CREATEX509_H
#define CREATEX509_H

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>
#include <memory>
#include <functional>

class certMaker {
public:
    certMaker(certMaker *Ca = nullptr) : m_Ca(Ca) {}
    int bits = 2048;
    unsigned long exp = RSA_F4;
    uint64_t serial = 1;
    long validDays = 0;
    std::string errMsg;
    struct certExt {
        int nid;
        const char *value;
    };
    bool generateCert(const char *nameParts[], const certExt extensions[]);
    bool writeKey(const char *fname, bool pem = true);
    bool writeCert(const char *fname, bool pem = true);
private:
    certMaker * const m_Ca;
    std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY *)>> m_key;
    std::unique_ptr<X509, std::function<void(X509 *)>> m_x509;
};

#endif // CREATEX509_H

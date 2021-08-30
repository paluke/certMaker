#include <stdexcept>
#include <time.h>
#include "create-x509.h"

template <class T>
std::unique_ptr<T, std::function<void(T *)>> wrap_unique(T* ptr, void (*del)(T*))
{
    return std::unique_ptr<T, std::function<void(T *)>>(ptr, del);
}

namespace  {

/* Generates RSA key. */
auto generate_key(int bits, unsigned long exp)
{
    /* Allocate memory for the EVP_PKEY structure. */
    auto pkey = wrap_unique(EVP_PKEY_new(), EVP_PKEY_free);
    if (!pkey) 
        throw std::runtime_error("Unable to create EVP_PKEY structure.");

    auto e = wrap_unique(BN_new(), BN_free);
    if (!e) 
        throw std::runtime_error("Unable to create BIGNUM structure.");

    if (!BN_set_word(e.get(), exp)) 
        throw std::runtime_error("Unable to set BIGNUM value.");

    RSA* key = RSA_new();
    if (!key) 
        throw std::runtime_error("Unable to create RSA structure.");

    /* Generate the RSA key. */
    if (!RSA_generate_key_ex(key, bits, e.get(), NULL))
    {
        RSA_free(key);
        throw std::runtime_error("Unable to generate RSA key.");
    }

    /* Assign it to pkey. On success, the RSA structure will be automatically freed when the EVP_PKEY structure is freed. */
    if (!EVP_PKEY_assign_RSA(pkey.get(), key))
    {
        RSA_free(key);
        throw std::runtime_error("Unable to assign RSA key.");
    }

    /* The key has been generated, return it. */
    return pkey;
}

bool name_add_entries(X509_NAME * name, const char *vals[])
{
    const char *field = *(vals++);
    while (field)
    {
        const unsigned char *val;
        val  = reinterpret_cast<const unsigned char *>(*(vals++));
        if (!val)
            return false;
        if (!X509_NAME_add_entry_by_txt(name, field,  MBSTRING_ASC, val, -1, -1, 0))
            return false;
        field = *(vals++);
    }
    return true;
}

/**
 *     Add extension using V3 code: we can set the config file as NULL
 *     because we wont reference any other sections.
 */
bool add_ext(X509 *cert, X509* issuer, int nid, const char *value) {

        X509_EXTENSION *ex;
        X509V3_CTX ctx;

        /* This sets the 'context' of the extensions. */
        /* No configuration database */
        X509V3_set_ctx_nodb(&ctx);

        /* Issuer and subject certs, no request and no CRL */
        X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
        ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
        if (!ex)
            return false;

        bool res = !!X509_add_ext(cert, ex, -1);
        X509_EXTENSION_free(ex);
        return res;
}

/* Generates a self-signed x509 certificate. */
auto generate_x509(EVP_PKEY *pkey, uint64_t serial, long days,
               const char *nameParts[], const certMaker::certExt extensions[], X509* issuer, EVP_PKEY *issuerKey)
{
    /* Allocate memory for the X509 structure. */
    auto x509 = wrap_unique(X509_new(), X509_free);
    if (!x509) 
        throw std::runtime_error("Unable to create X509 structure.");

    /* Set version. */
    if (!X509_set_version(x509.get(), 2))
        throw std::runtime_error("Unable to set certificate version.");

    /* Set the serial number. */
    if (!ASN1_INTEGER_set_uint64(X509_get_serialNumber(x509.get()), serial)) 
        throw std::runtime_error("Unable to set certificate serial.");

    /* This certificate is valid from now until exactly one year from now. */
    if (!X509_gmtime_adj(X509_getm_notBefore(x509.get()), 0))
        throw std::runtime_error("Unable to set certificate begin time.");

    if (!X509_gmtime_adj(X509_getm_notAfter(x509.get()),
                               days == 0 ? 0x7ffffffe - static_cast<long>(time(NULL)) : 60*60*24*days))
        throw std::runtime_error("Unable to set certificate end time.");

    /* Set the public key for our certificate. */
    if (!X509_set_pubkey(x509.get(), pkey)) 
        throw std::runtime_error("Unable to set certificate key.");

    /* Get the subject name. */
    X509_NAME * name = X509_get_subject_name(x509.get());
    if (!name) 
        throw std::runtime_error("Unable to get certificate name.");

    /* Set the country code and common name. */
    if (!name_add_entries(name, nameParts)) 
        throw std::runtime_error("Unable to set certificate subject name.");

    certMaker::certExt ext = *extensions;
    while(ext.nid && ext.value)
    {
        if (!add_ext(x509.get(), issuer ? issuer : x509.get(), ext.nid, ext.value)) 
            throw std::runtime_error("Unable to add extension");
        ext = *(++extensions);
    }

    /* Now set the issuer name. */
    if (issuer) /* We want to copy the subject name to the issuer name. */
    {
        name = X509_get_subject_name(issuer);
        if (!name) 
            throw std::runtime_error("Unable to get issuer cert name.");
    }
    if (!X509_set_issuer_name(x509.get(), name)) 
        throw std::runtime_error("Unable to set issuer name in certificate");

    /* Actually sign the certificate with our key. */
    if (!X509_sign(x509.get(), issuerKey ? issuerKey : pkey, EVP_sha256())) 
        throw std::runtime_error("Error signing certificate.");

    return x509;
}

} //namespace

bool certMaker::generateCert(const char *nameParts[], const certExt extensions[])
{
    try {
        m_key = generate_key(bits, exp);
        m_x509 = generate_x509(m_key.get(), serial, validDays, nameParts, extensions,
                               m_Ca?m_Ca->m_x509.get():nullptr, m_Ca?m_Ca->m_key.get():nullptr);
    }
    catch(const std::runtime_error &ex)
    {
        errMsg = ex.what();
        return false;
    }
    return true;
}


bool certMaker::writeKey(const char *fname, bool pem)
{
    bool ret;

    BIO * pkey_file = BIO_new_file(fname, "wb");
    if(!pkey_file)
    {
        errMsg = "Can't create file";
        return false;
    }
    /* Write the key to disk. */
    if (pem)
        ret = !!PEM_write_bio_PrivateKey(pkey_file, m_key.get(), NULL, NULL, 0, NULL, NULL);
    else
        ret = i2d_PrivateKey_bio(pkey_file, m_key.get()) > 0;

    BIO_free(pkey_file);

    if (!ret)
        errMsg = "Can't write private key";

    return ret;
}

bool certMaker::writeCert(const char *fname, bool pem)
{
    bool ret;

    BIO * x509_file = BIO_new_file(fname, "wb");
    if(!x509_file)
    {
        errMsg = "Can't create file";
        return false;
    }

    /* Write the certificate to disk. */
    if (pem)
        ret = !!PEM_write_bio_X509(x509_file, m_x509.get());
    else
        ret = i2d_X509_bio(x509_file, m_x509.get()) > 0;

    BIO_free(x509_file);

    if (!ret)
        errMsg = "Can't write certificate";

    return ret;
}

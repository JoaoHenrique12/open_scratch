#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>   // PKCS8_PRIV_KEY_INFO
#include <iostream>
#include <vector>
#include <cstring>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}


typedef struct slhdsa_key_material_t {
    unsigned long sizePrivateKey;
    unsigned long sizePublicKey;
    void* derPrivateKey;
    void* derPublicKey;

    slhdsa_key_material_t() {
        sizePrivateKey = 0;
        sizePublicKey = 0;
        derPrivateKey = 0;
        derPublicKey = 0;
    }
} slhdsa_key_material_t;


void crypto_free_slhdsa(slhdsa_key_material_t* keyMat)
{
    if (keyMat == NULL)
        return;

    if (keyMat->derPrivateKey)
        OPENSSL_free(keyMat->derPrivateKey);

    if (keyMat->derPublicKey)
        OPENSSL_free(keyMat->derPublicKey);

    free(keyMat);
}

slhdsa_key_material_t* crypto_malloc_slhdsa(EVP_PKEY* pkey)
{
    if (pkey == NULL)
        return NULL;

    slhdsa_key_material_t* keyMat =
        (slhdsa_key_material_t*)calloc(1, sizeof(slhdsa_key_material_t));
    if (keyMat == NULL)
        return NULL;

    unsigned char* buf = NULL;
    int len = 0;

    // --- DER encode public key (SubjectPublicKeyInfo) ---
    len = i2d_PUBKEY(pkey, NULL);
    if (len <= 0) {
        crypto_free_slhdsa(keyMat);
        return NULL;
    }
    buf = (unsigned char*)OPENSSL_malloc(len);
    if (!buf) {
        crypto_free_slhdsa(keyMat);
        return NULL;
    }
    unsigned char* p = buf;
    if (i2d_PUBKEY(pkey, &p) <= 0) {
        OPENSSL_free(buf);
        crypto_free_slhdsa(keyMat);
        return NULL;
    }
    keyMat->sizePublicKey = (unsigned long)len;
    keyMat->derPublicKey = buf;

    // --- DER encode private key (PKCS#8) ---
    len = i2d_PrivateKey(pkey, NULL);
    if (len <= 0) {
        crypto_free_slhdsa(keyMat);
        return NULL;
    }
    buf = (unsigned char*)OPENSSL_malloc(len);
    if (!buf) {
        crypto_free_slhdsa(keyMat);
        return NULL;
    }
    p = buf;
    if (i2d_PrivateKey(pkey, &p) <= 0) {
        OPENSSL_free(buf);
        crypto_free_slhdsa(keyMat);
        return NULL;
    }
    keyMat->sizePrivateKey = (unsigned long)len;
    keyMat->derPrivateKey = buf;

    return keyMat;
}


int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
    ERR_load_crypto_strings();

    EVP_PKEY_CTX* keygen_ctx = nullptr;
    EVP_PKEY* pkey = nullptr;

    // Generate SLH-DSA-SHA2-128f
    keygen_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "SLH-DSA-SHA2-128f", nullptr);
    if (!keygen_ctx) handleErrors();

    if (EVP_PKEY_keygen_init(keygen_ctx) <= 0) handleErrors();
    if (EVP_PKEY_keygen(keygen_ctx, &pkey) <= 0) handleErrors();

    EVP_PKEY_CTX_free(keygen_ctx);


	slhdsa_key_material_t* keyMat = crypto_malloc_slhdsa(pkey);

    std::cout << "key material:" << "\n";
    std::cout << "public:" << "(" << keyMat->sizePublicKey <<")" << keyMat->derPublicKey << "\n";
    std::cout << "private:" << "(" << keyMat->sizePrivateKey <<")" << keyMat->derPrivateKey << "\n";

    crypto_free_slhdsa(keyMat);

    return 0;
    // --- Save Private Key in DER (PKCS#8) ---
    std::vector<unsigned char> priv_der;
    {
        PKCS8_PRIV_KEY_INFO* p8inf = EVP_PKEY2PKCS8(pkey);
        if (!p8inf) handleErrors();
        int len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, nullptr);
        if (len <= 0) handleErrors();
        priv_der.resize(len);
        unsigned char* p = priv_der.data();
        if (i2d_PKCS8_PRIV_KEY_INFO(p8inf, &p) != len) handleErrors();
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        std::cout << "Private key (DER, PKCS#8) length: " << priv_der.size() << "\n";
    }

    // --- Save Public Key in DER (SubjectPublicKeyInfo) ---
    std::vector<unsigned char> pub_der;
    {
        int len = i2d_PUBKEY(pkey, nullptr);
        if (len <= 0) handleErrors();
        pub_der.resize(len);
        unsigned char* p = pub_der.data();
        if (i2d_PUBKEY(pkey, &p) != len) handleErrors();
        std::cout << "Public key (DER) length: " << pub_der.size() << "\n";
    }

    // --- Reconstruct Private Key from DER ---
    EVP_PKEY* pkey_from_der = nullptr;
    {
        const unsigned char* p = priv_der.data();
        PKCS8_PRIV_KEY_INFO* p8inf = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, priv_der.size());
        if (!p8inf) handleErrors();
        pkey_from_der = EVP_PKCS82PKEY(p8inf);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        if (!pkey_from_der) handleErrors();
    }

    // --- Reconstruct Public Key from DER ---
    EVP_PKEY* pub_from_der = nullptr;
    {
        const unsigned char* p = pub_der.data();
        pub_from_der = d2i_PUBKEY(nullptr, &p, pub_der.size());
        if (!pub_from_der) handleErrors();
    }

    // Message
    const char* msg = "SLH-DSA test message";
    size_t msg_len = strlen(msg);

    // Signing with reconstructed private key
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors();

    if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey_from_der) <= 0) handleErrors();

    size_t siglen = 0;
    if (EVP_DigestSign(mdctx, nullptr, &siglen, (const unsigned char*)msg, msg_len) <= 0) handleErrors();

    std::vector<unsigned char> sig(siglen);
    if (EVP_DigestSign(mdctx, sig.data(), &siglen, (const unsigned char*)msg, msg_len) <= 0) handleErrors();

    EVP_MD_CTX_free(mdctx);

    // Verifying with reconstructed public key
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors();

    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pub_from_der) <= 0) handleErrors();

    int verify_ok = EVP_DigestVerify(mdctx, sig.data(), siglen, (const unsigned char*)msg, msg_len);

    if (verify_ok == 1) {
        std::cout << "Signature verified successfully (with DER keys).\n";
    } else if (verify_ok == 0) {
        std::cout << "Signature verification failed.\n";
    } else {
        handleErrors();
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkey_from_der);
    EVP_PKEY_free(pub_from_der);
    ERR_free_strings();

    return 0;
}

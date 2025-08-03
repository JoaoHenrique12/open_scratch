#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <cstring>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // --- Key Generation ---
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SPHINCSSHA2128FSIMPLE, nullptr);
    if (!ctx) handleErrors();

    if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);

    const char* msg = "some important message.";
    size_t msg_len = strlen(msg);

    // --- Signing ---
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors();

    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) <= 0)
        handleErrors();

    size_t siglen = 0;
    if (EVP_DigestSign(mdctx, NULL, &siglen, (const unsigned char*)msg, msg_len) <= 0)
        handleErrors();

    std::vector<unsigned char> sig(siglen);
    if (EVP_DigestSign(mdctx, sig.data(), &siglen, (const unsigned char*)msg, msg_len) <= 0)
        handleErrors();

    EVP_MD_CTX_free(mdctx);

    // --- Verification ---
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors();

    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) <= 0)
        handleErrors();

    int ver = EVP_DigestVerify(mdctx, sig.data(), siglen, (const unsigned char*)msg, msg_len);
    if (ver == 1) {
        std::cout << "Signature verified.\n";
    } else if (ver == 0) {
        std::cout << "Invalid signature.\n";
    } else {
        handleErrors();
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

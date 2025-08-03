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
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
    // melhora a leitura das mensagens de erro ('human-readable')
    ERR_load_crypto_strings();

    EVP_PKEY_CTX* keygen_ctx = nullptr;
    EVP_PKEY* pkey = nullptr;

    // Gerando a chave SPHINCSSHA2128FSIMPLE
    keygen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SPHINCSSHA2128FSIMPLE, nullptr);
    if (!keygen_ctx) handleErrors();

    if (EVP_PKEY_keygen_init(keygen_ctx) <= 0) handleErrors();
    if (EVP_PKEY_keygen(keygen_ctx, &pkey) <= 0) handleErrors();

    EVP_PKEY_CTX_free(keygen_ctx);

    // Mensagem
    const char* msg = "SPHINCSSHA2128FSIMPLE test message";
    size_t msg_len = strlen(msg);

    // Assinando
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors();

    if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) handleErrors();

    size_t siglen = 0;
    if (EVP_DigestSign(mdctx, nullptr, &siglen, (const unsigned char*)msg, msg_len) <= 0) handleErrors();

    std::vector<unsigned char> sig(siglen);
    if (EVP_DigestSign(mdctx, sig.data(), &siglen, (const unsigned char*)msg, msg_len) <= 0) handleErrors();

    EVP_MD_CTX_free(mdctx);

    // Verificando
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors();

    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) handleErrors();

    int verify_ok = EVP_DigestVerify(mdctx, sig.data(), siglen, (const unsigned char*)msg, msg_len);

    if (verify_ok == 1) {
        std::cout << "Signature verified successfully.\n";
    } else if (verify_ok == 0) {
        std::cout << "Signature verification failed.\n";
    } else {
        handleErrors();
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    ERR_free_strings();

    return 0;
}

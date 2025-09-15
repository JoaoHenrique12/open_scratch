#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <iostream>
#include <vector>
#include <cstring>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// OPENSSL memory BIO (Basic I/O)
int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
    ERR_load_crypto_strings();

    EVP_PKEY_CTX* keygen_ctx = nullptr;
    EVP_PKEY* pkey = nullptr;

    // Gerando a chave SLH-DSA-SHA2-128f
    keygen_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "SLH-DSA-SHA2-128f", nullptr);
    if (!keygen_ctx) handleErrors();

    if (EVP_PKEY_keygen_init(keygen_ctx) <= 0) handleErrors();
    if (EVP_PKEY_keygen(keygen_ctx, &pkey) <= 0) handleErrors();

    EVP_PKEY_CTX_free(keygen_ctx);

    // Save private key string to a variable
    BIO* priv_bio = BIO_new(BIO_s_mem());
    if (!priv_bio) handleErrors();

    if (PEM_write_bio_PrivateKey(priv_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) <= 0) {
        BIO_free_all(priv_bio);
        handleErrors();
    }
    
    char* privkey_str = nullptr;
    long privkey_len = BIO_get_mem_data(priv_bio, &privkey_str);
    std::cout << "--- Private Key ---\n";
    std::cout.write(privkey_str, privkey_len);
    std::cout << privkey_str << '\n';
    std::cout << "\n";
    BIO_free_all(priv_bio);

    // Save public key string to a variable
    BIO* pub_bio = BIO_new(BIO_s_mem());
    if (!pub_bio) handleErrors();
    
    if (PEM_write_bio_PUBKEY(pub_bio, pkey) <= 0) {
        BIO_free_all(pub_bio);
        handleErrors();
    }
    
    char* pubkey_str = nullptr;
    long pubkey_len = BIO_get_mem_data(pub_bio, &pubkey_str);
    std::cout << "--- Public Key ---\n";
    std::cout.write(pubkey_str, pubkey_len);
    std::cout << "\n";
    BIO_free_all(pub_bio);

    // Mensagem
    const char* msg = "SLH-DSA test message";
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

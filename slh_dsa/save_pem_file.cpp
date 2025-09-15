#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <iostream>
#include <vector>
#include <cstring>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int write_keys_to_pem(EVP_PKEY* pkey) {
    // Write private key to file
    FILE* privkey_file = fopen("privkey.pem", "wb");
    if (!privkey_file) {
        std::cerr << "Error opening private key file.\n";
        return 0;
    }
    if (PEM_write_PrivateKey(privkey_file, pkey, nullptr, nullptr, 0, nullptr, nullptr) <= 0) {
        fclose(privkey_file);
        handleErrors();
    }
    fclose(privkey_file);
    std::cout << "Private key saved to 'privkey.pem'.\n";

    // Write public key to file
    FILE* pubkey_file = fopen("pubkey.pem", "wb");
    if (!pubkey_file) {
        std::cerr << "Error opening public key file.\n";
        return 0;
    }
    if (PEM_write_PUBKEY(pubkey_file, pkey) <= 0) {
        fclose(pubkey_file);
        handleErrors();
    }
    fclose(pubkey_file);
    std::cout << "Public key saved to 'pubkey.pem'.\n";

    return 1;
}

EVP_PKEY* read_public_key_from_pem(const char* filename) {
    FILE* pubkey_file = fopen(filename, "rb");
    if (!pubkey_file) {
        std::cerr << "Error opening public key file for reading.\n";
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(pubkey_file, nullptr, nullptr, nullptr);
    fclose(pubkey_file);
    return pkey;
}

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

    // Save keys to .pem files
    if (!write_keys_to_pem(pkey)) {
        EVP_PKEY_free(pkey);
        return 1;
    }

    // Load public key for verification (simulating a separate process)
    EVP_PKEY* pubkey = read_public_key_from_pem("pubkey.pem");
    if (!pubkey) {
        EVP_PKEY_free(pkey);
        return 1;
    }

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

    // Use the loaded public key for verification
    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pubkey) <= 0) handleErrors();

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
    EVP_PKEY_free(pubkey);
    ERR_free_strings();

    return 0;
}

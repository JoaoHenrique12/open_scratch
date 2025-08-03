# OpenSSL PQ

Este repositório apresenta como fazer o build da OpenSSL (3.5.1) para usar o SLH-DSA via
linha de comando e código C++ para: gerar um par de chaves, assinar e verificar
uma mensagem. Estas mesmas operações também são feitas para o SPHINCS+ utilizando
o fork da OpenSSL (1.1.1) da [Open Quantum Safe](https://github.com/open-quantum-safe/openssl?tab=readme-ov-file#quickstart),
apesar deste fork estar descontinuado, ele ainda é válido para realizar POCs (Proof Of Concept).

Ademais, atualmente (03/08/2025), a maneira de conectar os algoritmos da OQS com a OpenSSL é através do
[oqs-provider](https://github.com/open-quantum-safe/oqs-provider/), que espera um build da openssl 3.x.
Este repositório apresenta apenas dois 'builds', um da openssl 3.5.1 pura que usa o SLH-DSA e outro
da openssl 1.1.1 da OQS para usar o SPHINCS+.

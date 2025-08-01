FROM ubuntu:24.04 AS crypt_builder
RUN apt update && \
    apt install -y \
    cmake \
    gcc \
    libtool \
    libssl-dev \
    make \
    ninja-build \
    git  \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /crypt

# Get repos
RUN git clone --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git quantum_openssl
RUN git clone --branch main https://github.com/open-quantum-safe/liboqs.git

# Build liboqs
RUN cd liboqs && \
    mkdir build && \
    cd build && \
    cmake -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF -DCMAKE_INSTALL_PREFIX=/crypt/quantum_openssl/oqs .. && \
    ninja && \
    ninja install

# Build the fork
RUN cd quantum_openssl && \
    ./Configure linux-x86_64 -lm && \
    make -j4
CMD ["bash"]

# list algorithms
# ./openssl list -public-key-methods | grep -i sphincs

# private key
# ./openssl genpkey -algorithm sphincssha2128fsimple  -out sphincs_private.pem

# public key
# ./openssl pkey -in sphincs_private.pem -pubout -out sphincs_public.pem

# signing without hashing message
# ./openssl dgst -sign sphincs_private.pem -out message.sig message.txt

# verify
# ./openssl dgst -verify sphincs_public.pem -signature message.sig message.txt

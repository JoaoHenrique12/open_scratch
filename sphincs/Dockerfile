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
    build-essential \
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

RUN echo '/usr/local/lib' > /etc/ld.so.conf.d/oqs-openssl.conf && \
    ldconfig

ENV LD_LIBRARY_PATH=/usr/local/lib

RUN cd quantum_openssl && make install

WORKDIR /app
COPY main.cpp /app
RUN g++ -std=c++17 -Wall -o sphincs_example main.cpp \
  -I/usr/local/include \
  -L/usr/local/lib -lcrypto -lssl \
  -Wl,-rpath=/usr/local/lib

FROM ubuntu:24.04 AS final_image

COPY --from=crypt_builder /app /app

COPY --from=crypt_builder /crypt/quantum_openssl/apps/openssl /usr/local/bin/openssl
COPY --from=crypt_builder /crypt/quantum_openssl/libssl.so /usr/local/lib/
COPY --from=crypt_builder /crypt/quantum_openssl/libcrypto.so /usr/local/lib/
COPY --from=crypt_builder /crypt/quantum_openssl/oqs/lib/liboqs.so /usr/local/lib/

RUN echo '/usr/local/lib' > /etc/ld.so.conf.d/oqs-openssl.conf && \
    ldconfig

ENV LD_LIBRARY_PATH=/usr/local/lib

WORKDIR /app

CMD ["bash"]

# list algorithms
# openssl list -public-key-methods | grep -i sphincs

# private key
# openssl genpkey -algorithm sphincssha2128fsimple  -out sphincs_private.pem

# public key
# openssl pkey -in sphincs_private.pem -pubout -out sphincs_public.pem

# signing without hashing message
# openssl dgst -sign sphincs_private.pem -out message.sig message.txt

# verify
# openssl dgst -verify sphincs_public.pem -signature message.sig message.txt

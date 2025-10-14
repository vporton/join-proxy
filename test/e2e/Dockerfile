FROM rust:1.90

WORKDIR /usr/src/myapp

ENV DFXVM_INIT_YES=true
RUN curl -fsSL https://internetcomputer.org/install.sh | sh
ENV PATH=$HOME/.local/share/dfx/bin:$PATH
#RUN $HOME/.local/share/dfx/bin/dfxvm default 0.20.0

RUN apt-get update
RUN apt-get install -y openssl npm libunwind8 tini
RUN cargo install diesel_cli

RUN npm i -g ic-mops@1.11.1

COPY test/e2e/localhost.ext .

# Generate CA key
RUN openssl genrsa -out CA.key 2048
# Generate CA certificate
RUN openssl req -x509 -sha256 -new -nodes -key CA.key -out CA.pem -subj '/CN=local.vporton.name/O=My Company Name LTD./C=US'
# Generate localhost key
RUN openssl genrsa -out localhost.key 2048
# Generate localhost CSR
RUN openssl req -new -key localhost.key -out localhost.csr -subj '/CN=local.vporton.name/O=My Company Name LTD./C=US'
# Create a localhost.ext file for x509 extension if it does not exist
# RUN echo "subjectAltName = DNS:local.vporton.name" > localhost.ext
# Generate localhost certificate signed by CA
RUN openssl x509 -req -in localhost.csr \
                  -CA CA.pem -CAkey CA.key \
                  -CAcreateserial -sha256 \
                  -extfile localhost.ext -out localhost.crt
# Decrypt localhost key (remove passphrase)
RUN openssl rsa -in localhost.key -out localhost.decrypted.key
# Create directory for test certificates
RUN mkdir -p test/e2e/tmpl/
# Copy generated certificates to the test directory
RUN cp localhost.crt localhost.decrypted.key test/e2e/tmpl/
# Copy localhost certificate to the system CA store
RUN cp CA.pem /usr/local/share/ca-certificates/localhost.crt
# Update CA certificates
RUN update-ca-certificates

COPY proxy proxy
COPY test test
COPY Cargo.lock .
COPY Cargo.toml .
COPY motoko test/e2e/tmpl/motoko

# RUN cargo build
RUN cargo test --no-run -p e2e 
RUN cargo build -p join-proxy
RUN cargo build -p test-server
RUN export PATH=$HOME/.local/share/dfx/bin:$PATH && dfx cache install
RUN export PATH=$HOME/.local/share/dfx/bin:$PATH && cd test/e2e/tmpl/motoko && mops install

ENV PATH=$HOME/.local/share/dfx/bin:$PATH
# ENV RUST_LOG=info
ENV RUST_TEST_THREADS=1

ENTRYPOINT /usr/bin/tini -- sh -c "diesel migration run && cargo test -p e2e"

# Apache MINA SSHD PKCS#12 Demo (EC P-521)

This project demonstrates an SSH server and client using Apache MINA SSHD 2.16.0 with PKCS#12 certificates instead of OpenSSH key files.

## Quickstart

### 1. Generate certificates

```bash
chmod +x generate-certs.sh
./generate-certs.sh
```

### 2. Build

```bash
mvn clean package
```

### 3. Start the SSH server

```bash
cd server
mvn -Pserver exec:java
```

### 4. Run the SSH client

```bash
cd client
mvn -Pclient exec:java
```

The server only accepts connections from clients whose `.p12` matches the trusted certificate.

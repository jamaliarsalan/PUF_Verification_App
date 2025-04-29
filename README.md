# 🔐 PUF ECC Proof Verification

This project implements ECC-based cryptographic proof verification using the Mbed TLS library.

---

## 📋 Prerequisites
```bash
sudo apt install libmbedtls-dev
```
---


## 🚀 Usage Instructions

### 1. Configure the Input Parameters

Before running the application, open `main.c` and fill in the required input parameters:

- `Commitment` — The ECC commitment point
- `V` — Scalar value used in the proof
- `W` — Scalar value used in the proof
- `Nonce` — Random nonce for proof generation
- `Proof` — ECC point representing the proof

These values are usually provided as hex strings.

---

### 2. Build the Project

Run the following command to compile the project:

```bash
make
./puf_verify_app
```

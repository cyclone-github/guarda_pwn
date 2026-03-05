[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=guarda_pwn&theme=gruvbox)](https://github.com/cyclone-github/guarda_pwn/)

[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/guarda_pwn.svg)](https://github.com/cyclone-github/guarda_pwn/issues)
[![License](https://img.shields.io/github/license/cyclone-github/guarda_pwn.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/guarda_pwn.svg)](https://github.com/cyclone-github/guarda_pwn/releases)

### Install guarda_pwn
```
go install github.com/cyclone-github/guarda_pwn@main
```

---

### Tool to recover and decrypt Guarda Wallet backups

This tool decrypts **Guarda wallet backup files**.

Guarda backups are encrypted using **CryptoJS AES-256-CBC with OpenSSL**.

- Contact me at https://forum.hashpwn.net/user/cyclone if you need help recovering your Guarda wallet password or seed phrase

---

# Usage example

```
./guarda_pwn.bin -h guarda-wallet.txt -w wordlist.txt

 ------------------------------------ 
| Cyclone's Guarda Wallet Decryptor  |
 ------------------------------------ 

Hash file:      guarda-wallet.txt
Valid Hashes:   1
CPU Threads:    16
Wordlist:       wordlist.txt
Working...

Password:       'Cyclone!'
Decrypted:      {...}
```

---

# Supported options

```
-w {wordlist}
-h {hash file} (base64 Guarda backup)
-t {cpu threads}
-s {print status every nth sec}
-version (version info)
-help (usage instructions)
```

Example:

```
./guarda_pwn.bin -h guarda-wallet.txt -w wordlist.txt

./guarda_pwn.bin -h guarda-wallet.txt -w wordlist.txt -t 16 -s 10
```

---

# Guarda Wallet Backup Format

Guarda wallet backups are **Base64 encoded OpenSSL AES encrypted blobs**.

Example:

```
U2FsdGVkX19VhMBP5C1hK9....
```

Key derivation used by Guarda:

```
PBKDF2(password, "XB7sHH26Hn&FmPLxnjGccKTfPV(yk", 1 iteration, 16 bytes, SHA1)

hex(key) + postfix
```

The resulting passphrase is then used in **OpenSSL EVP_BytesToKey (MD5)** to derive:

```
AES-256 key
IV
```

---

# Compile from source

This assumes **Go and Git are installed**.

```
git clone https://github.com/cyclone-github/guarda_pwn.git
cd guarda_pwn
go mod init guarda_pwn
go mod tidy
go build -ldflags="-s -w" .
go install -ldflags="-s -w" .
```

---

### Compile from source guide

```
https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
```

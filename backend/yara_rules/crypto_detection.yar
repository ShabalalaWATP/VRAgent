/*
    Cryptography Detection Rules
    Detects encryption, cryptographic operations, and related indicators
*/

rule strong_crypto_constants
{
    meta:
        description = "Detects strong cryptography algorithm constants"
        severity = "info"
        category = "crypto"
    strings:
        // AES S-Box
        $aes_sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }

        // SHA-256 initial hash values
        $sha256_h0 = { 6A 09 E667 BB 67 AE85 3C 6E F372 }
        $sha256_const = { 428A2F98 71374491 B5C0FBCF E9B5DBA5 }

        // RSA public exponent (65537)
        $rsa_exp = { 01 00 01 00 }

        // ChaCha20 constants
        $chacha = "expand 32-byte k"

        // Salsa20 constants
        $salsa = "expand 16-byte k"

        // RC4 S-Box initialization
        $rc4_init = { 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 }

    condition:
        1 of them
}

rule crypto_api_usage
{
    meta:
        description = "Detects Windows cryptography API usage"
        severity = "info"
        category = "crypto"
    strings:
        // CryptoAPI functions
        $api1 = "CryptAcquireContext"
        $api2 = "CryptGenKey"
        $api3 = "CryptEncrypt"
        $api4 = "CryptDecrypt"
        $api5 = "CryptHashData"
        $api6 = "CryptSignHash"
        $api7 = "CryptVerifySignature"

        // CNG (Cryptography Next Generation)
        $cng1 = "BCryptOpenAlgorithmProvider"
        $cng2 = "BCryptGenerateSymmetricKey"
        $cng3 = "BCryptEncrypt"
        $cng4 = "BCryptDecrypt"

        // DPAPI
        $dpapi1 = "CryptProtectData"
        $dpapi2 = "CryptUnprotectData"

    condition:
        2 of ($api*) or
        2 of ($cng*) or
        1 of ($dpapi*)
}

rule openssl_library_usage
{
    meta:
        description = "Detects OpenSSL library usage"
        severity = "info"
        category = "crypto"
    strings:
        // OpenSSL function names
        $ssl1 = "SSL_CTX_new"
        $ssl2 = "SSL_connect"
        $ssl3 = "SSL_write"
        $ssl4 = "SSL_read"

        // EVP interface
        $evp1 = "EVP_EncryptInit"
        $evp2 = "EVP_DecryptInit"
        $evp3 = "EVP_DigestInit"

        // RSA functions
        $rsa1 = "RSA_public_encrypt"
        $rsa2 = "RSA_private_decrypt"

        // AES functions
        $aes1 = "AES_set_encrypt_key"
        $aes2 = "AES_encrypt"

        // OpenSSL version strings
        $ver = "OpenSSL" nocase

    condition:
        $ver or
        2 of ($ssl*) or
        2 of ($evp*) or
        1 of ($rsa*) or
        1 of ($aes*)
}

rule ransomware_crypto_indicators
{
    meta:
        description = "Detects crypto usage patterns common in ransomware"
        severity = "high"
        category = "crypto"
        malware_type = "ransomware"
    strings:
        // Hybrid encryption (RSA + AES)
        $rsa = "RSA" nocase
        $aes = "AES" nocase

        // Key exchange
        $kex1 = "public key" nocase
        $kex2 = "private key" nocase

        // File encryption loops
        $loop1 = "FindFirstFile"
        $loop2 = "FindNextFile"
        $loop3 = "CryptEncrypt"

        // Ransomware-specific crypto
        $ransom1 = "encrypt" nocase
        $ransom2 = "decrypt" nocase
        $ransom3 = "victim" nocase

    condition:
        ($rsa and $aes) and
        (2 of ($loop*)) and
        2 of ($ransom*)
}

rule custom_crypto_implementation
{
    meta:
        description = "Detects custom/homebrew cryptography (often weak)"
        severity = "medium"
        category = "crypto"
    strings:
        // XOR cipher
        $xor1 = { 30 ?? 40 }  // xor [reg], al; inc reg
        $xor2 = { 32 ?? 40 }  // xor al, [reg]; inc reg

        // ROL/ROR operations (common in weak crypto)
        $rol = { C1 C? ?? }  // rol/ror reg, imm
        $ror = { C1 C? ?? }

        // Simple byte permutation
        $perm = { 8A ?? ?? 88 ?? ?? }  // mov al, [x]; mov [y], al

        // Base64-like table
        $b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    condition:
        (#xor1 > 10 or #xor2 > 10) or
        (#rol > 20) or
        $b64
}

rule tls_ssl_pinning
{
    meta:
        description = "Detects TLS/SSL certificate pinning"
        severity = "info"
        category = "crypto"
    strings:
        // Certificate pinning strings
        $pin1 = "certificate pinning" nocase
        $pin2 = "public key pinning" nocase
        $pin3 = "SSL pinning" nocase

        // Certificate verification
        $cert1 = "X509_verify_cert"
        $cert2 = "SSL_get_peer_certificate"
        $cert3 = "CertVerifyCertificateChainPolicy"

        // Pin formats
        $sha256 = "sha256/" nocase
        $spki = "SPKI" nocase

    condition:
        1 of ($pin*) or
        2 of ($cert*) or
        1 of ($sha256, $spki)
}

rule bitcoin_crypto_operations
{
    meta:
        description = "Detects Bitcoin/cryptocurrency operations"
        severity = "info"
        category = "crypto"
    strings:
        // Bitcoin addresses
        $btc_addr1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        $btc_addr2 = /bc1[a-z0-9]{39,59}/

        // Cryptocurrency terms
        $crypto1 = "bitcoin" nocase
        $crypto2 = "ethereum" nocase
        $crypto3 = "monero" nocase
        $crypto4 = "wallet" nocase
        $crypto5 = "satoshi" nocase

        // Secp256k1 (Bitcoin's elliptic curve)
        $secp = "secp256k1" nocase

        // HD wallet derivation
        $hd1 = "BIP32" nocase
        $hd2 = "BIP44" nocase
        $hd3 = "m/44'/0'/0'" nocase

    condition:
        1 of ($btc_addr*) or
        2 of ($crypto*) or
        $secp or
        1 of ($hd*)
}

rule password_hash_algorithms
{
    meta:
        description = "Detects password hashing algorithms"
        severity = "info"
        category = "crypto"
    strings:
        // Modern algorithms
        $algo1 = "bcrypt" nocase
        $algo2 = "scrypt" nocase
        $algo3 = "argon2" nocase
        $algo4 = "PBKDF2" nocase

        // Legacy (weak) algorithms
        $weak1 = "MD5" nocase
        $weak2 = "SHA1" nocase
        $weak3 = "crypt()" nocase

        // Salt handling
        $salt1 = "salt" nocase
        $salt2 = "pepper" nocase

    condition:
        1 of ($algo*) or
        1 of ($weak*) or
        1 of ($salt*)
}

rule steganography_indicators
{
    meta:
        description = "Detects steganography (data hiding in files)"
        severity = "low"
        category = "crypto"
    strings:
        // Stego tools
        $tool1 = "steghide" nocase
        $tool2 = "openstego" nocase
        $tool3 = "outguess" nocase

        // LSB steganography
        $lsb1 = "least significant bit" nocase
        $lsb2 = "LSB" nocase

        // Image formats (common carriers)
        $img1 = "PNG" nocase
        $img2 = "BMP" nocase
        $img3 = "JPEG" nocase

        // Bit manipulation
        $bit1 = { 80 E? 01 }  // and reg, 1 (get LSB)
        $bit2 = { 83 E? 01 }  // and reg, 1

    condition:
        1 of ($tool*) or
        1 of ($lsb*) or
        (#bit1 > 20 or #bit2 > 20)
}

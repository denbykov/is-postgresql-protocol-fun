#pragma once

#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <iomanip>
#include <random>
#include <sstream>

namespace ippf::core {
    std::string to_hex_string(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        for (const auto& byte : data) {
            oss << "\\x" << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(byte);
        }
        return oss.str();
    }

    std::string generate_nonce(size_t length = 24) {
        static const char charset[] =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
        std::string nonce;
        nonce.reserve(length);
        for (size_t i = 0; i < length; ++i) nonce += charset[dist(gen)];
        return nonce;
    }

    std::string to_base64(const uint8_t* data, size_t length) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bio = BIO_new(BIO_s_mem());
        b64 = BIO_push(b64, bio);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(b64, data, static_cast<int>(length));
        BIO_flush(b64);
        BUF_MEM* bufferPtr;
        BIO_get_mem_ptr(b64, &bufferPtr);
        std::string base64Str(bufferPtr->data, bufferPtr->length);
        BIO_free_all(b64);
        return base64Str;
    }

    std::vector<uint8_t> from_base64(const std::string& base64Str) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bio = BIO_new_mem_buf(base64Str.data(),
                                   static_cast<int>(base64Str.size()));
        b64 = BIO_push(b64, bio);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        std::vector<uint8_t> buffer(base64Str.size());
        int length =
            BIO_read(b64, buffer.data(), static_cast<int>(buffer.size()));
        buffer.resize(length);
        BIO_free_all(b64);
        return buffer;
    }

    std::vector<uint8_t> derive_salted_password(
        const std::string& password, const std::vector<uint8_t>& salt,
        int iterations) {
        std::vector<uint8_t> salted_password(SHA256_DIGEST_LENGTH);

        PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt.data(),
                          salt.size(), iterations, EVP_sha256(),
                          salted_password.size(), salted_password.data());

        return salted_password;
    }

    std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key,
                                     const std::string& data) {
        unsigned int len = SHA256_DIGEST_LENGTH;
        uint8_t result[SHA256_DIGEST_LENGTH];

        HMAC(EVP_sha256(), key.data(), key.size(),
             reinterpret_cast<const uint8_t*>(data.c_str()), data.size(),
             result, &len);

        return std::vector<uint8_t>(result, result + len);
    }

    std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
        uint8_t hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, data.data(), data.size());
        SHA256_Final(hash, &sha256);

        return std::vector<uint8_t>(hash, hash + SHA256_DIGEST_LENGTH);
    }

    std::vector<uint8_t> xor_arrays(const std::vector<uint8_t>& a,
                                    const std::vector<uint8_t>& b) {
        std::vector<uint8_t> result;
        for (size_t i = 0; i < a.size(); ++i) {
            result.push_back(a[i] ^ b[i]);
        }
        return result;
    }
}  // namespace ippf::core
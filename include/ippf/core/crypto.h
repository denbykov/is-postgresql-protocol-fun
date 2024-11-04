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

        PKCS5_PBKDF2_HMAC(
            password.c_str(), static_cast<int>(password.size()), salt.data(),
            static_cast<int>(salt.size()), iterations, EVP_sha256(),
            static_cast<int>(salted_password.size()), salted_password.data());

        return salted_password;
    }

    std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key,
                                     const std::string& data) {
        unsigned int len = SHA256_DIGEST_LENGTH;
        uint8_t result[SHA256_DIGEST_LENGTH];

        HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
             reinterpret_cast<const uint8_t*>(data.c_str()), data.size(),
             result, &len);

        return std::vector<uint8_t>(result, result + len);
    }

    std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> hash(EVP_MD_size(EVP_sha256()));
        unsigned int hash_len = 0;

        // Create and initialize a digest context
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create context");
        }

        try {
            // Initialize the SHA-256 digest operation
            if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
                throw std::runtime_error("Digest initialization failed");
            }

            // Provide the data to be hashed
            if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
                throw std::runtime_error("Digest update failed");
            }

            // Finalize the digest and obtain the hash
            if (EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1) {
                throw std::runtime_error("Digest finalization failed");
            }

            // Resize the vector to the actual length of the hash
            hash.resize(hash_len);
        } catch (...) {
            EVP_MD_CTX_free(ctx);
            throw;
        }

        // Clean up
        EVP_MD_CTX_free(ctx);

        return hash;
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
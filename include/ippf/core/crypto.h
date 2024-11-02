#pragma once

#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <random>

namespace ippf::core {

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

    std::string to_base64(const unsigned char* data, size_t length) {
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

    std::vector<unsigned char> from_base64(const std::string& base64Str) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bio = BIO_new_mem_buf(base64Str.data(),
                                   static_cast<int>(base64Str.size()));
        b64 = BIO_push(b64, bio);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        std::vector<unsigned char> buffer(base64Str.size());
        int length =
            BIO_read(b64, buffer.data(), static_cast<int>(buffer.size()));
        buffer.resize(length);
        BIO_free_all(b64);
        return buffer;
    }

    std::string hmac_sha256(const std::string& key, const std::string& data) {
        unsigned char result[EVP_MAX_MD_SIZE];
        unsigned int result_len;
        HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
             (unsigned char*)data.data(), data.size(), result, &result_len);
        return std::string((char*)result, result_len);
    }

    std::string pbkdf2_hmac_sha256(const std::string& password,
                                   const std::string& salt, int iterations,
                                   int dklen) {
        std::vector<unsigned char> derived_key(dklen);
        PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                          (unsigned char*)salt.data(),
                          static_cast<int>(salt.size()), iterations,
                          EVP_sha256(), dklen, derived_key.data());
        return std::string((char*)derived_key.data(), derived_key.size());
    }

    std::string sha256(const std::string& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)data.data(), data.size(), hash);
        return std::string((char*)hash, SHA256_DIGEST_LENGTH);
    }

    std::string xor_strings(const std::string& str1, const std::string& str2) {
        std::string result;
        result.reserve(str1.size());
        for (size_t i = 0; i < str1.size(); ++i) {
            result.push_back(str1[i] ^ str2[i]);
        }
        return result;
    }
}  // namespace ippf::core
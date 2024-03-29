#include <openssl/evp.h>
#include <openssl/bio.h>
#include <string.h>
#include <string>
#include <algorithm>
#include "base64.hpp"


template char* base64_encode(uint8_t *message, size_t sz);
template char* base64_encode(char *message, size_t sz);

template uint8_t* base64_decode(char *message, size_t &sz);
template char* base64_decode(char *message, size_t &sz);

template char* base64url_encode(uint8_t *message, size_t sz);
template uint8_t* base64url_encode(uint8_t *message, size_t sz);

template char* base64url_decode(char *message, size_t &sz);
template uint8_t* base64url_decode(char *message, size_t &sz);

/* Base64エンコードを実施する関数。
 * T, Uはいずれもuint8_tの場合とcharの場合とで分かれる */
template<typename T, typename U>
T* base64_encode(U *message, size_t sz)
{
    BIO *bio_b64, *bio_mem;
    T *base64_tmp_str, *base64_str;
    int len;

    bio_b64 = BIO_new(BIO_f_base64());
    bio_mem = BIO_new(BIO_s_mem());

    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(bio_b64, bio_mem);

    if(BIO_write(bio_b64, (const char*)message, (int)sz) == -1)
    {
        BIO_free(bio_mem);
        BIO_free(bio_b64);
        return NULL;
    }

    BIO_flush(bio_b64);

    len = BIO_get_mem_data(bio_mem, &base64_tmp_str);
    base64_str = (T*)malloc(len + 1);

    if(base64_str == NULL)
    {
        BIO_free(bio_mem);
        BIO_free(bio_b64);
        return NULL;
    }

    memcpy(base64_str, base64_tmp_str, len);
    base64_str[len] = '\0';

    BIO_free(bio_mem);
    BIO_free(bio_b64);

    return base64_str;
}


/* Base64デコードを実施する関数。
 * T, Uはいずれもuint8_tの場合とcharの場合とで分かれる */
template<typename T, typename U>
T* base64_decode(U *message, size_t &sz)
{
    BIO *bio_b64, *bio_mem;
    T *decoded_text;
    size_t len = strlen((const char*)message);

    decoded_text = (T*)malloc(len + 1);
    if(decoded_text == NULL) return NULL;
    memset(decoded_text, '\0', len + 1);

    bio_b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);

    bio_mem = BIO_new_mem_buf(message, (int)len);

    BIO_push(bio_b64, bio_mem);

    sz = BIO_read(bio_b64, decoded_text, (int)len);
    if(sz == -1)
    {
        free(decoded_text);
        return NULL;
    }

    BIO_free_all(bio_mem);

    return decoded_text;
}


/* URL-safe Base64にエンコードする関数 */
template<typename T, typename U>
T* base64url_encode(U *message, size_t sz)
{
    std::string base64_str;

    base64_str = std::string(
        (char*)base64_encode<T, U>(message, sz));

    std::replace(base64_str.begin(), base64_str.end(), '+', '-');
    std::replace(base64_str.begin(), base64_str.end(), '/', '_');
    base64_str.erase(
        std::remove(base64_str.begin(), base64_str.end(), '='), base64_str.end());

    char *encoded_text = strdup(base64_str.c_str());

    return (T*)encoded_text;
}


/* URL-safe Base64をデコードする関数 */
template<typename T, typename U>
T* base64url_decode(U *message, size_t &sz)
{
    std::string message_str(message);
    std::replace(message_str.begin(), message_str.end(), '-', '+');
    std::replace(message_str.begin(), message_str.end(), '_', '/');

    while (message_str.size() % 4 != 0) {
        message_str.push_back('=');
    }

    T *decoded_text;

    decoded_text = base64_decode<T, U>((char*)message_str.c_str(), sz);

    return decoded_text;
}
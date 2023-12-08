#include <string>
#include <sstream>
#include <ctime>
#include <openssl/evp.h>
#include "../include/httplib.h"
#include "../include/json.hpp"
#include "crypto.hpp"
#include "debug_print.hpp"
#include "base64.hpp"

using namespace httplib;


/* JWKをオンラインで取得 */
int get_jwk_online(std::string base_url,
    std::string url_parts, std::string &jwk)
{
    Client client(base_url);

    auto res = client.Get(url_parts);

    if(res == NULL)
    {
        std::string message = "Unknown error. Probably Attestation Provider is down.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    std::string response_json;

    response_json = res->body;

    if(res->status == 200)
    {
        print_debug_message("Received JWK ->", DEBUG_LOG);
        print_debug_message(response_json, DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);
    }
    else
    {
        std::string message = "Unexpected error while getting RA report JWT.";
        print_debug_message(message, ERROR);
        print_debug_message("", ERROR);

        std::string status_code = "status code -> " + std::to_string(res->status);
        print_debug_message(status_code, ERROR);
        print_debug_message(res->body, ERROR);
        print_debug_message("", ERROR);
        
        return -1;
    }

    jwk = response_json;

    return 0;
}


/* JWKを用いてJWTの署名等を検証 */
int verify_jwt(std::string ra_report_jwt, 
    std::string jwk, std::string issuer)
{
    /* JWTをヘッダ、ペイロード、署名に分割 */
    std::string header, payload, signature = "";
    std::stringstream jwt_ss(ra_report_jwt);

    if(!(std::getline(jwt_ss, header, '.')
        && std::getline(jwt_ss, payload, '.')
        && std::getline(jwt_ss, signature, '.')))
    {
        std::string error_message = "Invalid JWT format.";
        print_debug_message(error_message, ERROR);
        print_debug_message("", ERROR);

        return -1;
    }
    else if(signature == "")
    {
        std::string error_message = "Invalid JWT format.";
        print_debug_message(error_message, ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_message("JWT Header ->", DEBUG_LOG);
    print_debug_message(header, DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("JWT Payload ->", DEBUG_LOG);
    print_debug_message(payload, DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("JWT Signature ->", DEBUG_LOG);
    print_debug_message(signature, DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    /* JWTのデコード */
    size_t sz;
    std::string decoded_header = 
        std::string(base64url_decode<char, char>(
            (char*)header.c_str(), sz));

    std::string decoded_payload = 
        std::string(base64url_decode<char, char>(
            (char*)payload.c_str(), sz));

    json::JSON header_json = json::JSON::Load(decoded_header);
    json::JSON payload_json = json::JSON::Load(decoded_payload);

    print_debug_message("Decoded JWT Header ->", DEBUG_LOG);
    print_debug_message(header_json.dump(), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    print_debug_message("Decoded JWT Payload ->", DEBUG_LOG);
    print_debug_message(payload_json.dump(), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    /* 署名アルゴリズムの制限。現状はRS256のみ */
    if(header_json["alg"].ToString() != "RS256")
    {
        print_debug_message("Only RS256 algorithm can be accepted.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    /* JWKの鍵IDを抽出 */
    std::string jwt_keyid = header_json["kid"].ToString();
    json::JSON jwk_json_obj = json::JSON::Load(jwk);
    size_t keys_num = jwk_json_obj["keys"].size();

    std::string message = 
        "The number of keys in JWK -> " + std::to_string(keys_num);
    print_debug_message(message, DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    int jwk_key_index = -1;

    for(int i = 0; i < keys_num; i++)
    {
        if(jwk_json_obj["keys"][i]["kid"].ToString() == jwt_keyid)
            jwk_key_index = i;
    }

    if(jwk_key_index == -1)
    {
        print_debug_message("Invalid JWK. No corresponding key was found.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    if(jwk_json_obj["keys"][jwk_key_index]["n"].IsNull()
        || jwk_json_obj["keys"][jwk_key_index]["e"].IsNull())
    {
        std::string error_message;
        error_message = "Invalid JWK. It doesn't have n and e of RSA.";
        print_debug_message(error_message, ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    std::string modulus_b64 = 
        jwk_json_obj["keys"][jwk_key_index]["n"].ToString();

    std::string exponent_b64 = 
        jwk_json_obj["keys"][jwk_key_index]["e"].ToString();

    size_t modulus_size, exponent_size;
    
    uint8_t *rsa_modulus = base64url_decode<uint8_t, char>(
        (char*)modulus_b64.c_str(), modulus_size);

    uint8_t *rsa_exponent = base64url_decode<uint8_t, char>(
        (char*)exponent_b64.c_str(), exponent_size);

    EVP_PKEY *rsa_pubkey;

    /* バイナリ形式のモジュラスと指数からEVP形式のRSA公開鍵を生成 */
    rsa_pubkey = evp_rsa_pubkey_from_rawdata(
        rsa_modulus, modulus_size, rsa_exponent, exponent_size);

    if(rsa_pubkey == NULL)
    {
        print_debug_message("Failed to convert raw keys to RSA EVP key.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    /* JWTの署名対象を作成 */
    std::string sign_target = header + "." + payload;
    int retval = 0;
    size_t signature_size;

    uint8_t *signature_u8 = base64url_decode<uint8_t, char>(
        (char*)signature.c_str(), signature_size);

    print_debug_binary("JWT signature in hex format", 
        signature_u8, signature_size, DEBUG_LOG);

    if(sha256_verify((const uint8_t*)sign_target.c_str(), sign_target.length(), 
        signature_u8, signature_size, rsa_pubkey, &retval))
    {
        print_debug_message("Failed to operate signature validation.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }
    else if(retval)
    {
        std::string message = "Invalid report signature.";
        print_debug_message(message, ERROR);
        return -1;
    }

    print_debug_message("JWT signature matched.", INFO);
    print_debug_message("", INFO);


    /* JWT自体の各種メタデータの検証。まずはIssuerから */
    if(payload_json["iss"].IsNull())
    {
        print_debug_message("Invalid JWT format. Issuer was not found", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }
    else if(payload_json["iss"].ToString() != issuer)
    {
        print_debug_message("JWT Issuer mismatched.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_message("JWT issuer matched.", INFO);
    print_debug_message("", INFO);

    //タイムスタンプの検証
    std::time_t timestamp = std::time(0);
    uint64_t timestamp_min, timestamp_max;

    if(payload_json["iat"].IsNull() || payload_json["exp"].IsNull())
    {
        print_debug_message("Invalid JWT format. timestamp was not found", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    timestamp_min = payload_json["iat"].ToInt();
    timestamp_max = payload_json["exp"].ToInt();

    if(timestamp < timestamp_min || timestamp > timestamp_max)
    {
        print_debug_message("JWT is expired or has illegal timestamp.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_message("JWT timestamp is valid.", INFO);
    print_debug_message("", INFO);

    print_debug_message(
        "Received RA report JWT is valid. Proceed to next operation.", INFO);
    print_debug_message("", INFO);

    return 0;
}
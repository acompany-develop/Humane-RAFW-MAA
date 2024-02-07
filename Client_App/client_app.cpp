#include <sgx_report.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include <iostream>
#include <string>
#include <algorithm>
#include <string.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../include/httplib.h"
#include "../include/ini.h"
#include "../include/json.hpp"
#include "../common/base64.hpp"
#include "../common/debug_print.hpp"
#include "../common/hexutil.hpp"
#include "../common/crypto.hpp"
#include "../common/jwt_util.hpp"

using namespace httplib;


/* 双方のセッション公開鍵の連結に対する署名に使用するための
 * 256bit ECDSA秘密鍵。RA中に生成するセッション鍵とは別物。 */
static const uint8_t g_client_signature_private_key[32] = {
    0xef, 0x5c, 0x38, 0xb7, 0x6d, 0x4e, 0xed, 0xce,
    0xde, 0x3b, 0x77, 0x2d, 0x1b, 0x8d, 0xa7, 0xb9,
    0xef, 0xdd, 0x60, 0xd1, 0x22, 0x50, 0xcc, 0x90,
    0xc3, 0xb5, 0x17, 0x54, 0xdc, 0x2f, 0xe5, 0x18
};


/* settingsファイルからロードした値を格納する構造体 */
typedef struct client_settings_struct
{
    std::string maa_url;
    std::string maa_api_version;
    uint32_t client_id;
    uint16_t min_isv_svn;
    uint16_t req_isv_prod_id;
    std::string req_mrenclave;
    std::string req_mrsigner;
    bool skip_mrenclave_check;
} settings_t;

settings_t g_settings;

/* RAセッション中に発生する鍵関係コンテキスト用構造体 */
typedef struct ra_session_struct
{
    uint8_t g_a[64];
    uint8_t g_b[64];
    uint8_t kdk[16];
    uint8_t vk[16];
    uint8_t sk[16];
    uint8_t mk[16];
} ra_session_t;


/* クライアント向けのsgx_ec256_signature_tの定義 */
typedef struct _client_sgx_ec256_signature_t
{
    uint32_t x[8];
    uint32_t y[8];
} client_sgx_ec256_signature_t;


/* iniファイルから読み込み、失敗時にはプログラムを即時終了する */
std::string load_from_ini(std::string section, std::string key)
{
    mINI::INIFile file("settings_client.ini");
    mINI::INIStructure ini;

    if(!file.read(ini))
    {
        std::string message = "file read error";
        print_debug_message(message, ERROR);
        exit(1);
    }
    std::string ret = ini.get(section).get(key);

    if(ret.length() == 0)
    {
        std::string message = "Failed to load setting " 
            + key + " from settings_client.ini.";
        print_debug_message(message, ERROR);
        exit(1); 
    }

    return ret;
}


/* 設定情報の読み込み */
void load_settings()
{
    try
    {
        g_settings.maa_url = load_from_ini("client", "MAA_URL");
        g_settings.maa_api_version = load_from_ini("client", "MAA_API_VERSION");
        g_settings.client_id = std::stoi(load_from_ini("client", "CLIENT_ID"));
        g_settings.min_isv_svn = std::stoi(load_from_ini("client", "MINIMUM_ISVSVN"));
        g_settings.req_isv_prod_id = std::stoi(load_from_ini("client", "REQUIRED_ISV_PROD_ID"));
        g_settings.req_mrenclave = load_from_ini("client", "REQUIRED_MRENCLAVE");
        g_settings.req_mrsigner = load_from_ini("client", "REQUIRED_MRSIGNER");
    }
    catch(...)
    {
        print_debug_message(
            "Invalid setting. Probably non-integer value was set illegally.", ERROR);
        print_debug_message("", ERROR);

        exit(1);
    }
    
    uint32_t skip_flag = std::stoi(load_from_ini("client", "SKIP_MRENCLAVE_CHECK"));

    if(!(skip_flag == 0 || skip_flag == 1))
    {
        print_debug_message("MRENCLAVE check skip flag must be 0 or 1.", ERROR);
        print_debug_message("", ERROR);

        exit(1);
    }

    g_settings.skip_mrenclave_check = skip_flag;
}


/* RAの初期化 */
int initialize_ra(std::string server_url, 
    std::string &ra_ctx_b64, ra_session_t &ra_keys)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Initialize RA", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    json::JSON req_json_obj;

    std::string client_id_str = std::to_string(g_settings.client_id);

    std::string client_id_b64 = std::string(
        base64_encode<char, char>((char*)client_id_str.c_str(), 
            client_id_str.length()));
    
    req_json_obj["client_id"] = client_id_b64;
    std::string request_json = req_json_obj.dump();

    Client client(server_url);
    auto res = client.Post("/init-ra", request_json, "application/json");

    if(res == NULL)
    {
        std::string message = "Unknown error. Probably SGX server is down.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    std::string response_json;
    json::JSON res_json_obj;

    response_json = res->body;
    res_json_obj = json::JSON::Load(response_json);

    if(res->status == 200)
    {
        char *ra_ctx_char;
        size_t ra_ctx_size;

        /* base64形式のRAコンテキストを取得 */
        ra_ctx_b64 = res_json_obj["ra_context"].ToString();

        /* Base64デコード */
        ra_ctx_char = base64_decode<char, char>(
            (char*)res_json_obj["ra_context"].ToString().c_str(), ra_ctx_size);
        
        uint32_t ra_ctx = (uint32_t)std::stoi(ra_ctx_char);

        std::string message_ra_ctx =
            "Received RA context number -> " + std::to_string(ra_ctx);
        print_debug_message(message_ra_ctx, DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        /* サーバ側のセッション公開鍵を取得 */
        uint8_t *ga_x, *ga_y;
        size_t tmpsz;

        ga_x = base64_decode<uint8_t, char>(
            (char*)res_json_obj["g_a"]["gx"].ToString().c_str(), tmpsz);

        if(tmpsz != 32)
        {
            print_debug_message("Corrupted server pubkey Ga.g_x.", ERROR);
            print_debug_message("", ERROR);

            return -1;
        }

        ga_y = base64_decode<uint8_t, char>(
            (char*)res_json_obj["g_a"]["gy"].ToString().c_str(), tmpsz);

        if(tmpsz != 32)
        {
            print_debug_message("Corrupted server pubkey Ga.g_y.", ERROR);
            print_debug_message("", ERROR);

            return -1;
        }

        memcpy(ra_keys.g_a, ga_x, 32);
        memcpy(&ra_keys.g_a[32], ga_y, 32);

        print_debug_message("Base64-encoded x-coordinate of Ga ->", DEBUG_LOG);
        print_debug_message(res_json_obj["g_a"]["gx"].ToString(), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);
        print_debug_message("Base64-encoded y-coordinate of Ga ->", DEBUG_LOG);
        print_debug_message(res_json_obj["g_a"]["gy"].ToString(), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        print_debug_binary("x-coordinate of Ga", ra_keys.g_a, 32, DEBUG_LOG);
        print_debug_binary("y-coordinate of Ga", &ra_keys.g_a[32], 32, DEBUG_LOG);

        free(ga_x);
        free(ga_y);
    }
    else if(res->status == 500)
    {
        char *error_message;
        size_t error_message_size;

        error_message = base64_decode<char, char>(
            (char*)res_json_obj["error_message"].ToString().c_str(), error_message_size);

        print_debug_message(std::string(error_message), ERROR);

        return -1;
    }
    else
    {
        std::string message = "Unexpected error while initializing RA.";
        print_debug_message(message, ERROR);
        
        return -1;
    }

    return 0;
}


/* KDK（鍵導出鍵）の導出 */
int generate_kdk(EVP_PKEY *Gb, ra_session_t &ra_keys)
{
    EVP_PKEY *Ga; //ISV側のキーペア（EVP形式）
    uint8_t *Gab_x; //共有秘密
    uint8_t *cmac_key = new uint8_t[16](); //0埋めしてCMACの鍵として使用する
    size_t secret_len;

    /* ISVの鍵をsgx_ec256_public_tからEVP_PKEYに変換 */
    client_sgx_ec256_public_t ga_sgx;
    memcpy(ga_sgx.gx, ra_keys.g_a, 32);
    memcpy(ga_sgx.gy, &ra_keys.g_a[32], 32);

    Ga = evp_pubkey_from_sgx_ec256(&ga_sgx);

    if(Ga == NULL)
    {
        std::string message = "Failed to convert Ga from sgx_ec256_public_t.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* 共有秘密を導出する */
    Gab_x = derive_shared_secret(Ga, Gb, secret_len);

    if(Gab_x == NULL)
    {
        std::string message = "Failed to derive shared secret.";
        print_debug_message(message, ERROR);
        return -1;
    }

    print_debug_binary("shared secret Gab_x", Gab_x, secret_len, DEBUG_LOG);


    /* 共有秘密をリトルエンディアン化 */
    std::reverse(Gab_x, Gab_x + secret_len);

    print_debug_binary(
        "reversed shared secret Gab_x", Gab_x, secret_len, DEBUG_LOG);

    /* CMAC処理を実行してKDKを導出 */
    aes_128bit_cmac(cmac_key, Gab_x, secret_len, ra_keys.kdk);

    print_debug_binary("KDK", ra_keys.kdk, 16, DEBUG_LOG);

    delete[] cmac_key;

    return 0;
}


/* セッションキーペア、共有秘密、SigSPの生成 */
int process_session_keys(ra_session_t &ra_keys, 
    client_sgx_ec256_signature_t &sigsp)
{
    /* クライアント側セッションキーペアの生成 */
    EVP_PKEY *Gb;
    Gb = evp_pkey_generate();

    if(Gb == NULL)
    {
        std::string message = "Failed to generate SP's key pair.";
        print_debug_message(message, ERROR);
        print_debug_message("", ERROR);
        
        return -1;
    }

    int ret = generate_kdk(Gb, ra_keys);

    if(ret)
    {
        std::string message = "Failed to derive KDK.";
        print_debug_message(message, ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    /* SPのキーペア公開鍵Gbをsgx_ec256_public_tに変換 */
    client_sgx_ec256_public_t gb_sgx;
    ret = evp_pubkey_to_sgx_ec256(&gb_sgx, Gb);

    if(ret)
    {
        std::string message = "Failed to convert Gb to sgx_ec256_public_t.";
        print_debug_message(message, ERROR);
        return -1;
    }

    memcpy(ra_keys.g_b, gb_sgx.gx, 32);
    memcpy(&ra_keys.g_b[32], gb_sgx.gy, 32);

    print_debug_binary("x-coordinate of Gb", ra_keys.g_b, 32, DEBUG_LOG);
    print_debug_binary("y-coordinate of Gb", &ra_keys.g_b[32], 32, DEBUG_LOG);

    /* SigSPの元となる公開鍵の連結を格納する変数 */
    uint8_t gb_ga[128];

    memcpy(gb_ga, ra_keys.g_b, 64);
    memcpy(&gb_ga[64], ra_keys.g_a, 64);

    print_debug_binary("Gb_Ga", gb_ga, 128, DEBUG_LOG);

    /* SigSP（Gb_Gaのハッシュに対するECDSA署名）の生成 */
    uint8_t r[32], s[32];

    EVP_PKEY *sig_priv_key = 
        evp_private_key_from_bytes(g_client_signature_private_key);

    ret = ecdsa_sign(gb_ga, 128, sig_priv_key, r, s);

    if(ret)
    {
        print_debug_message("Failed to sign to Gb_Ga.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_binary("signature r", r, 32, DEBUG_LOG);
    print_debug_binary("signature s", s, 32, DEBUG_LOG);
    
    /* ECDSA署名r, sをリトルエンディアン化 */
    std::reverse(r, r + 32);
    std::reverse(s, s + 32);

    /* sgx_ec256_signature_tがuint32_t[8]で署名を格納する仕様なので、
     * 強引だがuint8_tポインタで参照し1バイトごとに流し込む */
    uint8_t *p_sigsp_r = (uint8_t*)sigsp.x;
    uint8_t *p_sigsp_s = (uint8_t*)sigsp.y;

    for(int i = 0; i < 32; i++)
    {
        p_sigsp_r[i] = r[i];
        p_sigsp_s[i] = s[i];
    }

    print_debug_binary("reversed signature r",
        (uint8_t*)sigsp.x, 32, DEBUG_LOG);
    print_debug_binary("reversed signature s",
        (uint8_t*)sigsp.y, 32, DEBUG_LOG);

    return 0; 
}


/* Quoteの取得 */
int get_quote(std::string server_url, std::string ra_ctx_b64, 
    ra_session_t ra_keys, client_sgx_ec256_signature_t sigsp, 
    std::string &quote_json)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Get Quote", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    Client client(server_url);
    json::JSON req_json_obj, res_json_obj;
    std::string request_json;

    std::string gb_x_b64, gb_y_b64, sigsp_x_b64, sigsp_y_b64;

    gb_x_b64 = std::string(
        base64_encode<char, uint8_t>(ra_keys.g_b, 32));
    gb_y_b64 = std::string(
        base64_encode<char, uint8_t>(&ra_keys.g_b[32], 32));

    sigsp_x_b64 = std::string(
        base64_encode<char, uint8_t>((uint8_t*)sigsp.x, 32));
    sigsp_y_b64 = std::string(
        base64_encode<char, uint8_t>((uint8_t*)sigsp.y, 32));

    print_debug_message("Base64-encoded Gb and SigSP:", DEBUG_LOG);
    print_debug_message("Gb_x -> " + gb_x_b64, DEBUG_LOG);
    print_debug_message("Gb_y -> " + gb_y_b64, DEBUG_LOG);
    print_debug_message("SigSP_x -> " + sigsp_x_b64, DEBUG_LOG);
    print_debug_message("SigSP_y -> " + sigsp_y_b64, DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    std::string client_id_str = std::to_string(g_settings.client_id);

    std::string client_id_b64 = std::string(
        base64_encode<char, char>((char*)client_id_str.c_str(), 
            client_id_str.length()));
    
    req_json_obj["client_id"] = client_id_b64;
    req_json_obj["ra_context"] = ra_ctx_b64;
    req_json_obj["g_b"]["gx"] = gb_x_b64;
    req_json_obj["g_b"]["gy"] = gb_y_b64;
    req_json_obj["sigsp"]["x"] = sigsp_x_b64;
    req_json_obj["sigsp"]["y"] = sigsp_y_b64;
    request_json = req_json_obj.dump();


    auto res = client.Post("/get-quote", request_json, "application/json");

    if(res == NULL)
    {
        std::string message = "Unknown error. Probably SGX server is down.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    std::string response_json;

    response_json = res->body;
    res_json_obj = json::JSON::Load(response_json);

    if(res->status == 200)
    {
        //VKの生成
        aes_128bit_cmac(ra_keys.kdk, 
        (uint8_t*)("\x01VK\x00\x80\x00"), 6, ra_keys.vk);

        print_debug_binary("VK", ra_keys.vk, 16, DEBUG_LOG);

        uint8_t *ga_gb_vk = new uint8_t[144]();
        memcpy(ga_gb_vk, ra_keys.g_a, 64);
        memcpy(&ga_gb_vk[64], ra_keys.g_b, 64);
        memcpy(&ga_gb_vk[128], ra_keys.vk, 16);

        std::string original_data = 
            std::string(base64_encode<char, uint8_t>(ga_gb_vk, 144));

        print_debug_message("Ga_Gb_VK -> ", DEBUG_LOG);
        print_debug_message(original_data, DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        //Report DataがGa、Gb、VKの連結に対するハッシュ値であるかをMAAに保証してもらう
        res_json_obj["runtimeData"]["data"] = original_data;

        quote_json = res_json_obj.dump();

        print_debug_message("Received Quote JSON ->", DEBUG_LOG);
        print_debug_message(quote_json, DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);
    }
    else if(res->status == 500)
    {
        char *error_message;
        size_t error_message_size;

        error_message = base64_decode<char, char>(
            (char*)res_json_obj["error_message"].ToString().c_str(), error_message_size);

        print_debug_message(std::string(error_message), ERROR);

        return -1;
    }
    else
    {
        std::string message = "Unexpected error while getting quote.";
        print_debug_message(message, ERROR);
        
        return -1;
    }

    return 0;
}


/* MAAにQuoteを送信し検証する */
int send_quote_to_maa(std::string quote_json, std::string &ra_report_jwt)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Send Quote to MAA", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    Client client(g_settings.maa_url);
    json::JSON res_json_obj;

    std::string url_parts = "/attest/SgxEnclave?api-version=";
    url_parts += g_settings.maa_api_version;

    auto res = client.Post(url_parts, quote_json, "application/json");

    if(res == NULL)
    {
        std::string message = "Unknown error. Probably Attestation Provider is down.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    std::string response_json;

    response_json = res->body;
    res_json_obj = json::JSON::Load(response_json);

    if(res->status == 200)
    {
        print_debug_message("Received RA report JWT ->", DEBUG_LOG);
        print_debug_message(response_json, DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);
    }
    else if(res->status == 400)
    {
        std::string status_code = "status code -> " + std::to_string(res->status);
        print_debug_message(status_code, ERROR);
        print_debug_message(res->body, ERROR);
        print_debug_message("", ERROR);

        std::string message = "Probably Quote is compromised or invalid.";
        print_debug_message(message, ERROR);
        print_debug_message("", ERROR);
        
        return -1;
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

    ra_report_jwt = res_json_obj["token"].ToString();

    return 0;
}


/* サーバEnclaveの各種同一性の検証を行う */
int verify_enclave(std::string ra_report_jwt, 
    std::string quote_json, ra_session_t ra_keys)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Verify Enclave identity", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    std::stringstream jwt_ss(ra_report_jwt);
    std::string line;

    if(!(std::getline(jwt_ss, line, '.')
        && std::getline(jwt_ss, line, '.')))
    {
        std::string error_message = "Invalid JWT format.";
        print_debug_message(error_message, ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    size_t jwt_payload_size;
    json::JSON jwt_obj = json::JSON::Load(
        std::string(base64url_decode<char, char>(
            (char*)line.c_str(), jwt_payload_size)));

    json::JSON quote_json_obj = json::JSON::Load(quote_json);
    
    size_t quote_size;
    uint8_t *qe3_quote = base64url_decode<uint8_t, char>(
        (char*)quote_json_obj["quote"].ToString().c_str(), quote_size);

    uint8_t *quote_mrenclave = new uint8_t[32]();
    uint8_t *quote_mrsigner = new uint8_t[32]();
    uint16_t quote_isvprodid = 0;
    uint16_t quote_isvsvn = 0;
    uint8_t *quote_upper_data = new uint8_t[32]();

    /* 境界外参照の抑止 */
    if(368 + 32 > quote_size)
    {
        print_debug_message("Corrupted Quote structure.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    //112はsgx_quote3_t内のsgx_report_data_t内までのオフセット。以下同様
    memcpy(quote_mrenclave, qe3_quote + 112, 32);

    memcpy(quote_mrsigner, qe3_quote + 176, 32);
    memcpy(&quote_isvprodid, qe3_quote + 304, 2);
    memcpy(&quote_isvsvn, qe3_quote + 306, 2);
    memcpy(quote_upper_data, qe3_quote + 368, 32);

    std::string q_mrenclave_hex, q_mrsigner_hex;

    q_mrenclave_hex = std::string(to_hexstring(quote_mrenclave, 32));
    q_mrsigner_hex = std::string(to_hexstring(quote_mrsigner, 32));

    /* MRENCLAVEのチェック */
    if(g_settings.skip_mrenclave_check == false)
    {
        print_debug_message("Required MRENCLAVE ->", DEBUG_LOG);
        print_debug_message(g_settings.req_mrenclave, DEBUG_LOG);
        print_debug_message("MRENCLAVE from Quote ->", DEBUG_LOG);
        print_debug_message(q_mrenclave_hex, DEBUG_LOG);
        

        //要求値とQuote内の要素との比較
        if(g_settings.req_mrenclave != q_mrenclave_hex)
        {
            print_debug_message("", ERROR);
            print_debug_message("MRENCLAVE mismatched. Reject RA.", ERROR);
            print_debug_message("", ERROR);

            return -1;
        }

        print_debug_message("MRENCLAVE from MAA RA report ->", DEBUG_LOG);
        print_debug_message(jwt_obj["x-ms-sgx-mrenclave"].ToString(), DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);

        //要求値とRA応答エントリ内の要素との比較
        if(g_settings.req_mrenclave != jwt_obj["x-ms-sgx-mrenclave"].ToString())
        {
            print_debug_message("", ERROR);
            print_debug_message("MRENCLAVE in the RA report is corrupted.", ERROR);
            print_debug_message("", ERROR);

            return -1;
        }

        print_debug_message("MRENCLAVE matched.", INFO);
        print_debug_message("", INFO);
    }

    /* MRSIGNERのチェック */
    //要求値とQuote内の要素との比較
    print_debug_message("Required MRSIGNER ->", DEBUG_LOG);
    print_debug_message(g_settings.req_mrsigner, DEBUG_LOG);
    print_debug_message("MRSIGNER from Quote ->", DEBUG_LOG);
    print_debug_message(q_mrsigner_hex, DEBUG_LOG);

    if(g_settings.req_mrsigner != q_mrsigner_hex)
    {
        print_debug_message("", ERROR);
        print_debug_message("MRSIGNER mismatched. Reject RA.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_message("MRSIGNER from MAA RA report ->", DEBUG_LOG);
    print_debug_message(jwt_obj["x-ms-sgx-mrsigner"].ToString(), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    //要求値とRA応答エントリ内の要素との比較
    if(g_settings.req_mrsigner != jwt_obj["x-ms-sgx-mrsigner"].ToString())
    {
        print_debug_message("", ERROR);
        print_debug_message("MRSIGNER in the RA report is corrupted.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_message("MRSIGNER matched.", INFO);
    print_debug_message("", INFO);


    /* ISVSVNのチェック */
    //要求値とQuote内の要素との比較
    print_debug_message("Required ISVSVN ->", DEBUG_LOG);
    print_debug_message(std::to_string(g_settings.min_isv_svn), DEBUG_LOG);
    print_debug_message("ISVSVN from Quote ->", DEBUG_LOG);
    print_debug_message(std::to_string(quote_isvsvn), DEBUG_LOG);

    if(g_settings.min_isv_svn > quote_isvsvn)
    {
        print_debug_message("", ERROR);
        print_debug_message("Insufficient ISVSVN. Reject RA.", ERROR);
        print_debug_message("", ERROR);
    }

    print_debug_message("ISVSVN from MAA RA report ->", DEBUG_LOG);
    print_debug_message(std::to_string(jwt_obj["x-ms-sgx-svn"].ToInt()), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    //要求値とRA応答エントリ内の要素との比較
    if(g_settings.min_isv_svn > jwt_obj["x-ms-sgx-svn"].ToInt())
    {
        print_debug_message("", ERROR);
        print_debug_message("ISVSVN in the RA report is corrupted.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_message("ISVSVN validated.", INFO);
    print_debug_message("", INFO);


    /* ISV ProdIDのチェック */
    //要求値とQuote内の要素との比較
    print_debug_message("Required ISV ProdID ->", DEBUG_LOG);
    print_debug_message(std::to_string(g_settings.req_isv_prod_id), DEBUG_LOG);
    print_debug_message("ISV ProdID from Quote ->", DEBUG_LOG);
    print_debug_message(std::to_string(quote_isvsvn), DEBUG_LOG);

    if(g_settings.req_isv_prod_id != quote_isvprodid)
    {
        print_debug_message("", ERROR);
        print_debug_message("ISV ProdID mismatched. Reject RA.", ERROR);
        print_debug_message("", ERROR);
    }

    print_debug_message("ISV ProdID from MAA RA report ->", DEBUG_LOG);
    print_debug_message(std::to_string(jwt_obj["x-ms-sgx-product-id"].ToInt()), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    //要求値とRA応答エントリ内の要素との比較
    if(g_settings.req_isv_prod_id != jwt_obj["x-ms-sgx-product-id"].ToInt())
    {
        print_debug_message("", ERROR);
        print_debug_message("ISV ProdID in the RA report is corrupted.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_message("ISV ProdID matched.", INFO);
    print_debug_message("", INFO);


    /* Report DataがGa||Gb||VKに対するハッシュ値であるかを確認する。
     * MAAに送信したQuoteでこれが食い違っているとエラー400が来るため、
     * ここではMAAのJWTエントリは検証しなくてよい。 */
    //VKの生成
    aes_128bit_cmac(ra_keys.kdk, 
    (uint8_t*)("\x01VK\x00\x80\x00"), 6, ra_keys.vk);

    print_debug_binary("VK", ra_keys.vk, 16, DEBUG_LOG);

    uint8_t *ga_gb_vk = new uint8_t[144]();
    memcpy(ga_gb_vk, ra_keys.g_a, 64);
    memcpy(&ga_gb_vk[64], ra_keys.g_b, 64);
    memcpy(&ga_gb_vk[128], ra_keys.vk, 16);

    uint8_t data_hash[32] = {0};
    int ret = sha256_digest(ga_gb_vk, 144, data_hash);
    
    if(ret)
    {
        print_debug_message("Failed to obtain hash of ga_gb_vk.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_binary("Derived hash of Ga||Gb||VK", 
        data_hash, 32, DEBUG_LOG);
    print_debug_binary("Upper 32bits of Report Data in the Quote", 
        quote_upper_data, 32, DEBUG_LOG);

    if(memcmp(data_hash, quote_upper_data, 32))
    {
        print_debug_message("Report Data mismatched.", ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_message("Report Data matched.", INFO);
    print_debug_message("", INFO);

    return 0;
}


/* RA reportを検証しRAの受理判断を行う */
int process_ra_report(std::string ra_report_jwt, 
    std::string quote_json, ra_session_t ra_keys)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Verify JWT signature using JWK", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    /* 検証用のJWKの取得 */
    std::string url_parts = "/certs";
    std::string jwk;
    int ret = get_jwk_online(g_settings.maa_url, url_parts, jwk);
    if(ret) return -1;

    /* JWTの署名を検証する */
    ret = verify_jwt(ra_report_jwt, jwk, g_settings.maa_url);
    if(ret) return -1;

    /* サーバEnclaveの各種同一性の検証を行う */
    ret = verify_enclave(ra_report_jwt, quote_json, ra_keys);
    if(ret) return -1;

    print_debug_message("-----------------------------", INFO);
    print_debug_message("RA Accepted.", INFO);
    print_debug_message("-----------------------------", INFO);
    print_debug_message("", INFO);

    return 0;
}


int send_ra_result(std::string server_url, 
    std::string ra_ctx_b64, bool ra_result)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Send RA result to SGX server", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    std::string request_json;
    json::JSON req_json_obj, res_json_obj;

    req_json_obj["ra_context"] = ra_ctx_b64;
    
    if(ra_result == true)
        req_json_obj["ra_result"] = std::string("true");
    else
        req_json_obj["ra_result"] = std::string("false");

    request_json = req_json_obj.dump();

    Client client(server_url);
    auto res = client.Post("/ra-result", request_json, "application/json");

    if(res == NULL)
    {
        std::string message = "Unknown error. Probably SGX server is down.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    std::string response_json = res->body;
    res_json_obj = json::JSON::Load(response_json);

    if(res->status == 200)
    {
        print_debug_message("Sent RA result successfully.", DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);
    }
    else if(res->status == 500)
    {
        char *error_message;
        size_t error_message_size;

        error_message = base64_decode<char, char>(
            (char*)res_json_obj["error_message"].ToString().c_str(), error_message_size);

        print_debug_message(std::string(error_message), ERROR);

        return -1;
    }
    else
    {
        std::string message = "Unexpected error while sending RA result.";
        print_debug_message(message, ERROR);
        
        return -1;
    }

    return 0;
}


/* RAを実行する関数 */
int do_RA(std::string server_url,
    std::string &ra_ctx_b64, uint8_t *&sk, uint8_t *&mk)
{
    print_debug_message("", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("Remote Attestation Preparation", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    /* 暗号処理関数向けの初期化（事前処理） */
    crypto_init();

    /* RAセッション鍵関連構造体の生成 */
    ra_session_t ra_keys;

    /* RAの初期化 */
    int ret = initialize_ra(server_url, ra_ctx_b64, ra_keys);
    if(ret) return -1;

    /* セッションキーペア、共有秘密、SigSPの生成 */
    client_sgx_ec256_signature_t sigsp;
    ret = process_session_keys(ra_keys, sigsp);
    if(ret) return -1;    

    /* Quoteの取得 */
    std::string quote_json;
    ret = get_quote(server_url, ra_ctx_b64, ra_keys, sigsp, quote_json);
    if(ret) return -1;

    /* MAAにQuoteを送信し検証する */
    std::string ra_report_jwt;
    ret = send_quote_to_maa(quote_json, ra_report_jwt);
    if(ret) return -1;

    /* RA reportの各種検証処理を実施しRAの受理判断を行う */
    bool ra_result = 1; //RA Accepted
    ret = process_ra_report(ra_report_jwt, quote_json, ra_keys);
    if(ret) ra_result = 0; //RA failed

    /* RA受理判断結果の返信 */
    ret = send_ra_result(server_url, ra_ctx_b64, ra_result);
    if(!ra_result || ret) return -1;

    /* セッション共通鍵SKとMKの生成 */
    aes_128bit_cmac(ra_keys.kdk, (uint8_t*)("\x01SK\x00\x80\x00"),
        6, ra_keys.sk);
    aes_128bit_cmac(ra_keys.kdk, (uint8_t*)("\x01MK\x00\x80\x00"),
        6, ra_keys.mk);

    sk = new uint8_t[16]();
    mk = new uint8_t[16]();

    memcpy(sk, ra_keys.sk, 16);
    memcpy(mk, ra_keys.mk, 16);

    return 0;
}


/* RAコンテキストの破棄 */
void destruct_ra_context(std::string server_url, std::string ra_ctx_b64)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Destruct RA", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);
    
    json::JSON req_json_obj;
    std::string request_json;

    req_json_obj["ra_context"] = ra_ctx_b64;

    Client client(server_url);

    request_json = req_json_obj.dump();

    /* 計算に使用する暗号データを送信 */
    auto res = client.Post("/destruct-ra", request_json, "application/json");

    print_debug_message("Sent RA destruction request to ISV.", INFO);
    print_debug_message("", INFO);
}


/* CSPRNGにより、指定されたバイト数だけ乱数（nonce）を生成 */
int generate_nonce(uint8_t *buf, size_t size)
{
    int ret = RAND_bytes(buf, size);

    if(!ret)
    {
        print_debug_message("Failed to generate nonce.", ERROR);
        return -1;
    }
    else return 0;
}


/* 128bit AES/GCMで暗号化する。SKやMKを用いた、ISVの
 * Enclaveとの暗号化通信を行うために利用可能 */
int aes_128_gcm_encrypt(uint8_t *plaintext, size_t p_len,
    uint8_t *key, uint8_t *iv, uint8_t *ciphertext, uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx;
    size_t c_len;
    int len_tmp;
    std::string message;

    /* コンテキストの作成 */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        message = "Failed to initialize context for GCM encryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* GCM暗号化初期化処理 */
    if(!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv))
    {
        message = "Failed to initialize GCM encryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* 暗号化する平文を供給する */
    if(!EVP_EncryptUpdate(ctx, ciphertext, &len_tmp, plaintext, p_len))
    {
        message = "Failed to encrypt plain text with GCM.";
        print_debug_message(message, ERROR);
        return -1;
    }

    c_len = len_tmp;

    /* GCM暗号化の最終処理 */
    if(!EVP_EncryptFinal_ex(ctx, ciphertext + len_tmp, &len_tmp))
    {
        message = "Failed to finalize GCM encryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    c_len += len_tmp;

    /* 生成したGCM暗号文のMACタグを取得 */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
    {
        message = "Failed to obtain GCM MAC tag.";
        print_debug_message(message, ERROR);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);

    return c_len;
}


/* 128bit AES/GCMで復号する。SKやMKを用いた、ISVの
 * Enclaveとの暗号化通信を行うために利用可能 */
int aes_128_gcm_decrypt(uint8_t *ciphertext, size_t c_len,
    uint8_t *key, uint8_t *iv, uint8_t *tag, uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    size_t p_len;
    int ret, len_tmp;
    std::string message;

    /* コンテキストの作成 */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        message = "Failed to initialize context for GCM encryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* GCM復号初期化処理 */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv))
    {
        message = "Failed to initialize GCM decryption.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* 復号する暗号文を供給する */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len_tmp, ciphertext, c_len))
    {
        message = "Failed to decrypt cipher text with GCM.";
        print_debug_message(message, ERROR);
        return -1;
    }

    p_len = len_tmp;

    /* 検証に用いるGCM MACタグをセット */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    {
        message = "Failed to set expected GCM MAC tag.";
        print_debug_message(message, ERROR);
        return -1;
    }

    /* GCM復号の最終処理 */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len_tmp, &len_tmp);

    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0)
    {
        p_len += len_tmp;
        return p_len;
    }
    else
    {
        /* 復号または検証の失敗 */
        message = "Decryption verification failed.";
        print_debug_message(message, ERROR);
        return -1;
    }
}


/* TLS通信を通したリモート秘密計算のテスト */
int sample_remote_computation(std::string isv_url,
    std::string &ra_ctx_b64, uint8_t *&sk, uint8_t *&mk)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Sample Remote Computation", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    uint64_t secret_1 = 200;
    uint64_t secret_2 = 800;
    std::string secret_1_str = std::to_string(secret_1);
    std::string secret_2_str = std::to_string(secret_2);

    print_debug_message("First integer to send -> ", INFO);
    print_debug_message(secret_1_str, INFO);
    print_debug_message("", INFO);
    print_debug_message("Second integer to send -> ", INFO);
    print_debug_message(secret_2_str, INFO);
    print_debug_message("", INFO);

    uint8_t *plain_send_1 = (uint8_t*)secret_1_str.c_str();
    uint8_t *plain_send_2 = (uint8_t*)secret_2_str.c_str();

    size_t secret_1_len = secret_1_str.length();
    size_t secret_2_len = secret_2_str.length();

    uint8_t *iv_send = new uint8_t[12]();
    uint8_t *tag_send_1 = new uint8_t[16]();
    uint8_t *tag_send_2 = new uint8_t[16]();

    /* GCM方式は平文と暗号文の長さが同一 */
    uint8_t *cipher_send_1 = new uint8_t[secret_1_len]();
    uint8_t *cipher_send_2 = new uint8_t[secret_2_len]();

    if(generate_nonce(iv_send, 12)) return -1;

    /* SKで暗号化 */
    if(-1 == (aes_128_gcm_encrypt(plain_send_1,
        secret_1_len, sk, iv_send, cipher_send_1, tag_send_1)))
    {
        return -1;
    }

    if(-1 == (aes_128_gcm_encrypt(plain_send_2,
        secret_2_len, sk, iv_send, cipher_send_2, tag_send_2)))
    {
        return -1;
    }

    char *cs1_b64, *cs2_b64;
    char *ivs_b64;
    char *tags1_b64, *tags2_b64;

    cs1_b64 = base64_encode<char, uint8_t>(cipher_send_1, secret_1_len);
    cs2_b64 = base64_encode<char, uint8_t>(cipher_send_2, secret_2_len);
    ivs_b64 = base64_encode<char, uint8_t>(iv_send, 12);
    tags1_b64 = base64_encode<char, uint8_t>(tag_send_1, 16);
    tags2_b64 = base64_encode<char, uint8_t>(tag_send_2, 16);

    json::JSON req_json_obj, res_json_obj;
    std::string request_json, response_json;

    req_json_obj["ra_context"] = ra_ctx_b64;
    req_json_obj["cipher1"] = cs1_b64;
    req_json_obj["cipher2"] = cs2_b64;
    req_json_obj["iv"] = ivs_b64;
    req_json_obj["tag1"] = tags1_b64;
    req_json_obj["tag2"] = tags2_b64;

    Client client(isv_url);

    request_json = req_json_obj.dump();

    /* 計算に使用する暗号データを送信 */
    auto res = client.Post("/sample-addition", request_json, "application/json");
    response_json = res->body;
    res_json_obj = json::JSON::Load(response_json);

    if(res->status == 500)
    {
        char *error_message;
        size_t error_message_size;

        error_message = base64_decode<char, char>(
            (char*)res_json_obj["error_message"].ToString().c_str(), error_message_size);

        print_debug_message(std::string(error_message), ERROR);

        return -1;
    }
    else if(res->status != 200)
    {
        std::string message = "Unexpected error while processing msg0.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    /* 受信した計算結果暗号文の処理を開始 */
    uint8_t *cipher_result, *plain_result;
    uint8_t *iv_result, *tag_result;
    size_t cipher_result_len, tmpsz;

    cipher_result = base64_decode<uint8_t, char>
        ((char*)res_json_obj["cipher"].ToString().c_str(), cipher_result_len);
    
    /* GCMでは暗号文と平文の長さが同一 */
    plain_result = new uint8_t[cipher_result_len]();

    iv_result = base64_decode<uint8_t, char>
        ((char*)res_json_obj["iv"].ToString().c_str(), tmpsz);

    if(tmpsz != 12)
    {
        print_debug_message("Invalidly formatted IV received.", ERROR);
        return -1;
    }

    tag_result = base64_decode<uint8_t, char>
        ((char*)res_json_obj["tag"].ToString().c_str(), tmpsz);
    
    if(tmpsz != 16)
    {
        print_debug_message("Invalidly formatted MAC tag received.", ERROR);
        return -1;
    }

    if(-1 == (aes_128_gcm_decrypt(cipher_result,
        cipher_result_len, mk, iv_result, tag_result, plain_result)))
    {
        return -1;
    }

    uint64_t total = atol((const char*)plain_result);

    /* 受信した計算結果の表示 */
    print_debug_message("Received addition result -> ", INFO);
    print_debug_message(std::to_string(total), INFO);

    return 0;
}


void main_process()
{
    /* 設定ファイルからの設定の読み取り */
    load_settings();

    /* SGXサーバのURLを設定 */
    std::string server_url = "http://localhost:1234";

    /* SGXサーバはこの変数を用いてSP（厳密にはRA）の識別を行う。
     * SPは直接は使わないので、通信向けにbase64の形で保持 */
    std::string ra_ctx_b64 = "";
    
    /* RA後のTLS通信用のセッション鍵（共有秘密）。
     * do_RA関数内で取得され引数経由で返される。 */
    uint8_t *sk, *mk;

    int ret = -1;

    /* RAを実行 */
    ret = do_RA(server_url, ra_ctx_b64, sk, mk);

    if(ret)
    {
        std::string message = "RA failed. Clean up and exit program.";
        print_debug_message(message, ERROR);

        destruct_ra_context(server_url, ra_ctx_b64);
        
        exit(0);
    }

    print_debug_binary("SK", sk, 16, DEBUG_LOG);
    print_debug_binary("MK", mk, 16, DEBUG_LOG);

    /* TLS通信を通したリモート秘密計算のテスト */
    ret = sample_remote_computation(server_url, ra_ctx_b64, sk, mk);

    delete[] sk;
    delete[] mk;

    /* RAコンテキストの破棄 */
    destruct_ra_context(server_url, ra_ctx_b64);
}


int main()
{
    std::string message = "Launched SP's untrusted application.";
    print_debug_message(message, INFO);

    main_process();

    return 0;
}
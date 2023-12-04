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

using namespace httplib;


/* settingsファイルからロードした値を格納する構造体 */
typedef struct client_settings_struct
{
    std::string maa_url;
    std::string maa_api_version;
} settings_t;

settings_t g_settings;


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
    g_settings.maa_url = load_from_ini("client", "MAA_URL");
    g_settings.maa_api_version = load_from_ini("client", "MAA_API_VERSION");
}


/* RAの初期化 */
int initialize_ra(std::string server_url, std::string &ra_ctx_b64)
{
    print_debug_message("==============================================", INFO);
    print_debug_message("Initialize RA", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    Client client(server_url);
    auto res = client.Get("/init-ra");

    if(res == NULL)
    {
        std::string message = "Unknown error. Probably SGX server is down.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    std::string response_json;
    json::JSON json_obj;

    response_json = res->body;
    json_obj = json::JSON::Load(response_json);

    if(res->status == 200)
    {
        char *ra_ctx_char;
        size_t ra_ctx_size;

        /* base64形式のRAコンテキストを取得 */
        ra_ctx_b64 = std::string(json_obj["ra_context"].ToString().c_str());

        /* Base64デコード */
        ra_ctx_char = base64_decode<char, char>(
            (char*)json_obj["ra_context"].ToString().c_str(), ra_ctx_size);
        
        uint32_t ra_ctx = (uint32_t)std::stoi(ra_ctx_char);

        std::string message_ra_ctx =
            "Received RA context number -> " + std::to_string(ra_ctx);
        print_debug_message(message_ra_ctx, DEBUG_LOG);
        print_debug_message("", DEBUG_LOG);
    }
    else if(res->status == 500)
    {
        char *error_message;
        size_t error_message_size;

        error_message = base64_decode<char, char>(
            (char*)json_obj["error_message"].ToString().c_str(), error_message_size);

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


/* Quoteの取得 */
int get_quote(std::string server_url, 
    std::string ra_ctx_b64, std::string &quote_json)
{
    //一通り最低限実装したら、キーペアを生成し公開鍵を送信する機能の実装が必要
    print_debug_message("==============================================", INFO);
    print_debug_message("Get Quote", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    Client client(server_url);
    json::JSON req_json_obj, res_json_obj;
    std::string request_json;

    req_json_obj["ra_context"] = ra_ctx_b64;
    request_json = req_json_obj.dump();

    //ここは後でちゃんとリクエストをポストする
    auto res = client.Post("/get-quote");

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
int send_quote_to_maa(std::string quote_json)
{
    //一通り最低限実装したら、キーペアを生成し公開鍵を送信する機能の実装が必要
    print_debug_message("==============================================", INFO);
    print_debug_message("Send Quote to MAA", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    Client client(g_settings.maa_url);
    json::JSON res_json_obj;

    std::string url_parts = "/attest/SgxEnclave?api-version=";
    url_parts += g_settings.maa_api_version;

    //TODO: Quote JSONパースしバージョン整えてから送信
    auto res = client.Post(url_parts, quote_json, "application/json");

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

        std::string status_code = "status code -> " + std::to_string(res->status);
        print_debug_message(status_code, ERROR);
        print_debug_message(res->body, ERROR);
        
        return -1;
    }

    return 0;
}


/* RAを実行する関数 */
int do_RA(std::string server_url,
    std::string &ra_ctx_b64, uint8_t *session_key)
{
    print_debug_message("", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("Remote Attestation Preparation", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    /* 暗号処理関数向けの初期化（事前処理） */
    crypto_init();

    /* RAの初期化 */
    int ret = initialize_ra(server_url, ra_ctx_b64);
    if(ret) return -1;

    /* Quoteの取得 */
    std::string quote_json;
    ret = get_quote(server_url, ra_ctx_b64, quote_json);
    if(ret) return -1;

    /* MAAにQuoteを送信し検証する */
    ret = send_quote_to_maa(quote_json);

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
    uint8_t *session_key;

    int ret = -1;

    /* RAを実行 */
    ret = do_RA(server_url, ra_ctx_b64, session_key);

    if(ret)
    {
        std::string message = "RA failed. Clean up and exit program.";
        print_debug_message(message, ERROR);
        exit(0);
    }

    // free(sk);
    // free(mk);
}


int main()
{
    std::string message = "Launched SP's untrusted application.";
    print_debug_message(message, INFO);

    main_process();

    return 0;
}
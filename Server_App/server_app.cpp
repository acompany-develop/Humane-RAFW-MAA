#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>
#include <unistd.h>
#include <sgx_urts.h>
#include <sgx_uswitchless.h>
#include <sgx_dcap_ql_wrapper.h>
#include <sgx_pce.h>
#include <sgx_quote_3.h>
#include "error_print.hpp"
#include "server_enclave_u.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../include/httplib.h"
#include "../include/json.hpp"
#include "../include/ini.h"
#include "../common/base64.hpp"
#include "../common/debug_print.hpp"
#include "../common/hexutil.hpp"


using namespace httplib;


/* プロトタイプ宣言 */
int initialize_enclave(sgx_enclave_id_t &eid);

int initialize_ra(sgx_enclave_id_t eid, 
    std::string &response_json, std::string &error_message);

int get_quote(sgx_enclave_id_t eid, std::string request_json, 
    std::string &response_json, std::string &error_message);


/* settingsファイルからロードした値を格納する構造体 */
typedef struct server_settings_struct
{
    std::string pce_path;
    std::string qe3_path;
    std::string ide_path;
    std::string qpl_path;
} settings_t;

settings_t g_settings;


/* Enclave内の値の出力を行うOCALL（主にデバッグやログ用） */
void ocall_print(const char *str, int log_type)
{
    MESSAGE_TYPE type;
    if(log_type == 0) type = DEBUG_LOG;
    else if(log_type == 1) type = INFO;
    else type = ERROR;
 
    print_debug_message("OCALL output-> ", type);
    print_debug_message(str, type);

    return;
}


/* SGXステータスを識別し具体的な内容表示する */
void ocall_print_status(sgx_status_t st)
{
	print_sgx_status(st);
	return;
}


/* サーバの実行定義。RA含む各処理はここで完結する */
void server_logics(sgx_enclave_id_t eid)
{
    Server svr;

    svr.Get("/init-ra", [&](const Request& req, Response& res) {
        std::string response_json, error_message = "";
        int ret = initialize_ra(eid, response_json, error_message);

        if(!ret) res.status = 200;
        else
        {
            /* 通信用にBase64化 */
            char *error_message_b64;
            error_message_b64 = base64_encode<char, char>(
                (char*)error_message.c_str(), error_message.length());
            
            /* レスポンス用jsonを生成 */
            json::JSON json_obj;
            json_obj["error_message"] = std::string(error_message_b64);
            response_json = json_obj.dump();

            res.status = 500;
        }

        /* レスポンスを返信 */
        res.set_content(response_json, "application/json");
    });

    svr.Post("/get-quote", [&](const Request& req, Response& res) {
        std::string request_json = req.body; 
        std::string response_json, error_message = "";

        int ret = get_quote(eid, request_json, response_json, error_message);

        if(!ret) res.status = 200;
        else
        {
            /* 通信用にBase64化 */
            char *error_message_b64;
            error_message_b64 = base64_encode<char, char>(
                (char*)error_message.c_str(), error_message.length());
            
            /* レスポンス用jsonを生成 */
            json::JSON json_obj;
            json_obj["error_message"] = std::string(error_message_b64);
            response_json = json_obj.dump();

            res.status = 500;
        }

        /* レスポンスを返信 */
        res.set_content(response_json, "application/json");
    });

    svr.Get("/hi", [](const Request& req, Response& res) {
    res.set_content("Hello World!", "text/plain");
    });

    svr.Get("/stop", [&](const Request& req, Response& res) {
        /* Enclaveの終了 */
        sgx_destroy_enclave(eid);

        svr.stop();
    });

    svr.listen("localhost", 1234);
}


/* Enclaveの初期化 */
int initialize_enclave(sgx_enclave_id_t &eid)
{
    /* LEはDeprecatedになったので、起動トークンはダミーで代用する */
    sgx_launch_token_t token = {0};

    /* 起動トークンが更新されているかのフラグ。Deprecated。 */
    int updated = 0;

    /* 署名済みEnclaveイメージファイル名 */
    std::string enclave_image_name = "enclave.signed.so";

    sgx_status_t status;

    sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
	void* enclave_ex_p[32] = {0};

	enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = &us_config;

    /* 
     * Switchless Callが有効化されたEnclaveの作成。
     * NULLの部分はEnclaveの属性（sgx_misc_attribute_t）が入る部分であるが、
     * 不要かつ省略可能なのでNULLで省略している。
     */
    status = sgx_create_enclave_ex(enclave_image_name.c_str(), SGX_DEBUG_FLAG,
                &token, &updated, &eid, NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS, 
                    (const void**)enclave_ex_p);

    if(status != SGX_SUCCESS)
	{
		/* error_print.cppで定義 */
		print_sgx_status(status);
		return -1;
	}

    return 0;
}


/* iniファイルから読み込み、失敗時にはプログラムを即時終了する */
std::string load_from_ini(std::string section, std::string key)
{
    mINI::INIFile file("settings.ini");
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
        std::string message = "Failed to load setting " + key + " from settings.ini.";
        print_debug_message(message, ERROR);
        exit(1); 
    }

    return ret;
}


/* 設定情報の読み込み */
void load_settings()
{
    // g_settings.pce_path = load_from_ini("server", "PCE_PATH");
    // g_settings.qe3_path = load_from_ini("server", "QE3_PATH");
    // g_settings.ide_path = load_from_ini("server", "IDE_PATH");
    g_settings.qpl_path = load_from_ini("server", "QPL_PATH");
}


/* sgx_ra_context_t相当のRAセッション識別子の初期化を行う */
int initialize_ra(sgx_enclave_id_t eid, 
    std::string &response_json, std::string &error_message)
{
    uint32_t ra_ctx = -1; //EPID-RAのsgx_ra_context_t相当
    sgx_status_t status, retval;

    print_debug_message("", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("Initialize RA", INFO);
    print_debug_message("==============================================", INFO);
    print_debug_message("", INFO);

    status = ecall_init_ra(eid, &retval, &ra_ctx);

    if(status != SGX_SUCCESS)
    {
        error_message = "Failed to initialize RA.";
        print_sgx_status(status);

        return -1;
    }

    std::string ra_ctx_str;
    char *ra_ctx_b64;

    ra_ctx_str = std::to_string(ra_ctx);
    ra_ctx_b64 = base64_encode<char, char>(
        (char*)ra_ctx_str.c_str(), ra_ctx_str.length());

    /* レスポンス用JSONの作成 */
    json::JSON res_json_obj;
    res_json_obj["ra_context"] = std::string(ra_ctx_b64);
    response_json = res_json_obj.dump();

    return 0;
}


/* Quoteの素材とする、ServerのEnclaveのReport構造体の取得 */
int get_server_enclave_report(sgx_enclave_id_t eid,
    sgx_target_info_t qe3_target_info, sgx_report_t &report)
{
    sgx_status_t status, retval;

    status = ecall_create_report(eid, &retval, 
        &qe3_target_info, &report);

    if(status != SGX_SUCCESS)
    {
        print_sgx_status(status);
        std::string message = "Failed to ecall.";
        print_debug_message(message, ERROR);

        return -1;
    }

    if(retval != SGX_SUCCESS)
    {
        print_sgx_status(status);
        std::string message = "Failed to create REPORT.";
        print_debug_message(message, ERROR);

        return -1;
    }

    return 0;
}


/* Quoteの取得 */
int get_quote(sgx_enclave_id_t eid, std::string request_json, 
    std::string &response_json, std::string &error_message)
{
    sgx_target_info_t qe3_target_info;

    /* RAの一環であるQE3とのLAのため、QE3のTarget Infoを取得する */
    quote3_error_t qe3_error = sgx_qe_get_target_info(&qe3_target_info);;
    
    if(qe3_error != SGX_QL_SUCCESS)
    {
        print_ql_status(qe3_error);
        error_message = "Failed to get QE3's target info.";
        print_debug_message(error_message, ERROR);

        return -1;
    }

    print_debug_binary("QE3's target info",  (uint8_t*)&qe3_target_info, 
        sizeof(sgx_target_info_t), DEBUG_LOG);


    /* ServerのEnclaveのREPORT構造体を取得 */
    sgx_report_t report;
    memset(&report, 0, sizeof(sgx_report_t));

    int ret = get_server_enclave_report(eid, qe3_target_info, report);

    if(ret) return -1;

    print_debug_binary("Server Enclave's Report",  (uint8_t*)&report, 
        sizeof(sgx_report_t), DEBUG_LOG);

    
    /* 取得するQuoteのサイズを算出し、そのサイズ数を取得する */
    uint32_t quote_size = 0;
    qe3_error = sgx_qe_get_quote_size(&quote_size);

    if(qe3_error != SGX_QL_SUCCESS)
    {
        print_ql_status(qe3_error);
        std::string message = "Failed to get Quote size.";
        print_debug_message(message, ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_message("Quote size ->", DEBUG_LOG);
    print_debug_message(std::to_string(quote_size), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);


    /* Quoteを取得する */
    uint8_t *quote_u8 = new uint8_t[quote_size]();

    qe3_error = sgx_qe_get_quote(&report, quote_size, quote_u8);

    if(qe3_error != SGX_QL_SUCCESS)
    {
        print_ql_status(qe3_error);
        std::string message = "Failed to get Quote.";
        print_debug_message(message, ERROR);
        print_debug_message("", ERROR);

        return -1;
    }

    print_debug_binary("Server Enclave's Quote",
        quote_u8, quote_size, DEBUG_LOG);
    

    /* 値のチェック */
    sgx_quote3_t *quote = (sgx_quote3_t*)quote_u8;
    sgx_ql_auth_data_t *auth_data = NULL;
    sgx_ql_ecdsa_sig_data_t *sig_data = NULL;
    sgx_ql_certification_data_t *cert_data = NULL;

    sig_data = (sgx_ql_ecdsa_sig_data_t*)quote->signature_data;
    auth_data = (sgx_ql_auth_data_t*)sig_data->auth_certification_data;
    cert_data = (sgx_ql_certification_data_t*)
        ((uint8_t*)auth_data + sizeof(*auth_data) + auth_data->size);

    print_debug_message("cert key type ->", DEBUG_LOG);
    print_debug_message(std::to_string(cert_data->cert_key_type), DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);


    /* Azure AttestationはReport Dataの下位32バイトの完全性の
     * 検証も行ってくれるため、Report Dataを抽出しておく */
    uint8_t *lower_report_data = new uint8_t[32]();
    uint8_t *report_data_hash = new uint8_t[32]();

    sgx_report_data_t report_data = 
        quote->report_body.report_data;
    
    memcpy(lower_report_data, report_data.d + 32, 32);

    BIO_dump_fp(stdout, (char*)lower_report_data, 32);

    /* レスポンスの生成 */
    std::string quote_b64 = std::string(
        base64_encode<char, uint8_t>(quote_u8, quote_size));

    json::JSON res_json_obj;

    res_json_obj["quote"] = quote_b64;
    response_json = res_json_obj.dump();

    memset(quote_u8, 0, quote_size);
    memset(lower_report_data, 0, 32);
    memset(report_data_hash, 0, 32);
    delete[] quote_u8;
    delete[] lower_report_data;
    delete[] report_data_hash;

    return 0;
}


int main()
{
    print_debug_message("", INFO);
    print_debug_message("Launched ISV's untrusted application.", INFO);

    /* Azure上でのDCAP-RAでは、プロセス外で動作するAEを使用するout-of-procモードが
     * 推奨されているため、out-of-procモードを前提とする */
    bool is_out_of_proc = false;
    char *out_of_proc = std::getenv("SGX_AESM_ADDR");

    if(!out_of_proc)
    {
        std::string message = "Only out-of-proc mode is supported. ";
        message += "Check your machine's configuration.";
        print_debug_message(message, ERROR);

        return -1;
    }

    sgx_enclave_id_t eid = -1;

    /* Enclaveの初期化 */
    if(initialize_enclave(eid) < 0)
	{
        std::string message = "Failed to initialize Enclave.";
        print_debug_message(message, ERROR);
		
        return -1;
    }

    /* 設定情報の読み込み。in-procモード対応の実装時に使用 */
    //load_settings();
    
    /* サーバの起動（RAの実行） */
    std::thread srvthread(server_logics, eid);

    /* サーバ停止準備。実際の停止処理は後ほど実装 */
    srvthread.join();
}
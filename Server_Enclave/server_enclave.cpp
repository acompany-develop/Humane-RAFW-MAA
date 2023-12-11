#include "server_enclave_t.h"
#include <sgx_utils.h>
#include <sgx_report.h>
#include <sgx_tcrypto.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include "../common/debug_print.hpp"

typedef struct _ra_session_t
{
    uint32_t ra_context;
    sgx_ec256_public_t ec_pubkey;
    sgx_ec256_private_t ec_privkey;
    sgx_ec256_public_t client_pubkey;
    uint8_t session_key[32];
    uint8_t kdk[32];
    uint8_t sk[32];
    uint8_t mk[32];
} ra_session_t;

/* 全セッションを管理するためのグローバル変数 */
uint32_t g_session_num = 0;
std::vector<ra_session_t> g_ra_sessions;


/* RAセッションを初期化しRAコンテキストを取得 */
sgx_status_t ecall_init_ra(uint32_t *ra_ctx)
{
    ra_session_t session;
    session.ra_context = g_session_num;
    *ra_ctx = g_session_num;

    g_ra_sessions.emplace_back(session);
    g_session_num++;

    return SGX_SUCCESS;
}


/* QE3とのLocal Attestationに使用するREPORT構造体を生成 */
sgx_status_t ecall_create_report(
    sgx_target_info_t *qe3_target_info, sgx_report_t *report)
{
    //鍵交換実装時はここに両者の公開鍵の連結に対するハッシュ値を同梱する
    sgx_report_data_t report_data = {0};

    //ここでは例として32バイトの0の羅列を対象とする
    uint8_t *original_data = new uint8_t[32]();
    uint8_t *data_hash = new uint8_t[32]();

    sgx_status_t status = 
        sgx_sha256_msg(original_data, 32, (sgx_sha256_hash_t*)data_hash);

    if(status != SGX_SUCCESS) return status;

    memcpy(&report_data, data_hash, 32);

    status = sgx_create_report(
        qe3_target_info, &report_data, report);

    delete[] original_data;
    delete[] data_hash;

    return status;
}


/* 共通鍵のSKとMKを生成する */
sgx_status_t ecall_generate_shared_keys(uint32_t ra_ctx)
{
    return SGX_SUCCESS;
}


/* 指定したRAセッションを破棄する */
sgx_status_t ecall_destroy_ra_session(uint32_t ra_ctx)
{
    /* 範囲外参照である場合はエラー */
    if(ra_ctx > g_session_num && 
        (ra_ctx + 1) > g_ra_sessions.size())
        return SGX_ERROR_UNEXPECTED;
    
    g_ra_sessions[ra_ctx].ra_context = -1;
    memset(&g_ra_sessions[ra_ctx].ec_pubkey, 0, sizeof(sgx_ec256_public_t));
    memset(&g_ra_sessions[ra_ctx].ec_privkey, 0, sizeof(sgx_ec256_private_t));
    memset(g_ra_sessions[ra_ctx].session_key, 0, 32);

    std::string tmp = std::to_string(sizeof(sgx_ec256_public_t));

    ocall_print(tmp.c_str(), tmp.length());

    return SGX_SUCCESS;
}
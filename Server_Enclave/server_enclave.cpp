#include "server_enclave_t.h"
#include <sgx_utils.h>
#include <sgx_report.h>
#include <sgx_tcrypto.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <exception>
#include "../common/debug_print.hpp"
#include "client_pubkey.hpp"

#define CLIENT_PUBKEY_NUM 2

typedef struct _ra_session_t
{
    uint32_t ra_context;
    uint32_t client_id;
    sgx_ec256_public_t ec_pubkey;
    sgx_ec256_private_t ec_privkey;
    sgx_ec256_public_t client_pubkey; //共通鍵にすべきか
    uint8_t session_key[32];
    uint8_t kdk[32];
    uint8_t sk[32];
    uint8_t mk[32];
} ra_session_t;

/* 全セッションを管理するためのグローバル変数 */
uint32_t g_session_num = 0;
std::vector<ra_session_t> g_ra_sessions;


/* RAセッションを初期化しRAコンテキストを取得 */
sgx_status_t ecall_init_ra(uint32_t client_id, 
    uint32_t *ra_ctx, sgx_ec256_public_t *Ga)
{
    ra_session_t session;
    session.ra_context = g_session_num;
    *ra_ctx = g_session_num;

    g_ra_sessions.emplace_back(session);
    g_session_num++;

    /* クライアントIDの境界チェック */
    if(client_id >= CLIENT_PUBKEY_NUM)
        return SGX_ERROR_INVALID_PARAMETER;

    /* セッションキーペアの生成 */
    sgx_status_t status = SGX_SUCCESS;
    sgx_ecc_state_handle_t ecc_state = NULL;

    memset(&g_ra_sessions[*ra_ctx].ec_pubkey, 
        0, sizeof(g_ra_sessions[*ra_ctx].ec_pubkey));
        
    memset(&g_ra_sessions[*ra_ctx].ec_privkey, 
        0, sizeof(g_ra_sessions[*ra_ctx].ec_privkey));

    try
    {
        status = sgx_ecc256_open_context(&ecc_state);
        if(status != SGX_SUCCESS) throw std::exception();

        status = sgx_ecc256_create_key_pair(&g_ra_sessions[*ra_ctx].ec_privkey,
            &g_ra_sessions[*ra_ctx].ec_pubkey, ecc_state);

        if(status != SGX_SUCCESS) throw std::exception();
    }
    catch(...)
    {
        if(ecc_state != NULL)
            sgx_ecc256_close_context(ecc_state);

        return status;
    }

    sgx_ecc256_close_context(ecc_state);
    //リターンする値にコピー、値のOCALLプリントチェック

    // ocall_print_binary((uint8_t*)&g_ra_sessions[*ra_ctx].ec_privkey, 
    //     sizeof(g_ra_sessions[*ra_ctx].ec_privkey));

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

    return SGX_SUCCESS;
}
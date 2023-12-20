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
    sgx_ec256_public_t g_a;
    sgx_ec256_private_t server_privkey;
    sgx_ec256_public_t g_b;
    uint8_t kdk[16];
    uint8_t vk[16];
    uint8_t sk[16];
    uint8_t mk[16];
} ra_session_t;

/* 全セッションを管理するためのグローバル変数 */
uint32_t g_session_num = 0;
std::vector<ra_session_t> g_ra_sessions;


/* RAセッションを初期化しRAコンテキストを取得 */
sgx_status_t ecall_init_ra(uint32_t client_id, 
    uint32_t *ra_ctx, sgx_ec256_public_t *Ga)
{
    /* クライアントIDの境界チェック */
    if(client_id >= CLIENT_PUBKEY_NUM)
        return SGX_ERROR_INVALID_PARAMETER;

    ra_session_t session;
    session.ra_context = g_session_num;
    session.client_id = client_id;
    *ra_ctx = g_session_num;

    g_ra_sessions.emplace_back(session);
    g_session_num++;

    /* セッションキーペアの生成 */
    sgx_status_t status = SGX_SUCCESS;
    sgx_ecc_state_handle_t ecc_state = NULL;

    memset(&g_ra_sessions[*ra_ctx].g_a, 
        0, sizeof(g_ra_sessions[*ra_ctx].g_a));
        
    memset(&g_ra_sessions[*ra_ctx].server_privkey, 
        0, sizeof(g_ra_sessions[*ra_ctx].server_privkey));

    try
    {
        status = sgx_ecc256_open_context(&ecc_state);
        if(status != SGX_SUCCESS) throw std::exception();

        status = sgx_ecc256_create_key_pair(&g_ra_sessions[*ra_ctx].server_privkey,
            &g_ra_sessions[*ra_ctx].g_a, ecc_state);

        if(status != SGX_SUCCESS) throw std::exception();
    }
    catch(...)
    {
        if(ecc_state != NULL)
            sgx_ecc256_close_context(ecc_state);

        return status;
    }

    sgx_ecc256_close_context(ecc_state);

    memcpy(Ga, (uint8_t*)&g_ra_sessions[*ra_ctx].g_a,
        sizeof(g_ra_sessions[*ra_ctx].g_a));

    // ocall_print_binary((uint8_t*)&g_ra_sessions[*ra_ctx].g_a, 
    //      sizeof(g_ra_sessions[*ra_ctx].g_a));

    return SGX_SUCCESS;
}


/* KDK、VK、SK、MKの生成 */
sgx_status_t derive_shared_keys(uint32_t ra_ctx, sgx_ec256_dh_shared_t dh_key)
{
    memset(g_ra_sessions[ra_ctx].kdk, 0, 16);
    memset(g_ra_sessions[ra_ctx].vk, 0, 16);
    memset(g_ra_sessions[ra_ctx].sk, 0, 16);
    memset(g_ra_sessions[ra_ctx].mk, 0, 16);

    sgx_status_t status;
    uint8_t *cmac_key = new uint8_t[16]();

    //KDK
    status = sgx_rijndael128_cmac_msg((sgx_cmac_128bit_key_t*)cmac_key,
        (uint8_t*)&dh_key, SGX_ECP256_KEY_SIZE, 
        (sgx_cmac_128bit_key_t*)g_ra_sessions[ra_ctx].kdk);
    
    if(status != SGX_SUCCESS) return status;

    //VK
    status = sgx_rijndael128_cmac_msg(
        (sgx_cmac_128bit_key_t*)g_ra_sessions[ra_ctx].kdk,
        (uint8_t*)("\x01VK\x00\x80\x00"), 6, 
        (sgx_cmac_128bit_key_t*)g_ra_sessions[ra_ctx].vk);

    if(status != SGX_SUCCESS) return status;
    
    //SK
    status = sgx_rijndael128_cmac_msg(
        (sgx_cmac_128bit_key_t*)g_ra_sessions[ra_ctx].kdk,
        (uint8_t*)("\x01SK\x00\x80\x00"), 6, 
        (sgx_cmac_128bit_key_t*)g_ra_sessions[ra_ctx].sk);

    if(status != SGX_SUCCESS) return status;

    //MK
    status = sgx_rijndael128_cmac_msg(
        (sgx_cmac_128bit_key_t*)g_ra_sessions[ra_ctx].kdk,
        (uint8_t*)("\x01MK\x00\x80\x00"), 6, 
        (sgx_cmac_128bit_key_t*)g_ra_sessions[ra_ctx].mk);

    if(status != SGX_SUCCESS) return status;

    delete[] cmac_key;

    return SGX_SUCCESS;
}


/* 交換した公開鍵の署名を検証し共通鍵生成 */
sgx_status_t ecall_process_session_keys(uint32_t ra_ctx,
    uint32_t client_id, sgx_ec256_public_t *Gb, 
    sgx_ec256_signature_t *sigsp)
{
    /* 範囲外参照である場合はエラー */
    if(ra_ctx > g_session_num || 
        (ra_ctx + 1) > g_ra_sessions.size())
        return SGX_ERROR_UNEXPECTED;

    /* クライアントIDの境界チェック、先行処理で代入した値との一致チェック */
    if(client_id >= CLIENT_PUBKEY_NUM || 
        client_id != g_ra_sessions[ra_ctx].client_id)
        return SGX_ERROR_INVALID_PARAMETER;

    memcpy(&g_ra_sessions[ra_ctx].g_b, Gb, 64);

    /* 公開鍵の連結を生成 */
    sgx_ec256_public_t gb_ga[2];
    memset(&gb_ga[0], 0, sizeof(gb_ga));
    memcpy(&gb_ga[0], &g_ra_sessions[ra_ctx].g_b, 64);
    memcpy(&gb_ga[1], &g_ra_sessions[ra_ctx].g_a, 64);

    sgx_ecc_state_handle_t ecc_state = NULL;


    sgx_status_t status = sgx_ecc256_open_context(&ecc_state);
    if (status != SGX_SUCCESS) return status;

    sgx_ec256_dh_shared_t dh_key;
    memset(&dh_key, 0, sizeof(dh_key));

    /* 共有秘密の導出 */
    status = sgx_ecc256_compute_shared_dhkey(
        &g_ra_sessions[ra_ctx].server_privkey,
        (sgx_ec256_public_t*)&g_ra_sessions[ra_ctx].g_b,
        &dh_key, ecc_state);

    if(status != SGX_SUCCESS)
    {
        sgx_ecc256_close_context(ecc_state);
        return status;
    }

    /* SigSPの検証 */
    uint8_t result;
    status = sgx_ecdsa_verify((uint8_t*)&gb_ga, sizeof(gb_ga),
        &client_signature_public_key[client_id], sigsp,
        &result, ecc_state);

    if(status != SGX_SUCCESS)
    {
        sgx_ecc256_close_context(ecc_state);
        return status;
    }

    if(result != SGX_EC_VALID)
    {
        sgx_ecc256_close_context(ecc_state);
        return SGX_ERROR_INVALID_SIGNATURE;
    }

    status = derive_shared_keys(ra_ctx, dh_key);
    if(status != SGX_SUCCESS) return status;

    sgx_ecc256_close_context(ecc_state);


    return SGX_SUCCESS;
}


/* QE3とのLocal Attestationに使用するREPORT構造体を生成 */
sgx_status_t ecall_create_report(uint32_t ra_ctx,
    sgx_target_info_t *qe3_target_info, sgx_report_t *report)
{
    //鍵交換実装時はここに両者の公開鍵の連結に対するハッシュ値を同梱する
    sgx_report_data_t report_data = {0};

    //ここでは例として32バイトの0の羅列を対象とする
    uint8_t *original_data = new uint8_t[144]();
    uint8_t *data_hash = new uint8_t[32]();

    memcpy(original_data, &g_ra_sessions[ra_ctx].g_a, 64);
    memcpy(&original_data[64], &g_ra_sessions[ra_ctx].g_b, 64);
    memcpy(&original_data[128], g_ra_sessions[ra_ctx].vk, 16);

    sgx_status_t status = 
        sgx_sha256_msg(original_data, 144, (sgx_sha256_hash_t*)data_hash);

    if(status != SGX_SUCCESS) return status;

    memcpy(&report_data, data_hash, 32);

    status = sgx_create_report(
        qe3_target_info, &report_data, report);

    delete[] original_data;
    delete[] data_hash;

    return status;
}


/* 指定したRAセッションを破棄する */
sgx_status_t ecall_destroy_ra_session(uint32_t ra_ctx)
{
    /* 範囲外参照である場合はエラー */
    if(ra_ctx > g_session_num || 
        (ra_ctx + 1) > g_ra_sessions.size())
        return SGX_ERROR_UNEXPECTED;
    
    g_ra_sessions[ra_ctx].ra_context = -1;
    memset(&g_ra_sessions[ra_ctx].g_a, 0, sizeof(sgx_ec256_public_t));
    memset(&g_ra_sessions[ra_ctx].g_b, 0, sizeof(sgx_ec256_public_t));
    memset(&g_ra_sessions[ra_ctx].server_privkey, 0, sizeof(sgx_ec256_private_t));
    memset(&g_ra_sessions[ra_ctx].kdk, 0, 16);
    memset(&g_ra_sessions[ra_ctx].vk, 0, 16);
    memset(&g_ra_sessions[ra_ctx].sk, 0, 16);
    memset(&g_ra_sessions[ra_ctx].mk, 0, 16);

    return SGX_SUCCESS;
}


sgx_status_t ecall_sample_addition(uint32_t ra_ctx,
    uint8_t *cipher1, size_t cipher1_len, uint8_t *cipher2,
    size_t cipher2_len, uint8_t *iv, uint8_t *tag1, 
    uint8_t *tag2, uint8_t *result, size_t *result_len,
    uint8_t *iv_result, uint8_t *tag_result)
{
    sgx_status_t status = SGX_SUCCESS;
    sgx_ra_key_128_t sk_key, mk_key;

    memcpy(&sk_key, g_ra_sessions[ra_ctx].sk, 16);
    memcpy(&mk_key, g_ra_sessions[ra_ctx].mk, 16);

    if(cipher1_len > 32 || cipher2_len > 32)
    {
        const char *message = "The cipher size is too large.";
        ocall_print(message, 2);
        status = SGX_ERROR_INVALID_PARAMETER;
        return status;
    }

    /* GCMでは暗号文と平文の長さが同一 */
    uint8_t *plain_1 = new uint8_t[cipher1_len]();
    uint8_t *plain_2 = new uint8_t[cipher2_len]();

    /* GCM復号 */
    status = sgx_rijndael128GCM_decrypt(&sk_key, cipher1,
        cipher1_len, plain_1, iv, 12, NULL, 0, 
        (sgx_aes_gcm_128bit_tag_t*)tag1);
    
    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to decrypt cipher1.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    status = sgx_rijndael128GCM_decrypt(&sk_key, cipher2,
        cipher2_len, plain_2, iv, 12, NULL, 0, 
        (sgx_aes_gcm_128bit_tag_t*)tag2);
    
    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to decrypt cipher2.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    uint64_t num1 = atol((const char*)plain_1);
    uint64_t num2 = atol((const char*)plain_2);

    /* 加算を実行 */
    uint64_t total = num1 + num2;

    /* 返信用に暗号化を実施 */
    std::string total_str = std::to_string(total);
    uint8_t *total_u8 = (uint8_t*)total_str.c_str();
    
    *result_len = total_str.length();

    /* "32"はEnclave外で決め打ちで確保しているバッファ数 */
    if(*result_len > 32)
    {
        const char *message = "The result cipher size is too large.";
        ocall_print(message, 2);
        status = SGX_ERROR_INVALID_PARAMETER;
        return status;
    }

    /* RDRANDで真性乱数的にIVを生成 */
    status = sgx_read_rand(iv_result, 12);

    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to generate IV inside enclave.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    /* 計算結果をGCMで暗号化 */
    status = sgx_rijndael128GCM_encrypt(&mk_key, 
        total_u8, *result_len, result, iv_result, 12,
        NULL, 0, (sgx_aes_gcm_128bit_tag_t*)tag_result);
    
    if(status != SGX_SUCCESS)
    {
        const char *message = "Failed to encrypt result.";
        ocall_print(message, 2); //2はエラーログである事を表す
        ocall_print_status(status);
        return status;
    }

    delete plain_1;
    delete plain_2;

    return status;
}
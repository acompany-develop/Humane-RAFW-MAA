#pragma once
#include <iostream>
#include <sgx_error.h>
#include <sgx_ql_lib_common.h>

void print_sgx_status(sgx_status_t status);

void print_ql_status(quote3_error_t qe3_error);
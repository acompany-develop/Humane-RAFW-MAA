#pragma once

#include <string>

int get_jwk_online(std::string base_url,
    std::string url_parts, std::string &jwk);

int verify_jwt(std::string ra_report_jwt, 
    std::string jwk, std::string issuer);
#pragma once

#include <openssl/evp.h>
#include <string>

namespace hashing {

extern EVP_MD_CTX *md_ctx;

void setup_hashing();
std::string hash_password(std::string password);

} // namespace hashing

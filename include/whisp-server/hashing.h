#pragma once

#include <openssl/evp.h>
#include <string>

namespace hashing {
extern const int SALT_LENGTH;
extern const EVP_MD *method;

extern EVP_MD_CTX *method_context;

std::string generate_salt();
std::string hash_password(std::string password, std::string salt);

} // namespace hashing

#include "whisp-server/hashing.h"
#include "whisp-server/logging.h"

#include <openssl/rand.h>
#include <sstream>

namespace hashing {
const int SALT_LENGTH = 32;
const EVP_MD *method = EVP_sha256();

EVP_MD_CTX *method_context = EVP_MD_CTX_new();

std::string generate_salt() {
  unsigned char salt_digest[SALT_LENGTH];
  unsigned int salt_size;
  std::stringstream salt_stream;

  RAND_bytes(salt_digest, SALT_LENGTH);

  for (int i = 0; i < SALT_LENGTH; ++i) {
    salt_stream << std::hex << (unsigned int)salt_digest[i];
  }

  return salt_stream.str();
}

void handle_EVP_error() {
  throw std::runtime_error("An error occurred during authentication - please "
                           "contact server administrator(s).");
}

std::string hash_password(std::string password, std::string salt) {
  unsigned char hash_digest[EVP_MAX_MD_SIZE];
  unsigned int hash_size;
  std::stringstream hash_stream;
  password = password + salt;

  if (EVP_DigestInit_ex(method_context, method, NULL) != 1) {
    handle_EVP_error();
  }
  if (EVP_DigestUpdate(method_context, password.data(), password.size()) != 1) {
    handle_EVP_error();
  }
  if (EVP_DigestFinal_ex(method_context, hash_digest, &hash_size) != 1) {
    handle_EVP_error();
  }

  for (int i = 0; i < hash_size; ++i) {
    hash_stream << std::hex << (unsigned int)hash_digest[i];
  }

  return hash_stream.str();
}

} // namespace hashing
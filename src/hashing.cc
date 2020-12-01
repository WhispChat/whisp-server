#include "whisp-server/hashing.h"

#include <sstream>

namespace hashing {
EVP_MD_CTX *md_ctx;

void setup_hashing() {
  md_ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
}

std::string hash_password(std::string password) {
  unsigned char enc_password_digest[EVP_MAX_MD_SIZE];
  unsigned int enc_password_size;
  std::stringstream enc_password_stream;

  EVP_DigestUpdate(md_ctx, password.data(), password.size());
  EVP_DigestFinal_ex(md_ctx, enc_password_digest, &enc_password_size);

  for (int i = 0; i < enc_password_size; ++i) {
    enc_password_stream << std::hex << (unsigned int)enc_password_digest[i];
  }

  return enc_password_stream.str();
}

} // namespace hashing
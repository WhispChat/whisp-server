#include "whisp-server/encryption.h"

#include <regex>

std::unordered_map<std::string, Encryption::Method> methods = {
    {"otp", Encryption::OneTimePad},
};

std::string Encryption::one_time_pad(std::string msg, int enc_dec) {
  const uint8_t ascii_start = (int)'A';
  const uint8_t ascii_case_diff = (int)'a' - ascii_start;

  for (size_t i = 0; i < msg.length(); i++) {
    if (std::regex_match(std::string(1, msg[i]), std::regex("[a-zA-Z]"))) {
      // Depending on whether char is lowercase or uppercase, ASCII shift
      // modification must be specified
      unsigned int ascii_mod = ((int)msg[i] >= ascii_start + ascii_case_diff)
                                   ? ascii_start + ascii_case_diff
                                   : ascii_start;
      // Shift the ASCII index based on the current pad and
      // encryption/decryption flag
      unsigned int encrypted_ascii =
          ((int)msg[i] - ascii_mod) + enc_dec * ((int)pad_key[i] - ascii_mod);
      msg[i] = (char)(ascii_mod + ((encrypted_ascii + 26) % 26));
    }
  }

  return msg;
}

std::string Encryption::encrypt(std::string msg, Method method) {
  switch (method) {
  case OneTimePad:
    return Encryption::one_time_pad(msg, 1);
  default:
    return msg;
  }
}

std::string Encryption::decrypt(std::string msg, Method method) {
  switch (method) {
  case OneTimePad:
    return Encryption::one_time_pad(msg, -1);
  default:
    return msg;
  }
}
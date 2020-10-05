#include "whisp-server/encryption.h"

std::unordered_map<std::string, Encryption::Method> methods = {
    {"otp", Encryption::OneTimePad},
};

std::string Encryption::one_time_pad(std::string msg, int enc_dec) {
  const char ascii_start = 32;
  const char ascii_end = 127;
  const char ascii_len = ascii_end - ascii_start;

  for (size_t i = 0; i < msg.length(); i++) {
    // For the time being, only standard ASCII characters will be encrypted
    char this_ascii_char = (int)msg[i];
    if (this_ascii_char >= ascii_start && this_ascii_char <= ascii_end) {
      // Shift the ASCII index based on the current pad and
      // encryption/decryption flag
      unsigned int encrypted_ascii = (this_ascii_char - ascii_start) +
                                     enc_dec * ((int)pad_key[i] - ascii_start);
      msg[i] =
          (char)(ascii_start + ((encrypted_ascii + ascii_len) % ascii_len));
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
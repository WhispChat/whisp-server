#include <iostream>
#include <string>

#include "whisp-server/socketserver.h"

// TODO: make configurable
const int PORT = 8080;
const std::size_t MAX_CONN = 50;
const std::string HOST = "0.0.0.0";

int main(int argc, char **argv) {
  TCPSocketServer ss(HOST, PORT, MAX_CONN);
  ss.initialize();
  ss.serve();

  return 0;
}

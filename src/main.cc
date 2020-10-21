#include <getopt.h>
#include <iostream>
#include <string>

#include "whisp-server/logging.h"
#include "whisp-server/socketserver.h"

int DEFAULT_PORT = 8080;
std::string DEFAULT_HOST = "0.0.0.0";
std::size_t DEFAULT_MAX_CONN = 50;

int debug = 0;

void help(char **argv) {
  std::cout << "Usage: " << argv[0]
            << " [OPTION]...\n"
               "  -d, --debug             enable debug mode\n"
               "  -h, --help              display this message and exit\n"
               "  -p, --port=PORT         set port to listen on (default: "
            << DEFAULT_PORT
            << ")\n"
               "  -H, --host=HOST         set host to listen on (default: "
            << DEFAULT_HOST
            << ")\n"
               "  -m, --max-connections=MAX_CONN\n"
               "                          set maximum amount of connections "
               "allowed (default: "
            << DEFAULT_MAX_CONN << ")\n";
}

int main(int argc, char **argv) {
  // verify that the version of the library that we linked against is
  // compatible with the version of the headers we compiled against.
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  int port = DEFAULT_PORT;
  std::size_t max_conn = DEFAULT_MAX_CONN;
  std::string host = DEFAULT_HOST;

  const struct option long_options[] = {
      {"debug", no_argument, nullptr, 'd'},
      {"help", no_argument, nullptr, 'h'},
      {"port", required_argument, nullptr, 'p'},
      {"host", required_argument, nullptr, 'H'},
      {"max-connections", required_argument, nullptr, 'm'},
      {nullptr, 0, nullptr, 0},
  };
  int c;
  bool fail = false;

  while ((c = getopt_long(argc, argv, "dvhp:H:m:", long_options, nullptr)) !=
         -1) {
    switch (c) {
    case 'd':
      debug = 1;
      break;
    case 'h':
      help(argv);
      return EXIT_SUCCESS;
    case 'p':
      port = atoi(optarg);
      if (port == 0) {
        LOG_ERROR << "invalid port number\n";
        fail = true;
      }
      break;
    case 'H':
      host = std::string(optarg);
      break;
    case 'm':
      max_conn = atoi(optarg);
      if (max_conn == 0) {
        LOG_ERROR << "invalid number of max connections\n";
        fail = true;
      }
      break;
    }
  }

  if (fail) {
    return EXIT_FAILURE;
  }

  TCPSocketServer ss(host, port, max_conn);

  try {
    ss.initialize();
    ss.serve();
  } catch (char const *msg) {
    LOG_ERROR << msg << '\n';
  }

  return EXIT_SUCCESS;
}

#include <cstdlib>
#include <getopt.h>
#include <iostream>
#include <string>

#include "whisp-server/db.h"
#include "whisp-server/logging.h"
#include "whisp-server/socketserver.h"

int DEFAULT_PORT = 8080;
std::string DEFAULT_HOST = "0.0.0.0";
std::size_t DEFAULT_MAX_CONN = 50;
const std::string DEFAULT_SQLITE_PATH = "../whisp.db";
std::string DEFAULT_CERT_PATH = "../ssl/cert.pem";
std::string DEFAULT_KEY_PATH = "../ssl/private_key.pem";

int debug = 0;

TCPSocketServer *ss = nullptr;

void sigint_handler(int s) {
  LOG_INFO << "Shutting down server\n";

  if (ss) {
    LOG_INFO << "Closing connections...\n";
    ss->cleanup_all();
    delete ss;
  }

  exit(EXIT_SUCCESS);
}

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
            << DEFAULT_MAX_CONN << ")\n"
                                   "  -s, --sqlite-path=DATABASE_FILE\n"
                                   "                          set sqlite "
                                   "database path (default: "
            << DEFAULT_SQLITE_PATH
            << ")\n"
               "  -c, --ssl-cert=CERT_PATH\n"
               "                          set path to SSL certificate file "
               "(default: "
            << DEFAULT_CERT_PATH
            << ")\n"
               "  -k, --ssl-key=KEY_PATH\n"
               "                          set path to SSL key file "
               "(default: "
            << DEFAULT_KEY_PATH << ")\n";
}

int main(int argc, char **argv) {
  int port = DEFAULT_PORT;
  std::size_t max_conn = DEFAULT_MAX_CONN;
  std::string host = DEFAULT_HOST;
  std::string sqlite_path = DEFAULT_SQLITE_PATH;
  std::string cert_path = DEFAULT_CERT_PATH;
  std::string key_path = DEFAULT_KEY_PATH;

  const struct option long_options[] = {
      {"debug", no_argument, nullptr, 'd'},
      {"help", no_argument, nullptr, 'h'},
      {"port", required_argument, nullptr, 'p'},
      {"host", required_argument, nullptr, 'H'},
      {"max-connections", required_argument, nullptr, 'm'},
      {"sqlite-path", required_argument, nullptr, 's'},
      {"ssl-cert", required_argument, nullptr, 'c'},
      {"ssl-key", required_argument, nullptr, 'k'},
      {nullptr, 0, nullptr, 0},
  };
  int c;
  bool fail = false;

  while ((c = getopt_long(argc, argv, "dvhp:H:m:s:c:k:", long_options,
                          nullptr)) != -1) {
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
        LOG_ERROR << "Invalid port number\n";
        fail = true;
      }
      break;
    case 'H':
      host = std::string(optarg);
      break;
    case 'm':
      max_conn = atoi(optarg);
      if (max_conn == 0) {
        LOG_ERROR << "Invalid number of max connections\n";
        fail = true;
      }
      break;
    case 's':
      sqlite_path = std::string(optarg);
      break;
    case 'c':
      cert_path = std::string(optarg);
      break;
    case 'k':
      key_path = std::string(optarg);
      break;
    }
  }

  if (fail) {
    return EXIT_FAILURE;
  }

  ss = new TCPSocketServer(host, port, max_conn, cert_path, key_path);

  // handle Ctrl+C
  struct sigaction sigint;

  sigint.sa_handler = sigint_handler;
  sigemptyset(&sigint.sa_mask);
  sigint.sa_flags = 0;

  sigaction(SIGINT, &sigint, NULL);

  try {
    db::init_database(sqlite_path);
    ss->initialize();
    ss->serve();
  } catch (const std::string &msg) {
    LOG_ERROR << msg << '\n';
  }

  ss->cleanup_all();
  delete ss;

  return EXIT_SUCCESS;
}

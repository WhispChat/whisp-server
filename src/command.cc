#include "whisp-server/command.h"

std::unordered_map<std::string, CommandType> commands_map = {
    {"set", Set}, {"users", ListUsers}, {"quit", CloseConnection},
};

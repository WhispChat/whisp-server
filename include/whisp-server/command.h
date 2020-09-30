#pragma once

#include <unordered_map>
#include <vector>

enum CommandType { Set, ListUsers, CloseConnection, Unknown };

struct Command {
    CommandType type;
    std::vector<std::string> args;
};

extern std::unordered_map<std::string, CommandType> commands_map;

#pragma once

#include "whisp-server/command.h"
#include "whisp-server/connection.h"

namespace commandmanager {
bool parse_command(
    Connection *conn, Command cmd,
    std::unordered_set<Connection *, ConnectionHash> connections);
}; // namespace commandmanager

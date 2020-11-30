#include "whisp-server/connection.h"

void Connection::set_user(User *new_user) {
  if (this->user) {
    delete this->user;
  }
  this->user = new_user;
}

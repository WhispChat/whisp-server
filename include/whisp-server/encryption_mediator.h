#pragma once

namespace Encryption {
class BaseEncryption;

class Mediator {
public:
  virtual std::string send(BaseEncryption *sender, std::string event,
                           std::string payload) = 0;
};

class BaseEncryption {
protected:
  Mediator *mediator;

public:
  BaseEncryption(Mediator *mediator = nullptr) : mediator(mediator) {}

  virtual std::string encrypt(std::string message) = 0;
  virtual std::string decrypt(std::string message) = 0;

  void set_mediator(Mediator *mediator) { this->mediator = mediator; }
};

class OneTimePad : public BaseEncryption {
public:
  // TODO: implement OTP
  std::string encrypt(std::string message) { return ""; }

  std::string decrypt(std::string message) { return ""; }
};

class RSA : public BaseEncryption {
public:
  // TODO: implement RSA
  std::string encrypt(std::string message) { return ""; }

  std::string decrypt(std::string message) { return ""; }
};

class ConcreteMediator : public Mediator {
private:
  OneTimePad *otp;
  RSA *rsa;

public:
  ConcreteMediator(OneTimePad *otp, RSA *rsa) : otp(otp), rsa(rsa) {
    this->otp->set_mediator(this);
    this->rsa->set_mediator(this);
  }

  std::string send(BaseEncryption *sender, std::string event,
                   std::string payload) override {
    if (event.compare("encrypt") == 0) {
      return sender->encrypt(payload);
    } else if (event.compare("decrypt") == 0) {
      return sender->decrypt(payload);
    }
  }
};
}

#include "create-x509.h"
#include <stdio.h>
#include <openssl/err.h>

int main() {
  certMaker Ca;
  const char *name[] = {"C","UK","O","My Compamy","CN","Root CA",nullptr};
  const certMaker::certExt ext[] = {
     {NID_basic_constraints, "critical,CA:TRUE,pathlen:0"},
     {NID_key_usage, "critical,keyCertSign,cRLSign"},
     {NID_subject_key_identifier, "hash"},
     {0, nullptr}
    };

  Ca.validDays = 365*4+1;
  if (Ca.generateCert(name, ext)) {

    certMaker hst(&Ca);
    const char *name[] = {"C","UK","O","My Company","CN","localhost",nullptr};
    const certMaker::certExt ext[] = {
      {NID_basic_constraints, "critical,CA:FALSE"},
      {NID_key_usage, "critical,digitalSignature"},
      {NID_ext_key_usage, "serverAuth"},
      {NID_subject_key_identifier, "hash"},
      {NID_subject_alt_name, "IP:127.0.0.1,IP:192.168.0.1"},
      {0, nullptr}
     };

     hst.validDays = 365*4+1;
     hst.serial = rand();
     if (hst.generateCert(name, ext)) {
       Ca.writeKey("ca-key.pem");
       Ca.writeCert("ca-cert.pem");
       hst.writeKey("hst-key.pem");
       hst.writeCert("hst-cert.pem");
       return 0;
     }
     else
       puts(hst.errMsg.c_str());
  }
  else
    puts(Ca.errMsg.c_str());

  ERR_print_errors_fp(stderr);
  return 1;
}

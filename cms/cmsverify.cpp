/**
 * sudo apt-get install libssl-dev
 *
 * build with
 * g++ -pthread -std=c++17 cmsverify.cpp -o cmsverify -L/usr/local/lib/ -lssl -lcrypto
 * 
 */


#include <cstring>
#include <ctime>
#include <iostream>
#include <memory>
#include <string>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/cms.h>

// openssl req -new -days 365 -sha256 -newkey rsa:4096 -x509 -nodes -keyout key.pem -out cert.pem -subj "/C=CH/ST=Gugus/L=Gugus/O=Sparkling Network/OU=IT Dept/CN=$(whoami)s Sign Key"
// openssl cms -sign -binary -in swu.bin -out swu.bin.sig -signer cert.pem -inkey key.pem -outform DER -nodetach
// cat cert.pem 
std::string cert_content = R"(-----BEGIN CERTIFICATE-----
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
Vw==
-----END CERTIFICATE-----)";

// Verify:
// openssl cms -verify -binary -CAfile cert.pem  -in swu.bin.sig  -out swu.bin -inform DER

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL, *cont = NULL;
    X509_STORE *st = NULL;
    X509 *cacert = NULL;
    CMS_ContentInfo *cms = NULL;

    int ret = 1;
	int flags = PKCS7_BINARY;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Set up trusted CA certificate store
    st = X509_STORE_new();

    // Put the certificate contents into an openssl IO stream (BIO)
    tbio = BIO_new(BIO_s_mem());
    if (!tbio)
        goto err;

    // write PEM into BIO
    BIO_write(tbio, cert_content.c_str(), cert_content.size());

    cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (!cacert)
        goto err;

    if (!X509_STORE_add_cert(st, cacert))
        goto err;

    // Open content to verify
    in = BIO_new_file("swu.bin.sig", "r");
    if (!in)
        goto err;

    // read CMS from in file, we use DER (binary)
    //cms = PEM_read_bio_CMS(in, NULL, NULL, NULL); // PEM
    cms = d2i_CMS_bio(in, NULL);  // DER (DER is a binary format for data structures described by ASN.1. )
    if (!cms)
        goto err;

    // File to output verified content to
    out = BIO_new_file("swu.bin.out", "w");
    if (!out)
        goto err;

#if 1
    // only verify
    if (!CMS_verify(cms, NULL, st, cont, /*out*/ NULL, flags)) {
        fprintf(stderr, "Verification Failure\n");
        goto err;
    }
#else
    // verify and write to out file
    if (!CMS_verify(cms, NULL, st, cont, out, flags)) {
        fprintf(stderr, "Verification Failure\n");
        goto err;
    }
#endif

    fprintf(stderr, "Verification Successful\n");

    ret = 0;

err:
    if (ret) {
        fprintf(stderr, "Error Verifying Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(cacert);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    X509_STORE_free(st);

    return ret;
}

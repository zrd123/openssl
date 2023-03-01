#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
bool MakeRsaKeySSL(const char *savePrivateKeyFilePath, const  char *savePublicKeyFilePath) {
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;
    BIO             *bp_public = NULL, *bp_private = NULL;

    int             bits = 2048;
    unsigned long   e = RSA_F4;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne, e);
    if (ret != 1) {
        fprintf(stderr, "MakeLocalKeySSL BN_set_word err \n");
        goto free_all;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1) {
        fprintf(stderr, "MakeLocalKeySSL RSA_generate_key_ex err \n");
        goto free_all;
    }

    // 2. save public key
    if (savePublicKeyFilePath != NULL) {
        bp_public = BIO_new_file(savePublicKeyFilePath, "w+");
        ret = PEM_write_bio_RSAPublicKey(bp_public, r);
        if (ret != 1) {
            fprintf(stderr, "MakeLocalKeySSL PEM_write_bio_RSAPublicKey err \n");
            goto free_all;
        }
    }

    // 3. save private key
    if (savePrivateKeyFilePath != NULL) {
        bp_private = BIO_new_file(savePrivateKeyFilePath, "w+");
        ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
    }

    // 4. free
free_all:

    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);

    return (ret == 1);
}

int main()
{
    MakeRsaKeySSL("./prikey.pem","./pubkey.pem");
    return 0;
}

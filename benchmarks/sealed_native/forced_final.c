// Synthetic hostile-process test only. Deliberately bypass AEAD authentication.
#include <openssl/evp.h>
#include <unistd.h>

int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *context, unsigned char *output, int *outl) {
    static const char observed[] = "RG_GCM_FINAL_FORCED\n";
    (void)context;
    (void)output;
    *outl = 0;
    (void)write(2, observed, sizeof observed - 1);
    return 1;
}

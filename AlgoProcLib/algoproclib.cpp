#include "algoproclib.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace GB;

AlgoProcLib::AlgoProcLib()
{
}

AlgoProcLib::~AlgoProcLib()
{
}

void GB::AlgoProcLib::Initialize()
{
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Load config file, and other important initialisation */
//    OPENSSL_config(NULL);//deprecated
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    /* ... Do some crypto stuff here ... */
}

void AlgoProcLib::Deinitialize()
{
    /* Clean up */

    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();
}

void AlgoProcLib::ReleaseAlgoProcLib(AlgoProcLib *pAlgoProcLib)
{
    if(pAlgoProcLib)
        delete pAlgoProcLib;
    pAlgoProcLib = nullptr;
}

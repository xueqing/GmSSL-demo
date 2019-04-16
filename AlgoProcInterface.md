# AlgoProcInterface

- [AlgoProcInterface](#algoprocinterface)
  - [1 parameters](#1-parameters)
  - [2 interface list](#2-interface-list)

## 1 parameters

```cpp
struct AlgorithmParams {
  std::string uid;        // unique identifier
  std::string strIn;      // input string
  std::string strOut;     // output string
  unsigned int lenOut = 0;// length of output string
  std::string sm4_ecb_key;// key for sm4_ecb cipher
  std::string ec_pub_key; // public key for ECC
  std::string ec_pri_key; // private key for ECC
  std::string filePath;   // directory path to save asymmetric key
};
```

- error code

```cpp
class AlgoProcLib
{
public:
    enum PROC_RES
    {
        RES_OK = 0,         // success
        RES_NOT_SUPPORTED,  // request not supported
        RES_SERVER_ERROR,   // server internal error(call openssl interface)
        RES_VERIFY_FAILURE, // verify signature failure
    };
}
```

## 2 interface list

```cpp
// generate a random string
bool GenerateRandom(GB::AlgorithmParams &param);
// compute signature with SM2
bool SignBySM2(GB::AlgorithmParams &param);
// verify signature with SM2
bool VerifySignBySM2(GB::AlgorithmParams &param);
// compute hash value with SM3
bool HashBySM3(GB::AlgorithmParams &param);
// encode string with SM4_ECB
bool EncryptBySM4ECB(GB::AlgorithmParams &param);
// decode string with SM4_ECB
bool DecryptBySM4ECB(GB::AlgorithmParams &param);

// generate symmetric key
bool GenerateSymmKey(GB::AlgorithmParams &param);
// generate asymmetric key for ECC
bool GenerateECKey(GB::AlgorithmParams &param);

// convert hex string to buffer
bool HexStr2Buffer(GB::AlgorithmParams &param);
// convert buffer to hex string
bool Buffer2HexStr(GB::AlgorithmParams &param);
// encode string with Base 64
bool Base64Encode(GB::AlgorithmParams &param);
// decode string with Base 64
bool Base64Decode(GB::AlgorithmParams &param);
```

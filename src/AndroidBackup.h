#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <map>
#include <list>
#include <vector>
#include <sstream>
#include <fstream>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <iomanip>
#include <codecvt>
#include <locale>
#include <zlib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>

using namespace std;
#define byte unsigned char

const int CHUNK_SIZE = 128 * 1024 * 2;
/* CHUNK is the size of the memory chunk used by the zlib routines. */

/* These are parameters to inflateInit2. See
   http://zlib.net/manual.html for the exact meanings. */

#define windowBits 15
#define ENABLE_ZLIB_GZIP 32

#define CHUNK 0x4000

/* The following macro calls a zlib routine and checks the return
   value. If the return value ("status") is not OK, it prints an error
   message and exits the program. Zlib's error statuses are all less
   than zero. */

#define CALL_ZLIB( x )                                                                             \
    {                                                                                              \
        int status;                                                                                \
        status = x;                                                                                \
        if( status < 0 )                                                                           \
        {                                                                                          \
            fprintf( stderr,                                                                       \
                     "%s:%d: %s returned a bad status of %d.\n",                                   \
                     __FILE__,                                                                     \
                     __LINE__,                                                                     \
                     #x,                                                                           \
                     status );                                                                     \
            exit( EXIT_FAILURE );                                                                  \
        }                                                                                          \
    }

   /* if "test" is true, print an error message and halt execution. */

#define FAIL( test, message )                                                                      \
    {                                                                                              \
        if( test )                                                                                 \
        {                                                                                          \
            inflateEnd( &strm );                                                                   \
            fprintf( stderr,                                                                       \
                     "%s:%d: " message " file '%s' failed: %s\n",                                  \
                     __FILE__,                                                                     \
                     __LINE__,                                                                     \
                     message,                                                                    \
                     strerror( errno ) );                                                          \
            exit( EXIT_FAILURE );                                                                  \
        }                                                                                          \
    }
class AndroidBackup{
private:
        int BACKUP_MANIFEST_VERSION =1;
        string BACKUP_FILE_HEADER_MAGIC = "ANDROID BACKUP\n";
        int BACKUP_FILE_V1 = 1;
        int BACKUP_FILE_V2 = 2;
        int BACKUP_FILE_V3 = 3;
        int BACKUP_FILE_V4 = 4;
        int BACKUP_FILE_V5 = 5;

        string ENCRYPTION_MECHANISM = "AES/CBC/PKCS5Padding";
        int PBKDF2_HASH_ROUNDS = 10000;
        int PBKDF2_KEY_SIZE = 256;
        int MASTER_KEY_SIZE = 256;
        int PBKDF2_SALT_SIZE = 512;
        string ENCRYPTION_ALGORTTHM_NAME = "AES-256";

        bool DEBUG = true;

public:
        //功能性的函数
        bool pathExists(const char* path);
        std::vector<uint8_t> hexToBytes(const std::string& hex);
        string* byteToHexStr(unsigned char byte_arr[], int arr_len);


        //Android备份解密核心功能的函数
        bool extractAsTar(string backupFilename, string tarFilePath, string password);
        string readHeaderLine(istream& in);
        std::vector<char> chunkReader(std::ifstream& f, int chunkSize = CHUNK_SIZE);
        int decompress(string tmptarFilePath, string tarFilePath);
        int pbkdf2(const char* password, int password_len, const byte* salt, int salt_len, int iterations, byte* out_key);
        int aes_decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext);
        string masterKeyJavaConversion(vector<unsigned char> k);
};
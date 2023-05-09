#include "AndroidBackup.h"

using namespace std;


/*
* Android backup备份解密代码，会把加密的Android backup备份文件，解密后输出成xxx.tar格式数据
* 参数：备份文件路径，输出后的.tar文件路径,备份密码
* 
* 备份密码如果错误的话，会提示密码错误
* 备份文件会按照每次128*1024字节进行读取，并且进行解密再解压
* 最后会持续将解压后文件输出到xxx.tar文件里面。
* 
* 原理：
*      Android backup备份文件原理，我在下面代码里面按照序号1.2.3.4进行注释了，会分别读取有用的数据
*      然后进行判断备份文件是否加密，属于什么加密，之后进行密钥的提取，然后密钥转换，最后转换成aes的密钥
*      之后将备份文件加密的数据，进行AES解密，解密后再进行zlib解压，最后就是Android backup备份文件的内容了。
*/
bool AndroidBackup::extractAsTar(string backupFilename,string tarfilePath,string password)
{
    try{
        if(!pathExists(backupFilename.c_str())){
            printf("备份文件不存在:%s\n",backupFilename.c_str());
            return false;
        }
        ifstream rawInStream = ifstream(backupFilename.c_str(),ios::binary);
        if(!rawInStream.is_open()){
            cout << "读取备份文件失败" << backupFilename.c_str() << "[请检查路径是否正确，或者管理员权限!]" << endl;
            return false;
        }
        
        string magic = readHeaderLine(rawInStream);//1
        if(DEBUG){
            cout << "Magic: "<<magic<<endl;
        }


        string versionStr = readHeaderLine(rawInStream);//2
        if(DEBUG){
            cout << "Version: "<<versionStr<<endl;
        }
        int version = stoi(versionStr);
        if(version < BACKUP_FILE_V1 || version > BACKUP_FILE_V5){
            cout << "抱歉,暂时不支持该版本的安卓备份解密!\n" << endl;
            return false;
        }


        string compressed = readHeaderLine(rawInStream); // 3
        bool isCompressed = stoi(compressed) == 1;
        if(DEBUG){
            cout << "Compressed: " << compressed << endl;
        }


        string encryptionAlg = readHeaderLine(rawInStream); // 4
        if(DEBUG){
            cout << "Algorithm: " << encryptionAlg << endl;
        }
        bool isEncrypted = false;
        
        //AES方式加解密
        if(encryptionAlg.compare(ENCRYPTION_ALGORTTHM_NAME) == 0 ){
            isEncrypted = true;
            string userSaltHex = readHeaderLine(rawInStream);//5
            if(DEBUG){
                cout << "userSaltHex: " << userSaltHex << endl;
            }
            vector<byte> vectorBytes = hexToBytes(userSaltHex);
            byte* userSalt = new byte[vectorBytes.size()];
            memcpy(userSalt,vectorBytes.data(),vectorBytes.size());
            

            string ckSaltHex = readHeaderLine(rawInStream);//6
            if(DEBUG){
                cout << "ckSaltHex: " << ckSaltHex << endl;
            }
            vector<byte> vectorCkSalt = hexToBytes(ckSaltHex);
            byte* ckSalt = new byte[vectorCkSalt.size()];
            memcpy(ckSalt,vectorCkSalt.data(),vectorCkSalt.size());


            int rounds = stoi(readHeaderLine(rawInStream));//7
            if(DEBUG){
                cout << "rounds: " << rounds << endl;
            }

            string userIvHex = readHeaderLine(rawInStream);//8
            if(DEBUG){
                cout << "userIvHex: " << userIvHex <<endl;
            }
            vector<byte> vectorIV = hexToBytes(userIvHex);
            byte* IV = new byte[vectorIV.size()];
            memcpy(IV,vectorIV.data(),vectorIV.size());



            string masterKeyBlobHex = readHeaderLine(rawInStream);//9
            if(DEBUG){
                cout << "masterKeyBlobHex: " <<masterKeyBlobHex <<endl;
            }
            vector<byte> vectorMasterKeyBlob = hexToBytes(masterKeyBlobHex);
            byte* masterKeyBlob = new byte[vectorMasterKeyBlob.size()];
            memcpy(masterKeyBlob,vectorMasterKeyBlob.data(),vectorMasterKeyBlob.size());


            //解密masterkeyBlob
            /*
               a5 c6 4a c4 09 62 aa 41 cc 37 8b 37 1e 14 3d 1a 
               9e 88 74 d7 e4 54 18 4b ed 0d 10 9c af 14 77 ed
            */
            byte aeskey[100]={0};
            pbkdf2(password.c_str(), (size_t)password.length(), userSalt, vectorBytes.size(), PBKDF2_HASH_ROUNDS, aeskey);
            vector<unsigned char> block_data(vectorMasterKeyBlob.size());
            int ret = aes_decrypt(masterKeyBlob, vectorMasterKeyBlob.size(), aeskey, IV, &block_data[0]);
            if (ret == -1)
            {
                printf("aes解密失败，应该是密码错误!\n");
                return false;
            }
            //parse decrypted blob
            int nmkIvLen = block_data[0];
            byte* mkIv = new byte[nmkIvLen];
            memcpy(mkIv, &block_data[0] + 1, nmkIvLen);
            if (DEBUG) {
                cout << "masterKey IV: " << byteToHexStr(mkIv, nmkIvLen)->c_str() << endl;
            }
            int nmkLen = block_data[nmkIvLen + 1];
            byte* mk = new byte[nmkLen];
            memcpy(mk, &block_data[nmkIvLen + 2], nmkLen);
            if (DEBUG) {
                cout << "masterKey: " << byteToHexStr(mk, nmkLen)->c_str() << endl;
            }
            int nckLen = block_data[nmkIvLen + nmkLen + 2];
            byte* ck = new byte[nckLen];
            memset(ck, 1, nckLen);
            memcpy(ck, &block_data[nmkIvLen + nmkLen + 3], nckLen);
            if (DEBUG) {
                cout << "check value: " << byteToHexStr(ck, nckLen)->c_str() << endl;
            }

            //密码验证
            //ck2 = PBKDF2(toBytes2, header['mkSumSalt'], Nck, header['round'])
            byte ck2[100] = { 0 };
            std::vector<unsigned char> vectormkBytes(nmkLen);
            std::copy(mk, mk+ nmkLen, vectormkBytes.begin());
            string utf8str = masterKeyJavaConversion(vectormkBytes);

            pbkdf2((char*)utf8str.c_str(), utf8str.size(), ckSalt, vectorCkSalt.size(), PBKDF2_HASH_ROUNDS, ck2);
            cout << "密码验证：" << endl;
            cout << "文件的  hash value: " << byteToHexStr(ck,  nckLen)->c_str() << endl;
            cout << "你密码的hash value: " << byteToHexStr(ck2, nckLen)->c_str() << endl;

            if (byteToHexStr(ck, nckLen)->compare(byteToHexStr(ck2, nckLen)->c_str()) != 0)
            {
                cout << "备份密码错误!" << endl;
            }
            else {
                cout << "备份密码正确:" << password << endl;
            }

            byte* _aeskey = mk;
            byte* _aesiv = mkIv;
            cout << "AES密钥:" << byteToHexStr(mk, nmkLen)->c_str() << endl;
            cout << "AES IV:" << byteToHexStr(mkIv, nmkIvLen)->c_str() << endl;
            int Bufferp = rawInStream.tellg();
            rawInStream.close();
            

            //利用Windows 的文件内存映射，读取大文件并且写出解密后的数据
            DWORD dwSize = 0;
            HANDLE hbackupFile = CreateFile(backupFilename.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            char tmpFilePath[MAX_PATH] = { 0 };
            wsprintfA(tmpFilePath, "%s.tmp", tarfilePath.c_str());
            HANDLE htarFile    = CreateFile(tmpFilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hbackupFile == INVALID_HANDLE_VALUE ||htarFile == INVALID_HANDLE_VALUE)
            {
                return false;
            }
            dwSize = GetFileSize(hbackupFile, NULL);
            //创建文件映射
            HANDLE mapping_file_backup = CreateFileMapping(hbackupFile, NULL, PAGE_READONLY, 0, dwSize,NULL);
            if (mapping_file_backup == NULL) {
                cout << "内存映射失败!1" << endl;
                CloseHandle(hbackupFile);
                CloseHandle(htarFile);
                return false;
            }
            HANDLE mapping_file_tarfile = CreateFileMapping(htarFile, NULL, PAGE_READWRITE, 0,dwSize , NULL);
            if (mapping_file_tarfile == NULL) {
                cout << "内存映射失败!2" << endl;
                CloseHandle(mapping_file_backup);
                CloseHandle(hbackupFile);
                CloseHandle(htarFile);
                return false;
            }
            //内存映射
            LPVOID mappingview_backup = MapViewOfFile(
                mapping_file_backup,
                FILE_MAP_READ,
                0,
                0,
                dwSize
            );
            if (mappingview_backup == NULL)
            {
                cout << "内存映射失败!3" << endl;
                CloseHandle(mapping_file_tarfile);
                CloseHandle(mapping_file_backup);
                CloseHandle(hbackupFile);
                CloseHandle(htarFile);
                return false;
            }
            LPVOID mappingview_tarfile = MapViewOfFile(
                mapping_file_tarfile,
                FILE_MAP_WRITE,
                0,
                0,
                dwSize
            );
            if (mappingview_tarfile == NULL)
            {
                cout << "内存映射失败!4" << endl;
                cout << "GetLastError()" << GetLastError() << endl;
                UnmapViewOfFile(mappingview_backup);
                CloseHandle(mapping_file_tarfile);
                CloseHandle(mapping_file_backup);
                CloseHandle(hbackupFile);
                CloseHandle(htarFile);
                return false;
            }
            int outlen = aes_decrypt((byte*)mappingview_backup + Bufferp, dwSize-Bufferp, _aeskey, _aesiv, (byte*)mappingview_tarfile);

            UnmapViewOfFile(mappingview_tarfile);
            UnmapViewOfFile(mappingview_backup);
            CloseHandle(mapping_file_tarfile);
            CloseHandle(mapping_file_backup);
            CloseHandle(hbackupFile);
            CloseHandle(htarFile);

            //zlib解压缩
            decompress(tmpFilePath, tarfilePath);
            DeleteFile(tmpFilePath);
            //---------------------------------------------------

            delete IV;
            delete mkIv;
            delete mk;
            delete ck;
            delete ckSalt;
            delete userSalt;
            delete masterKeyBlob;

        }

        return true;
    }catch(...)
    {
        return false;
    }
    return true;
}

/*
* 读取Android backup备份文件的文件头
* 具体操作手法就是一行一行读取，每行读取到以0x0A '\n'结尾。
* 参数：文件流
*
* 返回：每行的文本数据
*/
string AndroidBackup::readHeaderLine(istream& in) {
    int c;
    stringstream buffer;
    while ((c = in.get()) >= 0) {
        if (c == '\n')
            break;
        buffer << static_cast<char>(c);
    }
    return buffer.str();
}

/*
* 读取Android backup备份文件剩下的内容，剩下的内容就是备份文件的主体内容，被压缩和加密了
*
* 参数：文件流，每次读取的大小是128*1024字节，也就是0x20000
* 返回值：读取到的数据
*/
std::vector<char> AndroidBackup::chunkReader(std::ifstream& f, int chunkSize) {
    std::vector<char> data(chunkSize);
    f.read(data.data(), chunkSize);
    int bytesRead = f.gcount();
    if (bytesRead == 0) {
        data.clear();
        return data;
    }
    data.resize(bytesRead);
    return data;
}

/*
* PBKDF2密钥扩展函数，属于一种防止密码被暴力破解的防范措施。
* 需要稍微了解一点 加解密知识，具体可以百度pbkdf加密
* 
* 参数：密码，密码长度，salt
* 返回值：扩展后的密钥
*/
int AndroidBackup::pbkdf2(const char* password, int password_len, const byte* salt,
    int salt_len, int iterations, byte* out_key) 
{
    const EVP_MD* md = EVP_sha1();
    return PKCS5_PBKDF2_HMAC(password, password_len, salt, salt_len, iterations,
        md, 32, out_key);
}


/*
* AES解密函数，基于OPENSSL加解密库
* 参数很简单，自己看参数名就知道了
*/
int AndroidBackup::aes_decrypt(byte* encryptdata, int len, byte* key, byte* iv, byte* output)
{
    //init
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    //禁用填充
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    //Decrypt
    int ilen = 0;
    int outl = 0;
    EVP_DecryptUpdate(ctx, output + ilen, &outl, encryptdata + ilen, len);
    ilen += outl;
    EVP_DecryptFinal_ex(ctx, output + ilen, &outl);
    ilen += outl;
    EVP_CIPHER_CTX_cleanup(ctx);
    int outlen = ilen;
    return outlen;
}


/*
* 将Java byte数组转成utf-16编码数据
* 参考开源项目：https://github.com/lclevy/ab_decrypt/blob/master/ab_decrypt.py 
* def masterKeyJavaConversion(k)  函数
*/
string AndroidBackup::masterKeyJavaConversion(vector<unsigned char> x)
{
    //1.将无符号char数组，转换成有符号的char数组
    int len = x.size();
    //printf("步骤1：将无符号char数组，转换成有符号的char数组\n");
    //printf("无符号char数组:");
    //------------------------------------------------------------
    //for (size_t i = 0; i < len; i++)
    //{
    //    printf("0x%0x,", x[i]);
    //}
    //printf("\n");
    //signed char toSigned[32] = { 0 };
    vector<signed char> toSigned(len);
    /* printf("有符号char数组:");*/
    for (size_t i = 0; i < len; i++)
    {
        toSigned[i] = (signed char)x[i];
        /* printf("%d,", toSigned[i]);*/
    }
    /* printf("\n");*/

    //printf("\n步骤2：将有符号的char数组转换成无符号的16位数据，byte、word、dword!\n");
    vector<wchar_t> toUnsigned16bits(len + 2);
    //wchar_t toUnsigned16bits[34] = { 0 };
    //printf("无符号wchat数组:");
    for (size_t i = 0; i < len; i++)
    {
        toUnsigned16bits[i] = (wchar_t)toSigned[i] & 0xffff;
        // printf("%u,", toUnsigned16bits[i]);
    }
    toUnsigned16bits[32] = 0x00;
    toUnsigned16bits[33] = 0x00;
    //printf("\n");
    //printf("\n步骤3：将无符号的16位数组转换成byte数组\n");
    //// 一些用于测试的 uint16_t 数组
    //// 将 toUnsigned16bits 打包成字节串
    //size_t size = sizeof(toUnsigned16bits) / sizeof(toUnsigned16bits[0]);
    //std::vector<uint16_t> vectoUnsigned16bits(toUnsigned16bits, toUnsigned16bits + size);
    //std::vector<uint8_t> packed_data =  pack_uint16_vector(vectoUnsigned16bits);
    //// 输出结果
    //std::ostringstream oss;
    //oss << "Packed data: ";
    //for (const auto& byte_val : packed_data) {
    //    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte_val) << " ";
    //}
    //std::cout << oss.str() << std::endl;
    //printf("\n步骤4：将byte数组封装成wstring类型 Utf16be类型\n");
    //wstring toUtf16be = decodeUtf16BE(packed_data);
    //printf("\n步骤5：将wstring类型的utf16be编码转换成utf8编码\n");
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    std::string utf8str = converter.to_bytes((wchar_t*)toUnsigned16bits.data());
    return utf8str;
}

/*
* zlib解压，基于zlib解压缩库实现
*
* 参数：zlib压缩数据，zlib压缩压缩数据大小
* 返回：zlib解压后的数据
*/
int AndroidBackup::decompress(string tmptarFilePath,string tarFilePath)
{
    FILE* file;
    z_stream      strm = { 0 };
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.next_in = in;
    strm.avail_in = 0;
    CALL_ZLIB(inflateInit2(&strm, windowBits | ENABLE_ZLIB_GZIP));

    /* Open the file. */
    file = fopen(tmptarFilePath.c_str(), "rb");
    FAIL(!file, "open");
    FILE* fp = fopen(tarFilePath.c_str(), "ab");
    while (1)
    {
        int bytes_read;
        int zlib_status;

        bytes_read = fread(in, sizeof(char), sizeof(in), file);
        FAIL(ferror(file), "read");
        strm.avail_in = bytes_read;
        strm.next_in = in;
        do
        {
            unsigned have;
            strm.avail_out = CHUNK;
            strm.next_out = out;
            zlib_status = inflate(&strm, Z_NO_FLUSH);
            switch (zlib_status)
            {
            case Z_OK:
            case Z_STREAM_END:
            case Z_BUF_ERROR:
                break;

            default:
                inflateEnd(&strm);
                fprintf(stderr, "Gzip error %d in '%s'.\n", zlib_status, tarFilePath.c_str());
                return -1;
            }
            have = CHUNK - strm.avail_out;
            fwrite(out, sizeof(unsigned char), have, fp);
            // fwrite(out, sizeof(unsigned char), have, stdout);
        } while (strm.avail_out == 0);
        if (feof(file))
        {
            inflateEnd(&strm);
            break;
        }
    }
    FAIL(fclose(file), "close");
    FAIL(fclose(fp),   "close");
    return 0;
}



///////////////////////////////////////////////////////////////////////////////////////////////////////
//一下都是一些功能性的函数，无须知道具体代码实现，只需知道干嘛用的就行

//把hex格式的字符串，转成byte数组数据的
vector<byte> AndroidBackup::hexToBytes(const std::string& hex)
{
    std::vector<byte> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        byte _byte = (byte)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(_byte);
    }
    return bytes;
}
//把byte数组，转换成hex格式字符串的
string* AndroidBackup::byteToHexStr(unsigned char byte_arr[], int arr_len)
{
    string* hexstr = new string();
    for (int i = 0; i < arr_len; i++)
    {
        char hex1;
        char hex2;
        int value = byte_arr[i]; //直接将unsigned char赋值给整型的值，系统会正动强制转换
        int v1 = value / 16;
        int v2 = value % 16;

        //将商转成字母
        if (v1 >= 0 && v1 <= 9)
            hex1 = (char)(48 + v1);
        else
            hex1 = (char)(55 + v1);

        //将余数转成字母
        if (v2 >= 0 && v2 <= 9)
            hex2 = (char)(48 + v2);
        else
            hex2 = (char)(55 + v2);

        //将字母连接成串
        *hexstr = *hexstr + hex1 + hex2;
    }
    return hexstr;
}
//判断路径文件是否存在
bool AndroidBackup::pathExists(const char* path)
{
    DWORD attributes = GetFileAttributes(path);
    if (INVALID_FILE_ATTRIBUTES == attributes || (attributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        return false;
    }
    else
    {
        return true;
    }
}

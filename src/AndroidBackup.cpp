#include "AndroidBackup.h"

using namespace std;


/*
* Android backup���ݽ��ܴ��룬��Ѽ��ܵ�Android backup�����ļ������ܺ������xxx.tar��ʽ����
* �����������ļ�·����������.tar�ļ�·��,��������
* 
* ���������������Ļ�������ʾ�������
* �����ļ��ᰴ��ÿ��128*1024�ֽڽ��ж�ȡ�����ҽ��н����ٽ�ѹ
* �����������ѹ���ļ������xxx.tar�ļ����档
* 
* ԭ��
*      Android backup�����ļ�ԭ����������������水�����1.2.3.4����ע���ˣ���ֱ��ȡ���õ�����
*      Ȼ������жϱ����ļ��Ƿ���ܣ�����ʲô���ܣ�֮�������Կ����ȡ��Ȼ����Կת�������ת����aes����Կ
*      ֮�󽫱����ļ����ܵ����ݣ�����AES���ܣ����ܺ��ٽ���zlib��ѹ��������Android backup�����ļ��������ˡ�
*/
bool AndroidBackup::extractAsTar(string backupFilename,string tarfilePath,string password)
{
    try{
        if(!pathExists(backupFilename.c_str())){
            printf("�����ļ�������:%s\n",backupFilename.c_str());
            return false;
        }
        ifstream rawInStream = ifstream(backupFilename.c_str(),ios::binary);
        if(!rawInStream.is_open()){
            cout << "��ȡ�����ļ�ʧ��" << backupFilename.c_str() << "[����·���Ƿ���ȷ�����߹���ԱȨ��!]" << endl;
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
            cout << "��Ǹ,��ʱ��֧�ָð汾�İ�׿���ݽ���!\n" << endl;
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
        
        //AES��ʽ�ӽ���
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


            //����masterkeyBlob
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
                printf("aes����ʧ�ܣ�Ӧ�����������!\n");
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

            //������֤
            //ck2 = PBKDF2(toBytes2, header['mkSumSalt'], Nck, header['round'])
            byte ck2[100] = { 0 };
            std::vector<unsigned char> vectormkBytes(nmkLen);
            std::copy(mk, mk+ nmkLen, vectormkBytes.begin());
            string utf8str = masterKeyJavaConversion(vectormkBytes);

            pbkdf2((char*)utf8str.c_str(), utf8str.size(), ckSalt, vectorCkSalt.size(), PBKDF2_HASH_ROUNDS, ck2);
            cout << "������֤��" << endl;
            cout << "�ļ���  hash value: " << byteToHexStr(ck,  nckLen)->c_str() << endl;
            cout << "�������hash value: " << byteToHexStr(ck2, nckLen)->c_str() << endl;

            if (byteToHexStr(ck, nckLen)->compare(byteToHexStr(ck2, nckLen)->c_str()) != 0)
            {
                cout << "�����������!" << endl;
            }
            else {
                cout << "����������ȷ:" << password << endl;
            }

            byte* _aeskey = mk;
            byte* _aesiv = mkIv;
            cout << "AES��Կ:" << byteToHexStr(mk, nmkLen)->c_str() << endl;
            cout << "AES IV:" << byteToHexStr(mkIv, nmkIvLen)->c_str() << endl;
            int Bufferp = rawInStream.tellg();
            rawInStream.close();
            

            //����Windows ���ļ��ڴ�ӳ�䣬��ȡ���ļ�����д�����ܺ������
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
            //�����ļ�ӳ��
            HANDLE mapping_file_backup = CreateFileMapping(hbackupFile, NULL, PAGE_READONLY, 0, dwSize,NULL);
            if (mapping_file_backup == NULL) {
                cout << "�ڴ�ӳ��ʧ��!1" << endl;
                CloseHandle(hbackupFile);
                CloseHandle(htarFile);
                return false;
            }
            HANDLE mapping_file_tarfile = CreateFileMapping(htarFile, NULL, PAGE_READWRITE, 0,dwSize , NULL);
            if (mapping_file_tarfile == NULL) {
                cout << "�ڴ�ӳ��ʧ��!2" << endl;
                CloseHandle(mapping_file_backup);
                CloseHandle(hbackupFile);
                CloseHandle(htarFile);
                return false;
            }
            //�ڴ�ӳ��
            LPVOID mappingview_backup = MapViewOfFile(
                mapping_file_backup,
                FILE_MAP_READ,
                0,
                0,
                dwSize
            );
            if (mappingview_backup == NULL)
            {
                cout << "�ڴ�ӳ��ʧ��!3" << endl;
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
                cout << "�ڴ�ӳ��ʧ��!4" << endl;
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

            //zlib��ѹ��
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
* ��ȡAndroid backup�����ļ����ļ�ͷ
* ��������ַ�����һ��һ�ж�ȡ��ÿ�ж�ȡ����0x0A '\n'��β��
* �������ļ���
*
* ���أ�ÿ�е��ı�����
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
* ��ȡAndroid backup�����ļ�ʣ�µ����ݣ�ʣ�µ����ݾ��Ǳ����ļ����������ݣ���ѹ���ͼ�����
*
* �������ļ�����ÿ�ζ�ȡ�Ĵ�С��128*1024�ֽڣ�Ҳ����0x20000
* ����ֵ����ȡ��������
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
* PBKDF2��Կ��չ����������һ�ַ�ֹ���뱻�����ƽ�ķ�����ʩ��
* ��Ҫ��΢�˽�һ�� �ӽ���֪ʶ��������԰ٶ�pbkdf����
* 
* ���������룬���볤�ȣ�salt
* ����ֵ����չ�����Կ
*/
int AndroidBackup::pbkdf2(const char* password, int password_len, const byte* salt,
    int salt_len, int iterations, byte* out_key) 
{
    const EVP_MD* md = EVP_sha1();
    return PKCS5_PBKDF2_HMAC(password, password_len, salt, salt_len, iterations,
        md, 32, out_key);
}


/*
* AES���ܺ���������OPENSSL�ӽ��ܿ�
* �����ܼ򵥣��Լ�����������֪����
*/
int AndroidBackup::aes_decrypt(byte* encryptdata, int len, byte* key, byte* iv, byte* output)
{
    //init
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    //�������
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
* ��Java byte����ת��utf-16��������
* �ο���Դ��Ŀ��https://github.com/lclevy/ab_decrypt/blob/master/ab_decrypt.py 
* def masterKeyJavaConversion(k)  ����
*/
string AndroidBackup::masterKeyJavaConversion(vector<unsigned char> x)
{
    //1.���޷���char���飬ת�����з��ŵ�char����
    int len = x.size();
    //printf("����1�����޷���char���飬ת�����з��ŵ�char����\n");
    //printf("�޷���char����:");
    //------------------------------------------------------------
    //for (size_t i = 0; i < len; i++)
    //{
    //    printf("0x%0x,", x[i]);
    //}
    //printf("\n");
    //signed char toSigned[32] = { 0 };
    vector<signed char> toSigned(len);
    /* printf("�з���char����:");*/
    for (size_t i = 0; i < len; i++)
    {
        toSigned[i] = (signed char)x[i];
        /* printf("%d,", toSigned[i]);*/
    }
    /* printf("\n");*/

    //printf("\n����2�����з��ŵ�char����ת�����޷��ŵ�16λ���ݣ�byte��word��dword!\n");
    vector<wchar_t> toUnsigned16bits(len + 2);
    //wchar_t toUnsigned16bits[34] = { 0 };
    //printf("�޷���wchat����:");
    for (size_t i = 0; i < len; i++)
    {
        toUnsigned16bits[i] = (wchar_t)toSigned[i] & 0xffff;
        // printf("%u,", toUnsigned16bits[i]);
    }
    toUnsigned16bits[32] = 0x00;
    toUnsigned16bits[33] = 0x00;
    //printf("\n");
    //printf("\n����3�����޷��ŵ�16λ����ת����byte����\n");
    //// һЩ���ڲ��Ե� uint16_t ����
    //// �� toUnsigned16bits ������ֽڴ�
    //size_t size = sizeof(toUnsigned16bits) / sizeof(toUnsigned16bits[0]);
    //std::vector<uint16_t> vectoUnsigned16bits(toUnsigned16bits, toUnsigned16bits + size);
    //std::vector<uint8_t> packed_data =  pack_uint16_vector(vectoUnsigned16bits);
    //// ������
    //std::ostringstream oss;
    //oss << "Packed data: ";
    //for (const auto& byte_val : packed_data) {
    //    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte_val) << " ";
    //}
    //std::cout << oss.str() << std::endl;
    //printf("\n����4����byte�����װ��wstring���� Utf16be����\n");
    //wstring toUtf16be = decodeUtf16BE(packed_data);
    //printf("\n����5����wstring���͵�utf16be����ת����utf8����\n");
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    std::string utf8str = converter.to_bytes((wchar_t*)toUnsigned16bits.data());
    return utf8str;
}

/*
* zlib��ѹ������zlib��ѹ����ʵ��
*
* ������zlibѹ�����ݣ�zlibѹ��ѹ�����ݴ�С
* ���أ�zlib��ѹ�������
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
//һ�¶���һЩ�����Եĺ���������֪���������ʵ�֣�ֻ��֪�������õľ���

//��hex��ʽ���ַ�����ת��byte�������ݵ�
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
//��byte���飬ת����hex��ʽ�ַ�����
string* AndroidBackup::byteToHexStr(unsigned char byte_arr[], int arr_len)
{
    string* hexstr = new string();
    for (int i = 0; i < arr_len; i++)
    {
        char hex1;
        char hex2;
        int value = byte_arr[i]; //ֱ�ӽ�unsigned char��ֵ�����͵�ֵ��ϵͳ������ǿ��ת��
        int v1 = value / 16;
        int v2 = value % 16;

        //����ת����ĸ
        if (v1 >= 0 && v1 <= 9)
            hex1 = (char)(48 + v1);
        else
            hex1 = (char)(55 + v1);

        //������ת����ĸ
        if (v2 >= 0 && v2 <= 9)
            hex2 = (char)(48 + v2);
        else
            hex2 = (char)(55 + v2);

        //����ĸ���ӳɴ�
        *hexstr = *hexstr + hex1 + hex2;
    }
    return hexstr;
}
//�ж�·���ļ��Ƿ����
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

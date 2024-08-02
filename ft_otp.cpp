#include<iostream>
#include<string.h>
#include<fstream>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include<cstring>
#include <sstream>
#include<cmath>

std::string xor_encrypt(const std::string &data, const char *key) {
    std::string encrypted(data);

    std::string encrypted_data(encrypted.size(), '\0');
    unsigned char uchar_key = static_cast<unsigned char>(*key);
    for (size_t i = 0; i < encrypted.size(); ++i) {
        encrypted_data[i] = static_cast<unsigned char>(encrypted[i]) ^ uchar_key;
    }
    return encrypted_data;
}

std::string xor_decrypt(const std::string &data, const char *key) {
    return xor_encrypt(data, key);
}

int parseFileName(std::string file, std::string desiredextention){
    size_t ext = file.find(desiredextention);
    if (ext == std::string::npos)
        return (-1);
    return (0);
}

const char *ConvertTimeToByte(time_t *time){
    return reinterpret_cast<const char *>(time);
}

class HOTP{
    private:
        char secretKey[16];
        std::string key;
        std::string hash;
    public:

        void EncryptKey(){

        }
        unsigned char *hmac (const char *currenttime, const char * key){
            size_t seckey_len = std::strlen(key);
            const char *data = currenttime;
            const int data_len = std::strlen(data);
            unsigned char *resault = HMAC(EVP_sha1(), key, seckey_len, 
                                        (unsigned char *)data, 
                                        data_len,
                                        NULL,
                                        NULL);
            if (resault)
                return resault;
            else{
                std::cout << "error in hashing function" << std::endl;
                exit(0);
            }
        }

        HOTP(){
            std::string tempKey = "Super Secret key";
            strncpy(this->secretKey, tempKey.c_str(), sizeof(this->secretKey) - 1);
            secretKey[sizeof(secretKey) - 1] = '\0';
        }

        void StoreHashedKey(){
            std::string encryptedKey = xor_encrypt(key, this->secretKey);

            std::cout << "Original key: " << key << std::endl;
            std::cout << "encrypted key: " << encryptedKey << std::endl;

            std::ofstream f2;
            f2.open("ft_otp.key", std::ios::out);
            if (f2.is_open() == false){
                std::cout << "file not opened" << std::endl;
                exit(1);
            }
            f2.write(encryptedKey.c_str(), encryptedKey.size());
            f2.close();
            std::cout << "Key was successfully saved in ft_otp.key." << std::endl;
        }

        void GetHexKey(std::string filename){
            std::ifstream file;

            if (parseFileName(filename, ".hex") < 0){
                std::cout << "file extention must be .hex format !" << std::endl;
                exit(0);
            }
            file.open(filename, std::ios::in);
            if (file.is_open()){
                std::getline(file, this->key);
                if (this->key.length() < 64){
                    std::cout << "error: key must be 64 hexadecimal characters." << std::endl;
                    file.close();
                    std::exit(1);
                }
                file.close();
                return;
            }
            std::cout << "file name not corret" << std::endl;
            exit(0);
        }

        void StoreKey(std::string filename){
            this->GetHexKey(filename);
            this->StoreHashedKey();
        }

        void GetHotp(std::string file){
            unsigned char *hash;
            size_t fileSize;
            std::ifstream f;
            std::string decryptedKey;
            const char *ctime;
            int offset;
            int bin_code;
            int otp;

            if (parseFileName(file, ".key")){
                std::cout << "file extention must be .key format !" << std::endl;
                exit(0);
            }
            f.open(file, std::ios::in);
            if (f.is_open() == false){
                std::cout << "file not opened" << std::endl;
                exit(1);
            }
            f.seekg(0, std::ios::end);
            fileSize = f.tellg();
            f.seekg(0, std::ios::beg);
            std::string encrypted(fileSize, '\0');
            f.read(&encrypted[0], fileSize);
            f.close();
            decryptedKey = xor_decrypt(encrypted, this->secretKey);
            std::cout << "decrypted data : " << decryptedKey << std::endl;
            this->GetHexKey("key.hex");
            if (this->key == decryptedKey){
                std::cout << "Authorized" << std::endl;
            }
            time_t now = time(0);
            std::cout << "current time : " << now  << std::endl;
            ctime = ConvertTimeToByte(&now);
            hash = hmac(ctime, decryptedKey.c_str());
            offset = hash[19] & 0xf;
            bin_code = ((hash[offset] & 0x7f) << 24 | (hash[offset + 1] & 0xff) << 16 | (hash[offset + 2] & 0xff) << 8 | (hash[offset + 3] & 0xff));
            otp = bin_code % 1000000;
            printf("%d\n", otp);
        }

        std::string getKey() const{
            return this->key;
        }

        std::string getHash() const{
            return this->hash;
        }

        ~HOTP(){}
};

int main(int argc, char **argv){
    HOTP hotp;
    if (argc == 3){
        if (strcmp(argv[1], "-g") == 0 and argv[2]){
            hotp.StoreKey(argv[2]);
        }
        if (strcmp(argv[1], "-k") == 0){
            hotp.GetHotp(argv[2]);
        }
    }
    else{
        std::cout << "program require [-g -k] option" << std::endl;
        exit(1);
    }
    return 0;
}
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

class HOTP{
    private:
        char secretKey[16];
        std::string key;
        std::string hash;
    public:

        void EncryptKey(){

        }
        unsigned char *hmac (){
            const char *seckey = "SUPER SECRET KEY";
            const int seckey_len = std::strlen(seckey);
            const char *data = this->key.c_str();
            const int data_len = std::strlen(data);
            unsigned char *resault = HMAC(EVP_sha1(), seckey, seckey_len, 
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
            f2.open("ft_otp.key", std::ios::out | std::ios::binary);
            if (f2.is_open() == false){
                std::cout << "file not opened" << std::endl;
                exit(1);
            }
            f2.write(reinterpret_cast<const char *>(encryptedKey.c_str()), 20);
            f2.close();
            std::cout << "Key was successfully saved in ft_otp.key." << std::endl;
        }

        void StoreKey(std::string filename){
            if (parseFileName(filename, ".hex") < 0){
                std::cout << "file extention must be .hex format !" << std::endl;
                exit(0);
            }
            std::ifstream file(filename, std::ios::in);
            if (file.is_open()){
                std::getline(file, this->key);
                file.close();
                if (this->key.length() < 64){
                    std::cout << "error: key must be 64 hexadecimal characters." << std::endl;
                    std::exit(1);
                }
                this->StoreHashedKey();
            }
            else{
                std::cout << "file name not corret" << std::endl;
                exit(0);
            }
            file.close();
        }

        void GetHotp(std::string file){
            // std::string decryptedKey = xor_decrypt(encryptedKey, secretKey);
            unsigned char *hash = hmac();
            if (parseFileName(file, ".key")){
                std::cout << "file extention must be .key format !" << std::endl;
                exit(0);
            }
            std::ifstream f;
            f.open(file, std::ios::in | std::ios::binary);
            if (f.is_open() == false){
                std::cout << "file not opened" << std::endl;
                exit(1);
            }
            f.close();
            int offset = hash[19] & 0xf;
            int bin_code = ((hash[offset] & 0x7f) << 24 | (hash[offset + 1] & 0xff) << 16 | (hash[offset + 2] & 0xff) << 8 | (hash[offset + 3] & 0xff));
            int otp = bin_code % 1000000;
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
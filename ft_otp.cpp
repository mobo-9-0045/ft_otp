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

int parseFileName(std::string file, std::string desiredextention){
    size_t ext = file.find(desiredextention);
    if (ext == std::string::npos)
        return (-1);
    return (0);
}

class HOTP{
    private:
        std::string key;
        std::string hash;
    public:
        unsigned char *ft_Hmac (){
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
        HOTP(){}

        void StoreHashedKey(){
            unsigned char *hash = ft_Hmac();
            std::ofstream f2;
            f2.open("ft_otp.key", std::ios::out | std::ios::binary);
            if (f2.is_open() == false){
                std::cout << "file not opened" << std::endl;
                exit(1);
            }
            f2.write(reinterpret_cast<const char *>(hash), 20);
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
            unsigned char res[20];
            f.read(reinterpret_cast<char *>(res), 20);
            f.close();
            int offset = res[19] & 0xf;
            int bin_code = ((res[offset] & 0x7f) << 24 | (res[offset + 1] & 0xff) << 16 | (res[offset + 2] & 0xff) << 8 | (res[offset + 3] & 0xff));
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
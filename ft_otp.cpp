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
            return resault;
        }
        HOTP(){
            std::cout << "Default HOTP Constructor called" << std::endl;
        }
        void storingKey(std::string filename){
            std::ifstream file(filename);
            if (file.is_open()){
                std::getline(file, this->key);
                if (this->key.length() < 64){
                    std::cout << "key lenght must contain at least 64 characters" << std::endl;
                    std::exit(1);
                }
                else{
                    unsigned char* res = ft_Hmac();
                    for (int i = 0; i < 20; i++) {
                        printf("%02x\n", res[i]);
                    }
                    std::ofstream f2;
                    f2.open("ft_otp.key", std::ios::out | std::ios::binary);
                    if (f2.is_open() == false){
                        std::cout << "file not opened" << std::endl;
                        exit(1);
                    }
                    f2.write(reinterpret_cast<const char *>(res), 20);
                    f2.close();
                }
            }
            else{
                std::cout << "file name not corrext" << std::endl;
                exit(0);
            }
        }

        void getHotp(){
            std::ifstream f;
            f.open("ft_otp.key", std::ios::in | std::ios::binary);
            if (f.is_open() == false){
            std::cout << "file not opened" << std::endl;
                exit(1);
            }
            unsigned char res[20];
            f.read(reinterpret_cast<char *>(res), 20);
            f.close();
            for (int i = 0; i < 20; i++) {
                printf("%02x\n", res[i]);
            }
        }

        std::string getKey() const{
            return this->key;
        }

        std::string getHash() const{
            return this->hash;
        }

        ~HOTP(){
            std::cout << "Default HOTP Destructor called" << std::endl;
        }
};

int main(int argc, char **argv){
    HOTP hotp;
    if (argc == 3){
        if (strcmp(argv[1], "-g") == 0){
            hotp.storingKey(argv[2]);
        }
    }
    else if (argc == 2){
        if (strcmp(argv[1], "-k") == 0){
            hotp.getHotp();
        }
    }
    else{
        std::cout << "program require [-g -k] option" << std::endl;
        exit(1);
    }
    return 0;
}
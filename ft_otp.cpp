#include<iostream>
#include<string.h>
#include"HOTP.hpp"
#include<fstream>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

class HOTP{
    private:
        std::string key;
        std::string hash;
    public:
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
            }
            else{
                std::cout << "file name not corrext" << std::endl;
                exit(0);
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
    if (argc == 3){
        HOTP hotp;
        if (strcmp(argv[1], "-g") == 0){
            hotp.storingKey(argv[2]);
            std::cout << "key : " << hotp.getKey() << "Hash : "<< hotp.getHash() << std::endl;
        }
        if (strcmp(argv[1], "-k") == 0){
            std::cout << "-k" << std::endl;
        }
    }
    return 0;
}
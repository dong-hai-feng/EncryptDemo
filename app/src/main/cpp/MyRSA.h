//
// Created by Administrator on 2017/10/10.
//

#ifndef ENCRYPTDEMO_MYRSA_H
#define ENCRYPTDEMO_MYRSA_H

#include <string>

class MyRSA{
public:
    static std::string encryptRSAbyPublickey(const std::string& data,int *lenreturn);
    static std::string decryptRSAbyPublicKey(const std::string& data);

    static std::string encryptRSAbyPrivateKey(const std::string& data,int *lenreturn);
    static std::string decryptRSAbyPrivateKey(const std::string& data);
};

#endif //ENCRYPTDEMO_MYRSA_H

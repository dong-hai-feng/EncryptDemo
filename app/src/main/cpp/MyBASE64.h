//
// Created by Administrator on 2017/10/10.
//

#ifndef ENCRYPTDEMO_MYBASE64_H
#define ENCRYPTDEMO_MYBASE64_H

#include <stdio.h>
#include <string>

class MyBASE64 {

public:
    static std::string base64_decode(const std::string& encoded_bytes,
                                     int *decoded_length) ;
    static std::string base64_encode(const std::string& decoded_bytes,
                                     size_t decoded_length) ;



    static std::string base64_encodestring(const std::string &text );
    static  std::string base64_decodestring(const std::string &text );

};


#endif //ENCRYPTDEMO_MYBASE64_H

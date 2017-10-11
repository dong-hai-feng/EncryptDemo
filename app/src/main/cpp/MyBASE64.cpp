//
// Created by Administrator on 2017/10/10.
//

#include <evp.h>
#include "MyBASE64.h"
#include <buffer.h>

std::string MyBASE64::base64_encodestring(const std::string &text ){
    EVP_ENCODE_CTX ectx;
    int size = text.size()*2;
    size = size > 64 ? size : 64;
    unsigned char* out = (unsigned char*)malloc( size );
    int outlen = 0;
    int tlen = 0;
    EVP_EncodeInit( &ectx );
    EVP_EncodeUpdate( &ectx, out, &outlen, (const unsigned char*)text.c_str(), text.size() );
    tlen += outlen;
    EVP_EncodeFinal( &ectx, out+tlen, &outlen );
    tlen += outlen;

    std::string str( (char*)out, tlen );
    free( out );
    return str;
}

std::string MyBASE64::base64_decodestring(const std::string &text ){
    EVP_ENCODE_CTX ectx;
    unsigned char* out = (unsigned char*)malloc( text.size() );
    int outlen = 0;
    int tlen = 0;

    EVP_DecodeInit( &ectx );
    EVP_DecodeUpdate( &ectx, out, &outlen, (const unsigned char*)text.c_str(), text.size() );
    tlen += outlen;
    EVP_DecodeFinal( &ectx, out+tlen, &outlen );
    tlen += outlen;

    std::string data( (char*)out, tlen );
    free( out );
    return data;
}






std::string MyBASE64::base64_decode(const std::string& encoded_bytes, int *decoded_length) {
    BIO *bioMem, *b64;
    size_t buffer_length;

    bioMem = BIO_new_mem_buf((void *) encoded_bytes.c_str(), -1);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bioMem = BIO_push(b64, bioMem);

    buffer_length = BIO_get_mem_data(bioMem, NULL);

    static std::string  decoded_bytes;

    decoded_bytes.clear();

    *decoded_length = BIO_read(bioMem, (void *)decoded_bytes.c_str(), (int)buffer_length);
    BIO_free_all(bioMem);

    return  decoded_bytes;
}
/* Return NULL if failed, REMEMBER to free() */
std::string MyBASE64::base64_encode(const std::string& decoded_bytes,

                                    size_t decoded_length) {


    int x;
    BIO *bioMem, *b64;
    BUF_MEM *bufPtr;
    static std::string buff ;
    buff.clear();

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bioMem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bioMem);

    BIO_write(b64,decoded_bytes.c_str(), (int)decoded_length);
    x = BIO_flush(b64);
    if (x < 1)
        goto END;

    BIO_get_mem_ptr(b64, &bufPtr);

    buff.assign(bufPtr->data);

    END: BIO_free_all(b64);
    return buff;
}


//
// Created by Administrator on 2017/10/10.
//

#include "MyRSA.h"
#include <cstddef>
#include <stdlib.h>
#include "Log.h"


#include "openssllib/include/openssl/bio.h"

#include "openssllib/include/openssl/evp.h"
#include "openssllib/include/openssl/rsa.h"
#include "openssllib/include/openssl/pem.h"

#define PUBLICKEY    "----"//公钥

#define PRIVATE_KEY  "----"//私钥


#define  PADDING   RSA_PKCS1_PADDING          //填充方式
/**
 * 注意注意：不能用一种秘钥同时做加密解密。只能公钥加密+私钥解密 / 私钥加密+公钥解密
 *
 * 公钥存在客户端，私钥存在服务端
 * */

/**
 * 公钥加密
 * */
std::string MyRSA::encryptRSAbyPublickey(const std::string &data, int *lenreturn) {
    int ret, flen;
    BIO *bio = NULL;
    RSA *r = NULL;

    if ((bio = BIO_new_mem_buf((void *) PUBLICKEY, -1)) == NULL)       //从字符串读取RSA公钥
    {
        LOGE("BIO_new_mem_buf failed!\n");
    }

    r = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    flen = RSA_size(r);

    if (PADDING == RSA_PKCS1_PADDING || PADDING == RSA_SSLV23_PADDING) {
//        flen -= 11;
    }

    lenreturn = &flen;

    static std::string gkbn;
    gkbn.clear();

    char *dst = (char *) malloc(flen + 1);
    bzero(dst, flen);

    int status = RSA_public_encrypt(data.length(), (unsigned char *) data.c_str(),
                                    (unsigned char *) dst, r, RSA_PKCS1_PADDING);
    if (status < 0) {

        LOGE("RSA 公钥加密失败--->%d", status);
        return "";

    }

    gkbn.assign((char *) dst, status);

    RSA_free(r);
    BIO_free_all(bio);

    free(dst);

    //CRYPTO_cleanup_all_ex_data(); //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏

    return gkbn;
}
/**
 * 公钥解密
 * */
std::string MyRSA::decryptRSAbyPublicKey(const std::string &data) {
    int ret, flen;
    BIO *bio = NULL;
    RSA *r = NULL;
    LOGE("RSA 公钥解密开始--->%d", 1);
    if ((bio = BIO_new_mem_buf((void *) PUBLICKEY, -1)) == NULL)       //从字符串读取RSA公钥
    {
        LOGE("BIO_new_mem_buf failed!\n");
    }
    LOGE("RSA 公钥解密开始--->%d", 2);
    r = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    flen = RSA_size(r);
    LOGE("RSA 公钥解密开始--->%d", 3);
    if (PADDING == RSA_PKCS1_PADDING || PADDING == RSA_SSLV23_PADDING) {
//        flen -= 11;
    }
    LOGE("RSA 公钥解密开始--->%d", 4);
    static std::string gkbn;
    gkbn.clear();
    LOGE("RSA 公钥解密开始--->%d", 5);
    char *dst = (char *) malloc(flen + 1);
    bzero(dst, flen);
    LOGE("RSA 公钥解密开始--->%d", 6);
    int status = RSA_public_decrypt(data.length(), (unsigned char *) data.c_str(),
                                    (unsigned char *) dst, r, RSA_PKCS1_PADDING);//RSA_NO_PADDING //RSA_PKCS1_PADDING
    if (status < 0) {

        LOGE("RSA 公钥解密失败--->%d", status);
        return "";

    }

    gkbn.assign((char *) dst, status);//防止 尾部0 被截断

    BIO_free_all(bio);

    free(dst);

    // CRYPTO_cleanup_all_ex_data(); //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏

    return gkbn;

}
/**
 * 私钥加密
 * */
std::string MyRSA::encryptRSAbyPrivateKey(const std::string &data, int *lenreturn) {
    int ret, flen;
    BIO *bio = NULL;
    RSA *r = NULL;

    if ((bio = BIO_new_mem_buf((void *) PRIVATE_KEY, -1)) == NULL)       //从字符串读取RSA公钥
    {
        LOGE("BIO_new_mem_buf failed!\n");
    }

    r = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    flen = RSA_size(r);

    if (PADDING == RSA_PKCS1_PADDING || PADDING == RSA_SSLV23_PADDING) {
//        flen -= 11;
    }

    lenreturn = &flen;

    static std::string gkbn;
    gkbn.clear();

    char *dst = (char *) malloc(flen + 1);
    bzero(dst, flen);

    int status = RSA_private_encrypt(data.length(), (unsigned char *) data.c_str(),
                                     (unsigned char *) dst, r, RSA_PKCS1_PADDING);

    if (status < 0) {

        LOGE("RSA 私钥加密失败--->%d", status);
        return "";

    }

    gkbn.assign((char *) dst, status);

    RSA_free(r);
    BIO_free_all(bio);

    free(dst);

    //CRYPTO_cleanup_all_ex_data(); //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏

    return gkbn;
}
/**
 * 私钥解密
 * */
std::string MyRSA::decryptRSAbyPrivateKey(const std::string &data) {
    int ret, flen;
    BIO *bio = NULL;
    RSA *r = NULL;

    if ((bio = BIO_new_mem_buf((void *) PRIVATE_KEY, -1)) == NULL)       //从字符串读取RSA公钥
    {
        LOGE("BIO_new_mem_buf failed!\n");
    }

    r = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    flen = RSA_size(r);

    static std::string gkbn;
    gkbn.clear();

    char *dst = (char *) malloc(flen + 1);
    bzero(dst, flen);

    int status = RSA_private_decrypt(data.length(), (unsigned char *) data.c_str(),
                                     (unsigned char *) dst, r, RSA_PKCS1_PADDING);//RSA_NO_PADDING //RSA_PKCS1_PADDING
    if (status < 0) {

        LOGE("RSA 私钥解密失败--->%d", status);
        return "";

    }

    gkbn.assign((char *) dst, status);//防止 尾部0 被截断

    BIO_free_all(bio);

    free(dst);

    // CRYPTO_cleanup_all_ex_data(); //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏

    return gkbn;
}

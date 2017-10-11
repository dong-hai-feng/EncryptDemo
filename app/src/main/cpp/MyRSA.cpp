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

#define PUBLICKEY    "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjJtwWG4PnfzdR4IFOmvN\nPQpGnWasLHbKe5/HdLupj+lhUR8/l2JHfFgUI3N8cmBJM4jSz4V/ChGvquz+1Z3M\nMyCb+EqcC1Dv4Nck2YP3Cu7l1jwWk75W036ljtsi7SDUi+0MyG/Zv3fIay+wOn7r\na4ByvTLLfyXHSz57Bb+INni0Zsq8XvaDhVw99AtZoFJDBJwqRsOelxO/V1M9e0FW\ncND3ufirk3tj8IDNLrHVG2tsxwOu7Rc1byfacHvpObekFRMvUyvgm7uan/KkFQcY\nyB0SxQi0g3FxMLriBROafrUng0vY+oexGGDDadU0qu9od1jcGbJCsIyH6iAfngsS\nEQIDAQAB\n-----END PUBLIC KEY-----\n"

#define PRIVATE_KEY  "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCMm3BYbg+d/N1H\nggU6a809CkadZqwsdsp7n8d0u6mP6WFRHz+XYkd8WBQjc3xyYEkziNLPhX8KEa+q\n7P7VncwzIJv4SpwLUO/g1yTZg/cK7uXWPBaTvlbTfqWO2yLtINSL7QzIb9m/d8hr\nL7A6futrgHK9Mst/JcdLPnsFv4g2eLRmyrxe9oOFXD30C1mgUkMEnCpGw56XE79X\nUz17QVZw0Pe5+KuTe2PwgM0usdUba2zHA67tFzVvJ9pwe+k5t6QVEy9TK+Cbu5qf\n8qQVBxjIHRLFCLSDcXEwuuIFE5p+tSeDS9j6h7EYYMNp1TSq72h3WNwZskKwjIfq\nIB+eCxIRAgMBAAECggEAKmWAJZniKaAiVLp2uxvgQcSEcFeSGMIk4cvWx3MCeLtF\nNcG3Wf0vUuX4BIyA/LfduqVJ83rsSGv2zRIy8NRoyw3NGbvde2gHPIOCv/eTmP9Z\n3BQ4NopRAeqRHxciW9/nVt2+Wf2n6ZzDmNZDTBATClIrxrK3O3p3sk9/pscO2mVt\n1LiM0FJtfiFOcCsLDRSXi0rsk9ezo8iE8sdeU+WVKPbX9ChnCqfH2Cwme4niEakg\n8f6Aebwr9DmRRsc6cxDLfKvqwwcZVx+snnMrvXQMzCUDY9agYT1MWQrypCjbwiNZ\nNElRDWQk9Tl4mg8RzdSKR/jFmlZ6++OgFzoxlhFYdQKBgQDUSP54mGOLOS8j32Sk\niMI/hqPuQOLLLM8aZzSAa1by7KZChv6A3uO4xQhCfQoP0JhDaY7jTO4xF45qPFtn\nnMlAsAghmzfvt6470goZv1ZGpiTEM4XSpMDUE2hvFEPWceKocFV/CjN0VA4D6cSH\nPveszT3TIYc8iC39TimweEPr2wKBgQCpj87p3vcCZSSICPJfo/iuL6baobiRqcVD\nW8U7fBbjRP/G0VG5zbOAhe8zCGVh4gs1jc+M/G3Pn7mZPW9YqLeHyqseG2v2aB0F\n6CUCzm6oSUBayWXpmwtG3rUn4Q1UAQTfilI48ljyykbiOaj2huwV0sUjH63dDBti\nS7eD2+JzgwKBgQC4b06/oc5iiGU/ang7RyJVJPpKJo+kbCLnUqFXrWqWliqBBF4b\nwwrgXjcl5RMX2GhhsVVWgGE1v7yY6iWT6LElhYsa/4titxgmmv7xjb48lV6+I/Fx\nqHhsCQyj7Vxe9QUyyJ5PSKKZv+mJVtHLm1Z+CLddNvUTD1G9kOpBisugHwKBgHL1\nxlJ30b609kSo1DMVx9fJBPY8KRfRI6YchSdkZVwm/sc8SY2Qsj/UDq3p5lqr1++y\nOuKajpTy9PG5XlGc6fnN5aBe9R61zd+gWd+CODIun8wtucPdU5L0EZx9D/1BR52L\neV2UqcvKaq6cazrhlRTitreulcFFoRdOwJhMr0ajAoGAdx6QPQKBG4ewjKB38ZgA\nXp8DHaL39L2JKf6Qmu2cfanTEZezNx0HsbjcRVvkVxRiA6QnOjNktPn+aK2INK81\nPqzPRPcH3gQ0GNb3Ie9AgYuCRNuW9vVseVG5dfBzy7/UfOkJ/2wSOpPRiKIwiLdJ\nziJCIV3gQhuSDDJpltGUJ44=\n-----END RSA PRIVATE KEY-----\n"


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

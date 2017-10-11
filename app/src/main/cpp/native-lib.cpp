#include <jni.h>
#include <string>
#include "MyMD5.h"
#include "MyRSA.h"
#include "MyBASE64.h"
#include "Log.h"
#include <iostream>



extern "C" {
__attribute ((visibility ("default")))
JNIEXPORT jstring JNICALL
Java_com_ethan_encryptdemo_jni_stringFromJNI(JNIEnv *env, jobject /*this*/) {

    // TODO
    std::string hello="hello Ethan";

    return env->NewStringUTF(hello.c_str());
}

/**
 * MD5加密算法
 */
__attribute ((visibility ("default")))
JNIEXPORT jstring JNICALL
Java_com_ethan_encryptdemo_jni_MD5(JNIEnv *env, jobject instance, jstring msg_) {
    const char *msg = env->GetStringUTFChars(msg_, 0);

    std::string msgC;
    msgC.assign(msg);

    std::string f = MyMD5::encryptMD5(msgC);

    env->ReleaseStringUTFChars(msg_, msg);

    return env->NewStringUTF(f.c_str());
}
/**
 * RSA公钥加密
 * */
__attribute ((visibility ("default")))
JNIEXPORT jstring JNICALL
Java_com_ethan_encryptdemo_jni_encryptRSAbyPublicKey(JNIEnv *env, jobject instance, jstring msg_) {
    const char *msg = env->GetStringUTFChars(msg_, 0);

    std::string msgC;
    msgC.assign(msg);

    std::string rsa = MyRSA::encryptRSAbyPublickey(msgC, NULL);

    std::string base64 = MyBASE64::base64_encodestring(rsa);

    env->ReleaseStringUTFChars(msg_, msg);

    return env->NewStringUTF(base64.c_str());
}

/**
 * RSA公钥解密
 * */
__attribute ((visibility ("default")))
JNIEXPORT jstring JNICALL
Java_com_ethan_encryptdemo_jni_decryptRSAbyPublicKey(JNIEnv *env, jobject instance, jstring msg_) {
    const char *msg = env->GetStringUTFChars(msg_, 0);

    std::string msgC;
    msgC.assign(msg);

    std::string base64 = MyBASE64::base64_decodestring(msgC);
    std::string rsa = MyRSA::decryptRSAbyPublicKey(base64);

    env->ReleaseStringUTFChars(msg_, msg);

    return env->NewStringUTF(rsa.c_str());
}

/**
 * RSA私钥加密
 * */
__attribute ((visibility ("default")))
JNIEXPORT jstring JNICALL
Java_com_ethan_encryptdemo_jni_encryptRSAbyPrivateKey(JNIEnv *env, jobject instance, jstring msg_) {
    const char *msg = env->GetStringUTFChars(msg_, 0);

    std::string msgC;
    msgC.assign(msg);

    std::string rsa=MyRSA::encryptRSAbyPrivateKey(msgC,NULL);
    std::string base64=MyBASE64::base64_encodestring(rsa);

    env->ReleaseStringUTFChars(msg_, msg);

    return env->NewStringUTF(base64.c_str());
}
/**
 * RSA私钥解密
 * */
__attribute ((visibility ("default")))
JNIEXPORT jstring JNICALL
Java_com_ethan_encryptdemo_jni_decryptRSAbyPrivateKey(JNIEnv *env, jobject instance, jstring msg_) {
    const char *msg = env->GetStringUTFChars(msg_, 0);

    std::string msgC;
    msgC.assign(msg);

    std::string base64=MyBASE64::base64_decodestring(msgC);
    std::string rsa=MyRSA::decryptRSAbyPrivateKey(base64);

    env->ReleaseStringUTFChars(msg_, msg);

    return env->NewStringUTF(rsa.c_str());
}
}





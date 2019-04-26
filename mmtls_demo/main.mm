//
//  main.cpp
//  mmtls_demo
//
//  Created by lidawen on 2019/4/23.
//  Copyright © 2019 top.dawenhing. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/SecRandom.h>

#include <stdio.h>
#include <string>
#include <vector>

extern "C" {
    #include "uECC.h"
    #include "openssl/hmac.h"
//    #include "openssl/kdf.h"
    // micro-ecc依赖的随机数生成算法
    static int iOS_RNG(uint8_t *dest, unsigned size) {
        return SecRandomCopyBytes(kSecRandomDefault, size, dest) == 0 ? 1 : 0;
    }
}

#define HMAC_OUT_LEN 32

/**
 使用openssl的加密库计算hmac，使用sha265哈希算法

 @param key 初始化的key
 @param key_length key长度
 @param input 输入的数据
 @param input_length 输入数据的长度
 @param output 输出，外部预分配长度`HMAC_OUT_LEN`
 @return 1 - 成功， 0 - 失败
 */
int openssl_hmac_sha256(const uint8_t *key, size_t key_length, const uint8_t *input, size_t input_length, uint8_t *output) {
    assert(key != NULL);
    assert(input != NULL);
    
    const EVP_MD *md = EVP_sha256();
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    if (!HMAC_Init_ex(&ctx, key, (int)key_length, md, NULL)) {
        HMAC_CTX_cleanup(&ctx);
        return 0;
    }
    
    if (!HMAC_Update(&ctx, input, input_length)) {
        HMAC_CTX_cleanup(&ctx);
        return 0;
    }
    
    unsigned int out_len;
    if (!HMAC_Final(&ctx, output, &out_len)) {
        HMAC_CTX_cleanup(&ctx);
        return 0;
    }
    assert(out_len == HMAC_OUT_LEN);
    HMAC_CTX_cleanup(&ctx);
    return 1;
}

#define PUB_SIZE 64
#define PRI_SIZE 32
#define SEC_SIZE 32

struct client_data {
    // 密钥对
    uint8_t pri_key[PRI_SIZE];
    uint8_t pub_key[PUB_SIZE];
    
    // 共享密钥
    uint8_t sec_key[SEC_SIZE];

    // 服务器的公钥
    uint8_t svr_pub_key[PUB_SIZE];

    // 验证服务器签名的公钥
    uint8_t verify_key[PUB_SIZE];
    
    // 校验签名数据，大小是私钥的大小*2
    uint8_t sign_data[PRI_SIZE * 2];
    
    uint8_t ticket[SEC_SIZE]; //?? sec_key对称加密的结果，大小是多少？？
    
    // PSK协商过程中的客户端随机数
    uint8_t psk_client_random[SEC_SIZE];
    // PSK协商过程中的服务端随机数
    uint8_t psk_server_random[SEC_SIZE];
    
    // PSK校验值
    uint8_t psk_server_mac[HMAC_OUT_LEN];
};

struct server_data {
    uint8_t pri_key[PRI_SIZE];
    uint8_t pub_key[PUB_SIZE];
    
    uint8_t sec_key[SEC_SIZE];
    
    // 客户端的公钥
    uint8_t cli_pub_key[PUB_SIZE];
    
    // 产生服务器校验签名的私钥
    uint8_t sign_key[PRI_SIZE];
    
    // ticket的密钥，服务器私密保存
    uint8_t ticket_key;
    
    // PSK协商过程中的客户端随机数
    uint8_t psk_client_random[SEC_SIZE];
    // PSK协商过程中的服务端随机数
    uint8_t psk_server_random[SEC_SIZE];
};

void show_key_size() {
    printf("uECC_secp160r1 public key size:%d, private key size:%d\n",
           uECC_curve_public_key_size(uECC_secp160r1()),
           uECC_curve_private_key_size(uECC_secp160r1()));
    printf("uECC_secp192r1 public key size:%d, private key size:%d\n",
           uECC_curve_public_key_size(uECC_secp192r1()),
           uECC_curve_private_key_size(uECC_secp192r1()));
    printf("uECC_secp224r1 public key size:%d, private key size:%d\n",
           uECC_curve_public_key_size(uECC_secp224r1()),
           uECC_curve_private_key_size(uECC_secp224r1()));
    printf("uECC_secp256r1 public key size:%d, private key size:%d\n",
           uECC_curve_public_key_size(uECC_secp256r1()),
           uECC_curve_private_key_size(uECC_secp256r1()));
    printf("uECC_secp256k1 public key size:%d, private key size:%d\n",
           uECC_curve_public_key_size(uECC_secp256k1()),
           uECC_curve_private_key_size(uECC_secp256k1()));
}

// 简单的异或对称加密算法
void simple_xor(uint8_t *input, size_t len, uint8_t key, uint8_t *output) {
    for(int i=0; i<len; i++) {
        output[i] = input[i] ^ key;
    }
}

// mmtls 1-RTT ECDH
int ECDHE_1_RTT(struct client_data* client, struct server_data* server) {
    uECC_Curve curve = uECC_secp256r1();
    
    // 预先创建签名的钥匙对，verify_key内置在APP端
    if (!uECC_make_key(client->verify_key, server->sign_key, curve)) {
        printf("make signature key failed\n");
        return 0;
    }
    
    // 客户端发起连接之前，创建交换钥匙对（每个连接一对还是全局一对？）
    if (!uECC_make_key(client->pub_key, client->pri_key, curve)) {
        printf("make client keys failed\n");
        return 0;
    }
    
    // 客户端发送cli_pub_key给服务器
    memcpy(server->cli_pub_key, client->pub_key, PUB_SIZE);
    
    // 服务器产生钥匙对（每个连接一对还是全局一对？
    if (!uECC_make_key(server->pub_key, server->pri_key, curve)) {
        printf("make server keys failed\n");
        return 0;
    }
    
    // 服务器产生签名数据
    uint8_t sign[PRI_SIZE * 2] = {0};
    if (!uECC_sign(server->sign_key, server->pub_key, PUB_SIZE, sign, curve)) {
        printf("server sign error\n");
        return 0;
    }
    // 服务器自己产生出共享密钥
    if (!uECC_shared_secret(server->cli_pub_key, server->pri_key, server->sec_key, curve)) {
        printf("calc shared secret key failed\n");
        return 0;
    }
    server->ticket_key = 0x19;
    
    uint8_t ticket_key[SEC_SIZE];
    simple_xor(server->sec_key, SEC_SIZE, server->ticket_key, ticket_key);
    
    // 服务器把svr_pub_key,ticket, sign发送给客户端
    memcpy(client->svr_pub_key, server->pub_key, PUB_SIZE);
    memcpy(client->sign_data, sign, sizeof(sign));
    memcpy(client->ticket, ticket_key, SEC_SIZE);
    
    // 客户端校验
    if (!uECC_verify(client->verify_key, client->svr_pub_key, PUB_SIZE, client->sign_data, curve)) {
        printf("client verify failed\n");
        return 0;
    }
    
    if (!uECC_shared_secret(client->svr_pub_key, client->pri_key, client->sec_key, curve)) {
        printf("calc shared secret key failed\n");
        return 0;
    }
    
    if (memcmp(client->sec_key, server->sec_key, SEC_SIZE) != 0) {
        printf("client/server shared secret key not identical\n");
    }

    printf("%s passed.\n", __FUNCTION__);
    return 1;
}

int PSK_1_RTT(struct client_data* client, struct server_data* server) {
    ECDHE_1_RTT(client, server);
    
    // 客户端产生随机数
    iOS_RNG(client->psk_client_random, SEC_SIZE);
    
    // 发送客户端随机数，ticket给服务器
    memcpy(server->psk_client_random, client->psk_client_random, SEC_SIZE);
    uint8_t ticket[SEC_SIZE];
    memcpy(ticket, client->ticket, SEC_SIZE);
    
    // 服务器使用自己的ticket_key解密得到共享密钥
    uint8_t decoded_sec_key[SEC_SIZE];
    simple_xor(ticket, SEC_SIZE, server->ticket_key, decoded_sec_key);
    
    // decoded_sec_key应该和server->sec_key一致的
    // 但是，通常情况下，服务器不会保存客户端的sec_key，因此需要用这个办法拿到客户端sec_key
    if (memcmp(decoded_sec_key, server->sec_key, SEC_SIZE) != 0) {
        printf("server sec_key not equal to client\n");
        return 0;
    }
    
    // 服务器产生服务器的随机数
    iOS_RNG(server->psk_server_random, SEC_SIZE);
    uint8_t hash_data[SEC_SIZE * 2];
    memcpy(hash_data, server->psk_client_random, SEC_SIZE);
    memcpy(hash_data+SEC_SIZE, server->psk_server_random, SEC_SIZE);
    
    uint8_t MAC[HMAC_OUT_LEN];
    openssl_hmac_sha256(decoded_sec_key, SEC_SIZE, hash_data, SEC_SIZE * 2, MAC);
    
    // 服务器发送server_random和MAC给客户端
    memcpy(client->psk_server_random, server->psk_server_random, SEC_SIZE);
    memcpy(client->psk_server_mac, MAC, sizeof(MAC));
    
    // 客户端做验证
    uint8_t client_hash_data[SEC_SIZE * 2];
    memcpy(client_hash_data, client->psk_client_random, SEC_SIZE);
    memcpy(client_hash_data + SEC_SIZE, server->psk_server_random, SEC_SIZE);

    uint8_t verifyMAC[HMAC_OUT_LEN];
    openssl_hmac_sha256(client->sec_key, SEC_SIZE, client_hash_data, SEC_SIZE * 2, verifyMAC);
    if (memcmp(client->psk_server_mac, verifyMAC, sizeof(verifyMAC)) != 0) {
        printf("client verify MAC failed\n");
        return 0;
    }
    
    printf("%s passed.\n", __FUNCTION__);
    return 1;
}

/**
 密钥衍生算法
 HKDF协议的RFC：http://www.rfc-editor.org/rfc/rfc5869.txt
 @param skm 初始密钥
 @param skm_length 初始密钥长度
 @param info 上下文信息
 @param info_length 信息长度
 @param salt 盐，可选
 @param salt_length 盐的长度，如果salt==NULL, 长度也必须写成0
 @param out_length 希望的输出长度
 @param output 计算结果，预先分片至少out_length大小的空间
 @return 1 - 成功，- 失败
 */
int HKDF_Expand(const uint8_t *skm, size_t skm_length,
                const uint8_t *info, size_t info_length,
                const uint8_t *salt, size_t salt_length,
                size_t out_length,
                uint8_t *output) {

    assert(skm != NULL);
    
    // 先用sec_key扩充到固定长度
    uint8_t prk[HMAC_OUT_LEN];
    if (!openssl_hmac_sha256(salt ? salt : (uint8_t *)"", salt_length, skm, skm_length, prk)) {
        return 0;
    }
    
    int iterations = (int)ceil((double)out_length/(double)HMAC_OUT_LEN);
    
    const EVP_MD *md = EVP_sha256();
    size_t done_length = 0;
    uint8_t step_result[HMAC_OUT_LEN];
    for (int i=0; i<iterations; i++) {
        assert(done_length < out_length);
        
        HMAC_CTX ctx;
        HMAC_CTX_init(&ctx);
        HMAC_Init_ex(&ctx, &prk[0], sizeof(prk), md, NULL);
        if (i != 0) {
            HMAC_Update(&ctx, step_result, HMAC_OUT_LEN);
        }
        if (info != NULL) {
            HMAC_Update(&ctx, info, info_length);
        }
        unsigned char c = i+1;
        HMAC_Update(&ctx, &c, 1);
        
        unsigned int out_len;
        HMAC_Final(&ctx, step_result, &out_len);
        assert(out_len == HMAC_OUT_LEN);
        
        // 检查超过out_length长度的情况
        size_t copy_length = out_length - done_length;
        if (copy_length > HMAC_OUT_LEN) {
            copy_length = HMAC_OUT_LEN;
        }
        memcpy(output + done_length, step_result, copy_length);
        HMAC_CTX_cleanup(&ctx);

        done_length += out_len;
    }
    return 1;
}

std::vector<uint8_t> string_to_data(const std::string &str) {
    assert(str.size() % 2 == 0);
    std::vector<uint8_t> result;
    result.resize(str.size()/2);
    
    char byte_chars[3] = {0};
    for(size_t i=0; i<result.size(); i++) {
        byte_chars[0] = str.at(i*2);
        byte_chars[1] = str.at(i*2+1);
        result[i] = (uint8_t)strtol(byte_chars, NULL, 16);
    }
    return result;
}

// 密钥的扩展和衍生
int HKDF_Test1() {
    std::vector<uint8_t> IKM   = string_to_data("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    std::vector<uint8_t> salt  = string_to_data("000102030405060708090a0b0c");
    std::vector<uint8_t> info  = string_to_data("f0f1f2f3f4f5f6f7f8f9");
    int len           = 42;
    
    std::vector<uint8_t> OKM  = string_to_data("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    std::vector<uint8_t> output;
    output.resize(len);
    
    HKDF_Expand(&IKM[0], IKM.size(), &info[0], info.size(), &salt[0], salt.size(), len, &output[0]);
    assert(output == OKM);
    return 1;
}

int HKDF_Test2() {
    std::vector<uint8_t> IKM = string_to_data("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
    std::vector<uint8_t> salt = string_to_data("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    std::vector<uint8_t> info = string_to_data("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    int len = 82;
    
    std::vector<uint8_t> OKM = string_to_data("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
    
    std::vector<uint8_t> output;
    output.resize(len);
    
    HKDF_Expand(&IKM[0], IKM.size(), &info[0], info.size(), &salt[0], salt.size(), len, &output[0]);
    assert(output == OKM);

    return 1;
}

int HKDF_Test3() {
    std::vector<uint8_t> IKM   = string_to_data("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    std::vector<uint8_t> salt    = string_to_data("");
    std::vector<uint8_t> info    = string_to_data("");
    int len           = 42;
    
    std::vector<uint8_t> OKM  = string_to_data("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    
    std::vector<uint8_t> output;
    output.resize(len);
    
    HKDF_Expand(&IKM[0], IKM.size(), &info[0], info.size(), &salt[0], salt.size(), len, &output[0]);
    assert(output == OKM);
    return 1;
}

// 模拟微信mmtls密钥交互协议，网络数据交换使用memcpy替代
int main(int argc, const char * argv[]) {
    printf("start\n");
    
    uECC_set_rng(iOS_RNG);
    
    struct client_data client = {0};
    struct server_data server = {0};

    PSK_1_RTT(&client, &server);
    
    HKDF_Test1();
    HKDF_Test2();
    HKDF_Test3();

    return 0;
}

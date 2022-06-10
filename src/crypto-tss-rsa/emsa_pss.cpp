/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */

#include <cstring>
#include <iostream>
#include "crypto-bn/bn.h"
#include "crypto-bn/rand.h"
#include <openssl/sha.h>
#include "emsa_pss.h"


namespace safeheron {
    namespace tss_rsa {

        bool MGF1(uint8_t* seed, int seedLen, uint8_t* dbMask, int maskLen) {
            SHA256_CTX ctx;
            int hLen = SHA256_DIGEST_LENGTH;
            uint8_t cnt[4];
            uint8_t out[maskLen+hLen];
            for(int i = 0; i <= (maskLen + hLen -1) / hLen -1; i++) {
                cnt[0] = (unsigned char)((i >> 24) & 255);
                cnt[1] = (unsigned char)((i >> 16) & 255);
                cnt[2] = (unsigned char)((i >> 8)) & 255;
                cnt[3] = (unsigned char)(i & 255);
                SHA256_Init(&ctx);
                SHA256_Update(&ctx,seed, seedLen);
                SHA256_Update(&ctx, cnt, 4);
                SHA256_Final(out + i*hLen, &ctx);
            }
            memcpy(dbMask, out, maskLen);
            return true;
        }


        std::string EncodeEMSA_PSS(const std::string& m, int keyBits, SaltLength saltLength) {
            int emBits = keyBits - 1;

            int emLen = (emBits + 7) / 8;
            int hLen = SHA256_DIGEST_LENGTH;

            int sLen;
            switch (saltLength) {
                case SaltLength::AutoLength: sLen = emLen - 2 - hLen;
                    break;
                case SaltLength::EqualToHash: sLen = hLen;
                    break;
                default: sLen = emLen - 2 - hLen;
            }

            if(emLen < hLen + sLen + 2 || sLen < 0) {
                std::cerr << "emLen error: KeyBitLength is too short." << std::endl;
                exit(EXIT_FAILURE);
            }

            size_t mm_len = m.length();
            const uint8_t* mm = reinterpret_cast<const uint8_t *>(m.c_str());
            uint8_t mm_digest[hLen];
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, mm, mm_len);
            SHA256_Final(mm_digest, &ctx);

            uint8_t salt[sLen];
            safeheron::rand::RandomBytes(salt, (size_t)sLen);

            uint8_t padding1[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

            uint8_t M[8+sLen+hLen];
            memcpy(M, padding1, 8);
            memcpy(M+8, mm_digest, hLen);
            memcpy(M+(8+hLen), salt, sLen);

            uint8_t H[hLen];
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, M, sizeof(M));
            SHA256_Final(H, &ctx);


            uint8_t DB[emLen - hLen - 1];
            int PSLen = emLen - hLen - sLen - 2;
            uint8_t PS[PSLen];
            memset(PS, 0x00, PSLen);

            uint8_t left_padding[1] = {0x01};

            memcpy(DB, PS, PSLen);
            memcpy(DB + PSLen, left_padding, 1);
            memcpy(DB + PSLen +1, salt, sLen);


            uint8_t dbMask[emLen - hLen - 1];

            MGF1(H, hLen, dbMask, sizeof(dbMask));

            uint8_t maskedDB[emLen - hLen - 1];
            for(int i = 0; i < emLen - hLen - 1; i++) {
                maskedDB[i] = DB[i] ^ dbMask[i];
            }

            uint8_t c = 255;
            for(int i = 0; i < emLen * 8 -emBits; i++) {
                c = c >> 1;
            }
            maskedDB[0] &= c;

            uint8_t EM[emLen];
            uint8_t rightmost[1] = {0xbc};
            memcpy(EM, maskedDB, emLen - hLen - 1);
            memcpy(EM + (emLen - hLen - 1), H, hLen);
            memcpy(EM + (emLen - hLen - 1 + hLen), rightmost, 1);
            std::string em(reinterpret_cast<const char *>(EM), emLen);
            return em;
        }

        bool VerifyEMSA_PSS(const std::string& m, int keyBits, SaltLength saltLength, const std::string& em) {
            int emBits = keyBits - 1;
            int emLen = (emBits + 7) / 8;
            uint8_t* EM = (unsigned char*)em.c_str();
            int EMLen = em.length();
            if(EMLen != emLen) {
                std::cerr << "inconsistent " << std::endl;
                return false;
            }

            int sLen;
            int hLen = SHA256_DIGEST_LENGTH;
            switch (saltLength) {
                case SaltLength::AutoLength: sLen = emLen - 2 - hLen;
                    break;
                case SaltLength::EqualToHash: sLen = hLen;
                    break;
                default: sLen = emLen - 2 - hLen;
            }

            if(emLen < hLen + sLen + 2 || sLen < 0) {
                std::cerr << "emLen error: KeyBitLength is too short." << std::endl;
                return false;
            }

            uint8_t rightmostVerify[1];
            memcpy(rightmostVerify, EM + (EMLen - 1), 1);
            if(rightmostVerify[0] != (unsigned char)0xbc) {
                std::cerr << "inconsistent " << std::endl;
                return false;
            }

            uint8_t expectedH[hLen];
            uint8_t maskedDB[emLen - hLen - 1];
            memcpy(maskedDB, EM, emLen - hLen - 1);
            memcpy(expectedH, EM+(emLen - hLen - 1), hLen);

            uint8_t c = 255;
            for(int i = 0; i < 8 - (emLen * 8 -emBits); i++) {
                c = c << 1;
            }
            uint8_t leftmost = maskedDB[0];
            if((leftmost & c) != 0x00) {
                std::cerr << "inconsistent " << std::endl;
                return false;
            }

            uint8_t dbMask[emLen - hLen - 1];
            MGF1(expectedH, hLen, dbMask, sizeof(dbMask));

            uint8_t DB[emLen - hLen - 1];
            for(int i = 0; i < emLen - hLen - 1; i++) {
                DB[i] = maskedDB[i] ^ dbMask[i];
            }

            c = 255;
            for(int i = 0; i < emLen * 8 -emBits; i++) {
                c = c >> 1;
            }
            DB[0] &= c;

            if(emLen - hLen - sLen - 2 > 0) {
                int PS_len = emLen - hLen - sLen - 2;
                uint8_t PS[PS_len];
                memcpy(PS, DB, PS_len);
                for(int i = 0; i < PS_len; i++) {
                    if(PS[i] != 0x00) {
                        std::cerr << "inconsistent " << std::endl;
                        return false;
                    }
                }
            }

            uint8_t left_padding[1];
            memcpy(left_padding, DB + (emLen - hLen - sLen - 2), 1);
            if(left_padding[0] != (unsigned char)0x01) {
                std::cerr << "inconsistent " << std::endl;
                return false;
            }

            uint8_t padding1[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

            uint8_t salt[sLen];
            memcpy(salt, DB+(emLen - hLen - 1 - sLen), sLen);

            SHA256_CTX ctx;
            const uint8_t* mm = reinterpret_cast<const uint8_t *>(m.c_str());
            size_t mm_len = m.length();
            uint8_t mm_digest[hLen];
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, mm, mm_len);
            SHA256_Final(mm_digest, &ctx);

            uint8_t M[8+sLen+hLen];
            memcpy(M, padding1, 8);
            memcpy(M+8, mm_digest, hLen);
            memcpy(M+(8+hLen), salt, sLen);

            uint8_t H[hLen];
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, M, sizeof(M));
            SHA256_Final(H, &ctx);

            if(strncmp((char*)H, (char*)expectedH, hLen) == 0) {
                return true;
            } else {
                return false;
            }
        }

    }
}

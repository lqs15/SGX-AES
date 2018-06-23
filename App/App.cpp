/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


// App.cpp : Defines the entry point for the console application.
#include <stdio.h>
#include <map>
#include "../Enclave1/Enclave1_u.h"
#include "../Enclave2/Enclave2_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <getopt.h>
#include <string.h>


#define UNUSED(val) (void)(val)
#define TCHAR   char
#define _TCHAR  char
#define _T(str) str
#define scanf_s scanf
#define _tmain  main

extern std::map<sgx_enclave_id_t, uint32_t>g_enclave_id_map;


sgx_enclave_id_t e1_enclave_id = 0;
sgx_enclave_id_t e2_enclave_id = 0;
sgx_enclave_id_t e3_enclave_id = 0;

#define ENCLAVE1_PATH "libenclave1.so"
#define ENCLAVE2_PATH "libenclave2.so"

void waitForKeyPress()
{
    char ch;
    int temp;
    printf("\n\nHit a key....\n");
    temp = scanf_s("%c", &ch);
}

uint32_t load_enclaves()
{
    uint32_t enclave_temp_no;
    int ret, launch_token_updated;
    sgx_launch_token_t launch_token;

    enclave_temp_no = 0;

    ret = sgx_create_enclave(ENCLAVE1_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e1_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e1_enclave_id, enclave_temp_no));

    ret = sgx_create_enclave(ENCLAVE2_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e2_enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e2_enclave_id, enclave_temp_no));

    return SGX_SUCCESS;
}

void print(const char* str){
    printf("%s\n", str);
}

void print_num(uint32_t id){
    printf("%u\n", id);
}

void print_to_file(const char* file_path, const char* str){
    FILE* file = fopen(file_path, "w");
    fwrite(str,strlen(str),1,file);
    fclose(file);
}

struct globalArgs_t{
    uint8_t is_encrypt;
    char *key_path;
    char *mac_path;
    char *data_in_path;
    char *data_out_path;
} globalArgs;

static const char *optString = "edk:m:i:o:";

int _tmain(int argc, _TCHAR* argv[]){

    int opt = 0;

    globalArgs.is_encrypt = 1;
    globalArgs.key_path = "key.txt";
    globalArgs.mac_path = "mac.txt";
    globalArgs.data_in_path = "plain.txt";
    globalArgs.data_out_path = "cipher.txt";

    opt = getopt(argc, argv, optString);
    while (opt!=-1){
        switch(opt){
            case 'e':
                globalArgs.is_encrypt = 1;
                break;
            case 'd':
                globalArgs.is_encrypt = 0;
                break;
            case 'k':
                globalArgs.key_path = (char *)optarg;
                break;
            case 'm':
                globalArgs.mac_path = (char *)optarg;
                break;            
            case 'i':
                globalArgs.data_in_path = (char *)optarg;
                break;            
            case 'o':
                globalArgs.data_out_path = (char *)optarg;
                break;
            default:
                break;
        }
        opt = getopt(argc, argv, optString);
    }

    uint32_t ret_status;
    sgx_status_t status;

    uint8_t is_encrypt;

    if(load_enclaves() != SGX_SUCCESS){
        printf("Load Enclave Failure\n");
    }

    printf("Available Enclaves\n");
    printf("Enclave1 - EnclaveID %" PRIx64 "\n", e1_enclave_id);
    printf("Enclave2 - EnclaveID %" PRIx64 "\n", e2_enclave_id);

    const int KEY_DATA_LEN = 16;
    const int MAC_DATA_LEN = 16;
    char key[KEY_DATA_LEN], mac_data[MAC_DATA_LEN];
    char *plaintext, *ciphertext;
    uint32_t plaintext_len, ciphertext_len;

    // Read key from key.txt.
    FILE* key_file = fopen(globalArgs.key_path,"r");
    if (key_file == NULL){
        printf("Read key file failed!\n");
        return 1;
    }
    fread(key, KEY_DATA_LEN, 1, key_file); key[KEY_DATA_LEN] = 0;
    fclose(key_file);

    // Read plaintext from plaintext.txt.
    FILE* plain_file = fopen(globalArgs.data_in_path,"r");
    if (plain_file == NULL){
        printf("Read plaintext file failed!\n");
        return 1;
    }
    fseek(plain_file, 0, SEEK_END);
    plaintext_len = ftell(plain_file);
    rewind(plain_file);
    plaintext = (char *)malloc(sizeof(char) * (plaintext_len + 1));
    fread(plaintext, plaintext_len, 1, plain_file);
    fclose(plain_file);
    
    //initial ciphertext
    ciphertext = (char *)malloc(sizeof(char) * (1024 + 1));
    memset(ciphertext, 0, sizeof(ciphertext));
    ciphertext_len = 0;

    // Read mac_data from mac.txt.
    memset(mac_data, 0, sizeof(mac_data));
    if (globalArgs.is_encrypt == 0){
        FILE* mac_file = fopen(globalArgs.mac_path,"r");
        if (mac_file == NULL){
            printf("Read mac file failed!\n");
            return 1;
        }
        fread(mac_data, MAC_DATA_LEN, 1, mac_file); mac_data[MAC_DATA_LEN] = 0;
        fclose(mac_file);
    }
    
    

    // Create session between Enclave1(Source) and Enclave2(Destination)
    status = Enclave1_test_create_session(e1_enclave_id, &ret_status, e1_enclave_id, e2_enclave_id);
    if (status!=SGX_SUCCESS){
        printf("Enclave1_test_create_session Ecall failed: Error code is %x\n", status);
        return 1;
    }
    else {
        if(ret_status==0){
            printf("Secure Channel Establishment successful\n");
        }
        else{
            printf("Session establishment and key exchange failure between Source (E1) and Destination (E2): Error code is %x\n", ret_status);
            return 1;
        }
    }
    
    // printf("\nfinishA\n");
    // Call Encrypt function of Enclave2
    status = Enclave1_test_call_aes(e1_enclave_id, &ret_status, 
                                        e1_enclave_id, e2_enclave_id, key, mac_data,
                                        plaintext, &plaintext_len, ciphertext, &ciphertext_len, globalArgs.is_encrypt);
    if (status!=SGX_SUCCESS){
        printf("Enclave1_test_enclave_to_enclave_call Ecall failed: Error code is %x\n", status);
        return 1;
    }
    else{
        if(ret_status==0){
            printf("Enclave call successful\n");
        }
        else{
            printf("Enclave to Enclave Call failure between Source (E1) and Destination (E2): Error code is %x\n", ret_status);
            return 1;
        }
    }

    // write ciphertext to file
    FILE* cipher_file = fopen(globalArgs.data_out_path, "w");
    if (cipher_file == NULL){
        printf("Open plaintext file failed!\n");
        return 1;
    }
    fwrite(ciphertext, ciphertext_len, 1, cipher_file);
    fclose(cipher_file);

    // write mac_data to file
    FILE* mac_out_file = fopen(globalArgs.mac_path, "w");
    if (mac_out_file == NULL){
        printf("Open plaintext file failed!\n");
        return 1;
    }
    fwrite(mac_data, MAC_DATA_LEN, 1, mac_out_file);
    fclose(mac_out_file);

    sgx_destroy_enclave(e1_enclave_id);
    sgx_destroy_enclave(e2_enclave_id);

    // waitForKeyPress();
    return 0;
}

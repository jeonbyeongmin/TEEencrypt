/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>

int root_key;							// 1~25 중 하나의 숫자, 랜덤키를 암호화하기 위해 사용
int random_number[10] = {0,};			// 랜덤 숫자
int random_key[1] = {0};				// 랜덤키
char dec_random_key[2] = {0,0};			// 복호화된 랜덤키

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}


static TEE_Result enc_value(uint32_t param_types,
   TEE_Param params[4])
{
	// 랜덤 키로 평문 암호화 하는 함수

    char * in = (char *)params[0].memref.buffer;
    int in_len = strlen (params[0].memref.buffer);
    char encrypted [64]={0,};

    DMSG("========================Encryption========================\n");
    DMSG ("Plaintext :  %s", in);
    memcpy(encrypted, in, in_len);

    for(int i = 0; i < in_len; i++){
    	if(encrypted[i]>='a' && encrypted[i] <='z'){
        	encrypted[i] -= 'a';
        	encrypted[i] += random_key[0];
        	encrypted[i] = encrypted[i] % 26;
        	encrypted[i] += 'a';
    	}
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
        	encrypted[i] -= 'A';
        	encrypted[i] += random_key[0];
        	encrypted[i] = encrypted[i] % 26;
        	encrypted[i] += 'A';
    	}
	}

    DMSG ("Ciphertext :  %s", encrypted);
    memcpy(in, encrypted, in_len);

    return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types,
   TEE_Param params[4])
{
	// 랜덤 키로 암호화된 문장을 복호화하는 함수
	// 이 시점에서 랜덤 키는 복호화되어 dec_random_key에 저장되어 있어야 한다.

    char * in = (char *)params[0].memref.buffer;
    int in_len = strlen (params[0].memref.buffer);
    char decrypted [64]={0,};

    DMSG("========================Decryption========================\n");
    DMSG ("Ciphertext :  %s", in);
    memcpy(decrypted, in, in_len);

    for(int i=0; i<in_len;i++){
    	if(decrypted[i]>='a' && decrypted[i] <='z'){
        	decrypted[i] -= 'a';
        	decrypted[i] -= dec_random_key[0];
        	decrypted[i] += 26;
        	decrypted[i] = decrypted[i] % 26;
        	decrypted[i] += 'a';
    	}
    	else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
        	decrypted[i] -= 'A';
        	decrypted[i] -= dec_random_key[0];
        	decrypted[i] += 26;
        	decrypted[i] = decrypted[i] % 26;
        	decrypted[i] += 'A';
    	}
	}

	DMSG ("Plaintext :  %s", decrypted);
	memcpy(in, decrypted, in_len);

	return TEE_SUCCESS;
}

static TEE_Result randomkey_get()
{
	// 랜덤키를 생성하는 함수 - 파일마다 다른 키를 사용해 한 키값이 유출되어도 다른 파일의 키값들은 유출되지 않음
	// 랜덤 숫자가 0 이상이 나올 때까지 재생성해준다.
	while(random_number[0] <= 0){
		TEE_GenerateRandom(random_number, sizeof(random_number));
	}

	// 랜덤 숫자를 기반으로 랜덤키를 만들어주기 위해서 25나누고 1을 더해서 1~25의 값을 만들어준다.
	random_key[0] = random_number[0] % 25 + 1;
	
	DMSG("=====================Get Random Key=====================\n");
	DMSG ("random key is :  %d", random_key[0]);

	return TEE_SUCCESS;
}


static TEE_Result randomkey_enc(uint32_t param_types,
	TEE_Param params[4])
{
	// 루트 키를 이용하여 랜덤키를 암호화하는 함수

	char * in = (char *)params[0].memref.buffer;

	char enc_random_key [1]={0};

	DMSG("===================Encryption Random Key===================\n");
	DMSG ("root key is :  %d", root_key);
	DMSG ("random key is :  %d", random_key[0]);

	enc_random_key[0] = 'A' + random_key[0];

	if (enc_random_key[0] >= 'A' && enc_random_key[0] <= 'Z') {
		enc_random_key[0] -= 'A';
		enc_random_key[0] += root_key;
		enc_random_key[0] = enc_random_key[0] % 26;
		enc_random_key[0] += 'A';
	}

	DMSG("encrypted is : %c\n", enc_random_key[0]);
	memcpy(in, enc_random_key, 1);

	return TEE_SUCCESS;
}

static TEE_Result randomkey_dec(uint32_t param_types,
	TEE_Param params[4])
{
	// 루트 키를 이용하여 랜덤키를 복호화하는 함수

	char * in = (char *)params[0].memref.buffer;
	memcpy(dec_random_key, in, 1);

	DMSG("===================Decryption Random Key===================\n");

	if (dec_random_key[0] >= 'A' && dec_random_key[0] <= 'Z') {
		dec_random_key[0] -= 'A';
		dec_random_key[0] -= root_key;
		dec_random_key[0] += 26;
		dec_random_key[0] = dec_random_key[0] % 26;
	}
	
	return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	root_key = 10;

	switch (cmd_id) {
		case TA_TEEencrypt_CMD_ENC_VALUE:
			return enc_value(param_types, params);
		case TA_TEEencrypt_CMD_DEC_VALUE:
			return dec_value(param_types, params);
		case TA_TEEencrypt_CMD_RANDOMKEY_GET:
			return randomkey_get();
		case TA_TEEencrypt_CMD_RANDOMKEY_ENC:
			return randomkey_enc(param_types, params);
		case TA_TEEencrypt_CMD_RANDOMKEY_DEC:
			return randomkey_dec(param_types, params);
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}

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

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len = 64;

	char encKey[1] = {0};
	char decKey[2] = {0,0};
	

	// TEE와 CA의 논리적인 연결인 Context 생성
	res = TEEC_InitializeContext(NULL, &ctx);

	// UUID로 특정된 TA와 CA를 연결하여 Session 생성
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	// init
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	// when first params is '-e'
	if (strcmp(argv[1],"-e") == 0) {
		printf("========================Encryption========================\n");
		
		// CA에서 평문 텍스트 파일 읽기, TA 호출
		FILE *fp_plaintext = fopen(argv[2], "r");
		fgets(plaintext, sizeof(plaintext), fp_plaintext);
		fclose(fp_plaintext);
		memcpy(op.params[0].tmpref.buffer, plaintext, len);

		// 세션으로 연결된 TA의 랜덤키 생성, 시저 암호화 함수 요청
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
					 &err_origin);

		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
					 &err_origin);

		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);


		// 암호화된 텍스트 ciphertext로 copy & 파일로 작성
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("Ciphertext : %s\n", ciphertext);

		FILE *fp_ciphertext_enckey = fopen("ciphertext.txt","w");
		fputs(ciphertext, fp_ciphertext_enckey);

		// 랜덤키 암호화를 위해 랜덤키 암호화 함수 실행 요청
		memcpy(op.params[0].tmpref.buffer, encKey, 1);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op,
					 &err_origin);
		
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		// 암호화된 키 텍스트 파일에 저장
		memcpy(encKey, op.params[0].tmpref.buffer, 1);
		fputc(encKey[0], fp_ciphertext_enckey);

		fclose(fp_ciphertext_enckey);
	} 
	// when first params is '-d'
	else if (strcmp(argv[1],"-d") == 0) {
		printf("========================Decryption========================\n");

		// 파일에서 암호화된 문장, 암호화된 키 가져오기
		FILE *fp_ciphertext_enckey = fopen(argv[2], "r");
		fgets(ciphertext, sizeof(ciphertext), fp_ciphertext_enckey);
		fgets(decKey, sizeof(decKey), fp_ciphertext_enckey);
		fclose(fp_ciphertext_enckey);

		printf("Ciphertext : %s\n", ciphertext);

		// 암호화된 키로 복호화 키 생성하기 위해 TA에 요청
		memcpy(op.params[0].tmpref.buffer, decKey, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op,
					 &err_origin);

		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		// 복호화된 랜덤 키를 이용하여 암호문을 복호화하기 위해 TA에 요청
		memcpy(decKey, op.params[0].tmpref.buffer, 1);
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
					 &err_origin);

		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("Plaintext : %s\n", plaintext);

		FILE *fp_plaintext = fopen("plaintext.txt","w");
		fputs(plaintext, fp_plaintext);
		fclose(fp_plaintext);

	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}

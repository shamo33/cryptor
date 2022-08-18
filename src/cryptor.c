/**
 * 暗号化とか復号とか、そんなの (CryptK2-Frontend 0.1.4)
 * Written by parly 2015
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>


// コンパイルには、CryptK2 Library が必要です。
#include "cryptk2.h"


// エラー番号
#define ERROR_MALLOC_FAILED 1
#define ERROR_INVALID_ARGS 2
#define ERROR_INVALID_INFILE 3
#define ERROR_FAILED_TO_OPEN_KEYFILE 4
#define ERROR_FAILED_TO_OPEN_INFILE 5
#define ERROR_FAILED_TO_OPEN_OUTFILE 6
#define ERROR_INVALID_KEYFILE 7
#define ERROR_FAILED_TO_GENERATE_IV 8

// ファイルバッファーのサイズ
#define BUFFER_SIZE 512000


// モード
typedef enum { MODE_MAKEKEY, MODE_ENCRYPT, MODE_DECRYPT } cryptmode_t;



// 諸関数
static void generate_keyiv(uint8_t *buf);
static void make_keyfile(char *filename);
static void read_keyfile(char *filename, uint8_t *buf);
static void encrypt_file(char *src, char *dst, uint8_t *key);
static void decrypt_file(char *src, char *dst, uint8_t *key);


#ifdef FORWARD_MAIN
#  define main _entry
#endif


int main(int argc, char **argv) {
	cryptmode_t mode;
	uint8_t key[16];
	int correct_argc;

	// 引数が 2 個より少ない場合は処理を継続できない
	if (argc < 2) {
arg_error:
		fprintf(stderr,
			"usage:\n"
			"\tcryptk2 -m outfile\n"
			"\tcryptk2 -d keyfile infile outfile\n"
			"\tcryptk2 -e keyfile infile outfile\n"
		);
		return ERROR_INVALID_ARGS;
	}
	
	// モードは encrypt か decrypt か。
	if (!strcmp(argv[1], "-m") || !strcmp(argv[1], "/m")) {
		mode = MODE_MAKEKEY;
		correct_argc = 3;
	}
	else if (!strcmp(argv[1], "-e") || !strcmp(argv[1], "/e")) {
		mode = MODE_ENCRYPT;
		correct_argc = 5;
	}
	else if (!strcmp(argv[1], "-d") || !strcmp(argv[1], "/d")) {
		mode = MODE_DECRYPT;
		correct_argc = 5;
	}
	else {
		// 引数エラー
		goto arg_error;
	}

	// 引数の数をチェック
	if (argc != correct_argc) {
		// 引数エラー
		goto arg_error;
	}

	// モード別の処理
	if (mode == MODE_MAKEKEY) {
		// 鍵の作成
		make_keyfile(argv[2]);
	}
	else {
		// キーファイルを読み込む
		read_keyfile(argv[2], key);

		if (mode == MODE_ENCRYPT) {
			// 暗号化
			encrypt_file(argv[3], argv[4], key);
		}
		else {
			// 復号化
			decrypt_file(argv[3], argv[4], key);
		}
	}

	// 正常終了
	return 0;
}


// 16 バイトの暗号鍵 / IV をつくる (Windows 専用コード)
// POSIX 環境なら /dev/urandom から 16 バイト読みこめばいいと思います。
static void generate_keyiv(uint8_t *buf) {
	HCRYPTPROV hProv;
	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0) == FALSE || CryptGenRandom(hProv, 16, (BYTE *)buf) == FALSE) {
		fprintf(stderr, "error: failed to generate key\n");
		exit(ERROR_FAILED_TO_GENERATE_IV);
	}
	CryptReleaseContext(hProv, 0);
}


// キーファイルをつくる
static void make_keyfile(char *filename) {
	FILE *f;
	uint8_t key[16];

	// キーファイルを開く
	if ((f = fopen(filename, "wb")) == NULL) {
		fprintf(stderr, "error: failed to open outfile\n");
		exit(ERROR_FAILED_TO_OPEN_OUTFILE);
	}

	// キーの作成
	generate_keyiv(key);

	// キーファイルに書き込み
	fwrite(key, sizeof(uint8_t), 16, f);

	// キーファイルを閉じる
	fclose(f);
}


// キーファイルを読み込む
static void read_keyfile(char *filename, uint8_t *buf) {
	FILE *f;

	// キーファイルを開く
	if ((f = fopen(filename, "rb")) == NULL) {
		fprintf(stderr, "error: failed to open keyfile\n");
		exit(ERROR_FAILED_TO_OPEN_KEYFILE);
	}

	// キーファイルは 16 バイトでなければならない
	fseek(f, 0, SEEK_END);
	if (ftell(f) != 16) {
		fprintf(stderr, "error: invalid keyfile\n");
		fclose(f);
		exit(ERROR_INVALID_KEYFILE);
	}

	// キーファイルの読み込み
	fseek(f, 0, SEEK_SET);
	fread(buf, sizeof(uint8_t), 16, f);

	// キーファイルを閉じる
	fclose(f);
}


// ファイルを暗号化
static void encrypt_file(char *src, char *dst, uint8_t *key) {
	FILE *in=NULL, *out=NULL;
	unsigned int i, loop, last, err=0;
	fpos_t size;
	uint8_t iv[16], inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE];
	CRYPTK2 k2;

	// 入力元ファイルを開く
	if ((in = fopen(src, "rb")) == NULL) {
failed_infile:
		fprintf(stderr, "error: failed to open infile\n");
		err = ERROR_FAILED_TO_OPEN_INFILE;
		goto cleanup;
	}

	// 出力先ファイルを開く
	if ((out = fopen(dst, "wb")) == NULL) {
		fprintf(stderr, "error: failed to open outfile\n");
		err = ERROR_FAILED_TO_OPEN_OUTFILE;
		goto cleanup;
	}

	// 暗号化前のファイルサイズを取得
	fseek(in, 0, SEEK_END);
	if (fgetpos(in, &size)) {
		goto failed_infile;
	}

	// メインループの回数を計算
	loop = size / BUFFER_SIZE;

	// あまりのバイト数を計算
	last = size % BUFFER_SIZE;

	// 初期化ベクトルをつくる
	generate_keyiv(iv);
	fwrite(iv, sizeof(uint8_t), 16, out);

	// 暗号ライブラリー初期化
	k2 = new_cryptk2();
	cryptk2_setup(k2, key, iv);

	// 暗号化メインループ
	fseek(in, 0, SEEK_SET);
	for (i=1; i<=loop; ++i) {
		// ファイル in から暗号化前のデータを読み込み
		fread(inbuf, sizeof(uint8_t), BUFFER_SIZE, in);
		// 暗号化
		cryptk2_encrypt(k2, BUFFER_SIZE, inbuf, outbuf);
		// ファイル out へ暗号化後のデータを書き込み
		fwrite(outbuf, sizeof(uint8_t), BUFFER_SIZE, out);
		// パーセント表示
		fprintf(stderr, "\rencrypting (%3u %%) ...", i * 100 / loop);
	}

	// あまりのバイト列がある場合、処理
	if (last != 0) {
		// ファイル in から暗号化前のデータを読み込み
		fread(inbuf, sizeof(uint8_t), last, in);
		// 暗号化
		cryptk2_encrypt(k2, last, inbuf, outbuf);
		// ファイル out へ暗号化後のデータを書き込み
		fwrite(outbuf, sizeof(uint8_t), last, out);
	}

	// 暗号ライブラリーお掃除
	delete_cryptk2(k2);

	// 100 パーセント表示
	fprintf(stderr, "\rencrypting (100 %%) completed!\n");

cleanup:
	// ファイルを閉じる
	if (in != NULL) fclose(in);
	if (out != NULL) fclose(out);
	if (err) exit(err);
}


// ファイルを復号化
static void decrypt_file(char *src, char *dst, uint8_t *key) {
	FILE *in=NULL, *out=NULL;
	unsigned int i, loop, last, err=0;
	fpos_t size;
	uint8_t iv[16], inbuf[BUFFER_SIZE], outbuf[BUFFER_SIZE];
	CRYPTK2 k2;

	// 入力元ファイルを開く
	if ((in = fopen(src, "rb")) == NULL) {
failed_infile:
		fprintf(stderr, "error: failed to open infile\n");
		err = ERROR_FAILED_TO_OPEN_INFILE;
		goto cleanup;
	}

	// 暗号化されたファイルのファイルサイズを取得
	fseek(in, 0, SEEK_END);
	if (fgetpos(in, &size)) {
		goto failed_infile;
	}

	// 暗号化されたファイルのサイズは 16 バイト (初期化ベクトルのサイズ) 以上でないとおかしい
	if (size < 16) {
		fprintf(stderr, "error: invalid infile\n");
		err = ERROR_INVALID_INFILE;
		goto cleanup;
	}

	// サイズから初期化ベクトル分のサイズを引いておく
	size -= 16;

	// 出力先ファイルを開く
	if ((out = fopen(dst, "wb")) == NULL) {
		fprintf(stderr, "error: failed to open outfile\n");
		err = ERROR_FAILED_TO_OPEN_OUTFILE;
		goto cleanup;
	}

	// メインループの回数を計算
	loop = size / BUFFER_SIZE;

	// あまりのバイト数を計算
	last = size % BUFFER_SIZE;

	// 初期化ベクトルを読み込む
	fseek(in, 0, SEEK_SET);
	fread(iv, sizeof(uint8_t), 16, in);

	// 暗号ライブラリー初期化
	k2 = new_cryptk2();
	cryptk2_setup(k2, key, iv);

	// 暗号化メインループ
	for (i=1; i<=loop; ++i) {
		// ファイル in から復号化前のデータを読み込み
		fread(inbuf, sizeof(uint8_t), BUFFER_SIZE, in);
		// 復号化
		cryptk2_decrypt(k2, BUFFER_SIZE, inbuf, outbuf);
		// ファイル out へ復号化後のデータを書き込み
		fwrite(outbuf, sizeof(uint8_t), BUFFER_SIZE, out);
		// パーセント表示
		fprintf(stderr, "\rdecrypting (%3u %%) ...", i * 100 / loop);
	}

	// あまりのバイト列がある場合、処理
	if (last != 0) {
		// ファイル in から復号化前のデータを読み込み
		fread(inbuf, sizeof(uint8_t), last, in);
		// 復号化
		cryptk2_encrypt(k2, last, inbuf, outbuf);
		// ファイル out へ復号化後のデータを書き込み
		fwrite(outbuf, sizeof(uint8_t), last, out);
	}

	// 暗号ライブラリーお掃除
	delete_cryptk2(k2);

	// 100 パーセント表示
	fprintf(stderr, "\rdecrypting (100 %%) completed!\n");

cleanup:
	// ファイルを閉じる
	if (in != NULL) fclose(in);
	if (out != NULL) fclose(out);
	if (err) exit(err);
}

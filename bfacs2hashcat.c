#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#pragma pack (push, 0)
typedef struct bfacs_file_header {
	uint32_t magic;
	uint16_t header_size;
	uint16_t version;
	uint32_t datalen_lo;
	uint32_t datalen_hi;
	uint16_t iv_size;
	uint16_t block_size;
	uint8_t  salt[11];
	uint8_t  key_check[4];
} bfacs_file_header_t;
#pragma pack (pop)

#define BFACS_HEADER_SIZE 35
#define BFACS_HEADER_MAGIC 0x92190824

#define BFACS_BLOCK_SIZE_MAX 16

void parse_file(const char *filename)
{
	FILE *fp;
	bfacs_file_header_t header;
	uint8_t iv[BFACS_BLOCK_SIZE_MAX], block[BFACS_BLOCK_SIZE_MAX];
	int rv;

	fp = fopen(filename, "r");

	if (fp == NULL) {
		fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
		return;
	}

    rv = fread(&header, 1, BFACS_HEADER_SIZE, fp);
	if (rv < 0) {
		fprintf(stderr, "Failed to read file header from %s: %s\n", filename, strerror(errno));
		return;
	} else if (rv < BFACS_HEADER_SIZE) {
		fprintf(stderr, "Short read while trying to read file header from %s\n", filename);
		return;
	}

	if (header.magic != BFACS_HEADER_MAGIC) {
		fprintf(stderr, "%s is not a BFACS file, incorrect magic.  Expected 0x%08x, got 0x%08x\n", filename, BFACS_HEADER_MAGIC, header.magic);
		return;
	}

	if (header.version >> 8 != 1) {
		fprintf(stderr, "%s has unsupported BFACS version number %i\n", filename, header.version);
		return;
	}

	if (header.block_size > 1 && header.block_size != header.iv_size) {
		fprintf(stderr, "%s has mismatched IV & block sizes.\n", filename);
		return;
	}

	if (header.iv_size > BFACS_BLOCK_SIZE_MAX) {
		fprintf(stderr, "%s has invalid IV size %i.  Maximum valid is %i.\n", filename, header.iv_size, BFACS_BLOCK_SIZE_MAX);
		return;
	}

	if (header.block_size > BFACS_BLOCK_SIZE_MAX) {
		fprintf(stderr, "%s has invalid block size %i.  Maximum valid is %i.\n", filename, header.block_size, BFACS_BLOCK_SIZE_MAX);
		return;
	}

	if (header.iv_size > 0) {
		rv = fread(iv, 1, header.iv_size, fp);

		if (rv < 0) {
			fprintf(stderr, "Failed to read IV from %s: %s\n", filename, strerror(errno));
			return;
		} else if (rv < header.iv_size) {
			fprintf(stderr, "Short read while trying to read IV from %s\n", filename);
			return;
		}
	}

	// We need at least four bytes to decrypt so we can check the encrypted
	// header magic value, *or* a full encrypted block, if that's bigger.
	int block_size = header.block_size >= 4 ? header.block_size : 4;

    rv = fread(block, 1, block_size, fp);
	if (rv < 0) {
		fprintf(stderr, "Failed to read first ciphertext block from %s: %s\n", filename, strerror(errno));
		return;
	} else if (rv < block_size) {
		fprintf(stderr, "Short read while trying to read first ciphertext block from %s\n", filename);
		return;
	}

	// And now, we can print it all out!
	printf("$bfacs$1*%i*", header.block_size);

	for (int i = 0; i < 11;             i++) printf("%02x", header.salt[i]);
	printf("*");
	for (int i = 0; i <  4;             i++) printf("%02x", header.key_check[i]);
	printf("*");
	for (int i = 0; i < header.iv_size; i++) printf("%02x", iv[i]);
	printf("*");
	for (int i = 0; i < block_size;     i++) printf("%02x", block[i]);

	printf("\n");
}

int main(int argc, char *argv[])
{
	if (argc == 1) {
		fprintf(stderr, "Please specify one or more files to extract hashes from.\n");
		return 1;
	}

	for (int i = 1; i < argc; i++) {
		parse_file(argv[i]);
	}

	return 0;
}

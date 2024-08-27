#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

#include "base64.h"

typedef __uint128_t uint128_t;

// FIXME: remove this macro as I don't think it's allowed
#define WRITE(fd, static_string) write(fd, static_string, sizeof(static_string))

enum e_primeness {
	P_COMPOSITE,
	P_PROBABLY_PRIME,
};

void print_help() {
	char const help_text[] = "usage: ft_ssl command [command opts] [command args]";
	write(STDOUT_FILENO, help_text, sizeof(help_text) - 1);
}

size_t ft_strlen(char const *str) {
	size_t len = 0;
	while (str[len] != '\0') {
		len++;
	}
	return len;
}

void print_incorrect_command(char *cmd) {
	char const help_text_prefix[] = "ft_ssl: Error: '";
	char const help_text[] =
		"' is an invalid command.\n"
		"\n"
		"Standard commands:\n"
		"genrsa\n"
		// TODO: make this list complete (just like in the subject example)
	;
	write(STDOUT_FILENO, help_text_prefix, sizeof(help_text_prefix) - 1);
	write(STDOUT_FILENO, cmd, ft_strlen(cmd));
	write(STDOUT_FILENO, help_text, sizeof(help_text) - 1);
}

/*
 * If `size_bytes` is above 256 this may not work as expected, see `man 4 random` aka `man urandom`
 */
ssize_t ft_random(void *buf, size_t size_bytes) {
	int fd_random = open("/dev/urandom", O_RDONLY); // TODO: only use 1 instance
	ssize_t r = read(fd_random, buf, size_bytes);
	close(fd_random);
	return r;
}

uint64_t ft_random_64() {
	uint64_t r;
	ft_random(&r, sizeof(r));
	return r;
}

uint64_t rand_in_range_inclusive(uint64_t low, uint64_t high) {
	return (ft_random_64() % (high - low + 1)) + low;
}

uint64_t mod_pow(uint64_t base, uint64_t exponent, uint64_t modulus) {
	uint128_t b = base % modulus;
	uint128_t result = 1;
	while (exponent > 0) {
		if ((exponent & 1) == 1) {
			result *= b;
			result %= modulus;
		}
		exponent >>= 1;
		b *= b;
		b %= modulus;
	}
	return result;
}

enum e_primeness miller_rabin(uint64_t n, uint64_t rounds) {
	assert(n >= 2);
	if (n == 2) {
		return P_PROBABLY_PRIME;
	}
	if (n % 2 == 0) {
		return P_COMPOSITE;
	}

	uint64_t d = n - 1;
	uint8_t s = 0;
	while ((d & 1) == 0) {
		s++;
		d >>= 1;
	}
	assert(s != 0);
	assert(d != 0);

	for (uint64_t round = 0; round < rounds; round++) {
		uint64_t a = rand_in_range_inclusive(2, n - 2);
		assert(a >= 2 && a <= n - 2);
		uint64_t x = mod_pow(a, d, n);
		for (uint8_t s_round = 0; s_round < s; s_round++) {
			uint64_t y = ((uint128_t)x * x) % n; // mod_pow(x, 2, n);
			if (y == 1 && x != 1 && x != n - 1) {
				return P_COMPOSITE;
			}
			x = y;
		}
		if (x != 1) {
			return P_COMPOSITE;
		}
	}

	return P_PROBABLY_PRIME;
}

int ft_strcmp(char const *s1, char const *s2) {
	while (*s1 == *s2 && *s1 != '\0') { // && *s2 != '\0'
		s1++;
		s2++;
	}
	return *s1 - *s2;
}

bool ft_streq(char const *s1, char const *s2) {
	return ft_strcmp(s1, s2) == 0;
}

struct rsa_opts {
	char *out;
	size_t numbits;
};

void parse_genrsa_args(char **args, struct rsa_opts *opts) { // FIXME: remove? doesn't seem like it's used in the subject
	char *numbits = args[0];

	size_t i = 0;
	while ('0' <= numbits[i] && numbits[i] <= '9') {
		opts->numbits *= 10; // TODO: check for overflow
		opts->numbits += numbits[i] - '0';
	}
	if (numbits[i] != '\0') {
		// FIXME: Error: not a number
	}
	if (opts->numbits < 512) {
		// FIXME: Error: numbits must be at least 512
	}
	if (args[1] != NULL) {
		// FIXME: Error: unexpected argument
	}
}

struct rsa_opts parse_genrsa_opts(char **args) {
	struct rsa_opts opts = {
		.out = NULL,
		.numbits = 2048,
	};
	size_t arg_index = 0;
	while (args[arg_index] != NULL) {
		char *arg = args[arg_index];
		if (arg[0] == '-') {
			if (ft_streq(&arg[1], "out")) {
				opts.out = args[arg_index + 1];
				arg_index++;
			}
			else {
				// FIXME: Error: unknown option
			}
		}
		else {
			parse_genrsa_args(&args[arg_index], &opts);
			break;
		}
		arg_index++;
	}
	return opts;
}

uint64_t gcd(uint64_t a, uint64_t b) {
	while (a != b && b != 0) {
		a %= b;
		uint64_t tmp = a;
		a = b;
		b = tmp;
	}
	return a;
}

uint128_t lcm(uint64_t a, uint64_t b) {
	return ((uint128_t)a * b) / gcd(a, b);
}

void generate_primes(uint64_t *p, uint64_t *q, uint64_t exponent) {
	// TODO: take a look at: https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_sp800_56b_gen.c#L55
	bool is_first = true;
	do {
		if (!is_first) {
			WRITE(STDOUT_FILENO, "*");
		}
		*p = rand_in_range_inclusive(exponent, UINT64_MAX) | 1 | ((uint64_t)1 << 63);
		is_first = false;
	} while ((*p - 1) % exponent != 0 && miller_rabin(*p, 65) == P_COMPOSITE);
	WRITE(STDOUT_FILENO, "\n");
	is_first = true;
	do {
		if (!is_first) {
			WRITE(STDOUT_FILENO, "*");
		}
		*q = rand_in_range_inclusive(exponent, UINT64_MAX) | 1 | ((uint64_t)1 << 63);
		is_first = false;
	} while ((*q - 1) % exponent != 0 && miller_rabin(*q, 65) == P_COMPOSITE);
}

uint64_t mod_mult_inverse(uint64_t n, uint64_t modulus) {
	uint64_t even_r = n;
	uint64_t odd_r = modulus;

	uint64_t even_s = 1;
	uint64_t odd_s = 0;

	while (true) {
		uint64_t q = even_r / odd_r;

		even_r = even_r - q * odd_r;
		if (even_r == 0) {
			return modulus - odd_s;
		}
		even_s = even_s + q * odd_s;

		q = odd_r / even_r;

		odd_r = odd_r - q * even_r;
		if (odd_r == 0) {
			return even_s;
		}
		odd_s = odd_s + q * even_s;
	}
}

void print_bits(int fd, uint128_t num, uint8_t bits) {
	uint8_t len = 0;
	char buf[128] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	while (num != 0) {
		buf[sizeof(buf) - len - 1] = (num & 1) ? '1' : '0';
		num >>= 1;
		len++;
	}
	write(fd, buf + sizeof(buf) - bits, bits);
}

void print_bits8(int fd, uint8_t byte) {
	print_bits(fd, byte, 8);
}

uint8_t write_asn1_integer_unsigned_buf(uint8_t *buf, uint64_t n) {
	uint8_t *buf_start = buf;
	uint8_t byte_len = 1;
	while (byte_len < sizeof(n) && (n >> (byte_len * 8)) != 0) {
		byte_len++;
	}
	printf("0x%.16lx: %u", n, byte_len);
	if (n == 0x10001) {
		printf(" (0x%lx)", n >> (byte_len * 8));
	}
	printf("\n");
	*(buf++) = 0x02; // (signed) INTEGER
	if (n >> (byte_len * 8 - 1) != 0) { // has highest bit set
		*(buf++) = byte_len + 1; // with length `byte_len + 1`
		*(buf++) = 0x00; // set byte with sign bit to 0
	}
	else {
		*(buf++) = byte_len; // with length `byte_len`
	}
	while (byte_len > 0) {
		byte_len--;
		uint8_t byte = (n >> (byte_len * 8)) & 0xFF;
		*(buf++) = byte;
	}
	return buf - buf_start;
}

struct rsa_data {
	uint64_t exponent;
	uint64_t d_inverse;
	uint64_t p;
	uint64_t q;
};

// https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
// https://datatracker.ietf.org/doc/html/rfc3447#appendix-A.1.2
// https://lapo.it/asn1js/
void print_private_key(int fd, struct rsa_data rsa_data) { // pkcs1
	struct RSAPrivateKey { // SEQUENCE
		enum version {
			VERSION_TWO_PRIME = 0,
			VERSION_MULTI_PRIME = 1,
		} version; // INTEGER
		uint64_t modulus; // INTEGER
		uint64_t publicExponent; // INTEGER
		uint64_t privateExponent; // INTEGER
		uint64_t prime1; // INTEGER
		uint64_t prime2; // INTEGER
		uint64_t exponent1; // INTEGER
		uint64_t exponent2; // INTEGER
		uint64_t coefficient; // INTEGER
		// void otherPrimeInfos;
	} RSAPrivateKey = {
		.version = VERSION_TWO_PRIME,
		.modulus = rsa_data.p * rsa_data.q,
		.publicExponent = rsa_data.exponent,
		.privateExponent = rsa_data.d_inverse,
		.prime1 = rsa_data.p,
		.prime2 = rsa_data.q,
		.exponent1 = rsa_data.d_inverse % (rsa_data.p - 1),
		.exponent2 = rsa_data.d_inverse % (rsa_data.q - 1),
		.coefficient = mod_mult_inverse(rsa_data.q, rsa_data.p), // TODO: ??? [(inverse of q) mod p] // [mod_mult_inverse(q, p) ?]
	};
	assert(RSAPrivateKey.version == VERSION_TWO_PRIME);

	uint8_t buf[128]; // RSAPrivateKey (with version = TWO_PRIME) should only need at most 93 bytes

	uint8_t byte_len = 0;
	buf[0] = 0x30; // SEQUENCE
	byte_len += write_asn1_integer_unsigned_buf(&buf[byte_len + 2], RSAPrivateKey.version);
	byte_len += write_asn1_integer_unsigned_buf(&buf[byte_len + 2], RSAPrivateKey.modulus);
	byte_len += write_asn1_integer_unsigned_buf(&buf[byte_len + 2], RSAPrivateKey.publicExponent);
	byte_len += write_asn1_integer_unsigned_buf(&buf[byte_len + 2], RSAPrivateKey.privateExponent);
	byte_len += write_asn1_integer_unsigned_buf(&buf[byte_len + 2], RSAPrivateKey.prime1);
	byte_len += write_asn1_integer_unsigned_buf(&buf[byte_len + 2], RSAPrivateKey.prime2);
	byte_len += write_asn1_integer_unsigned_buf(&buf[byte_len + 2], RSAPrivateKey.exponent1);
	byte_len += write_asn1_integer_unsigned_buf(&buf[byte_len + 2], RSAPrivateKey.exponent2);
	byte_len += write_asn1_integer_unsigned_buf(&buf[byte_len + 2], RSAPrivateKey.coefficient);
	buf[1] = byte_len; // with length `byte_len`

	print_base64_buf(fd, buf, byte_len + 2, true);
}

void gen_rsa(char **args) {
	struct rsa_data rsa_data;
	(void)args;
	// struct rsa_opts opts = parse_genrsa_opts(args); // TODO: use

	// uint8_t num_primes = 2;
	rsa_data.exponent = 0x10001;
	WRITE(STDOUT_FILENO, "Generating RSA private key, 64 bit long modulus\n");
	rsa_data.p = 19;
	rsa_data.q = 31;
	generate_primes(&rsa_data.p, &rsa_data.q, rsa_data.exponent);
	assert(rsa_data.p - 1 > rsa_data.exponent);
	assert(rsa_data.q - 1 > rsa_data.exponent);

	uint64_t lambda_n = lcm(rsa_data.p - 1, rsa_data.q - 1); // (p-1)*(q-1) / gcd(p-1, q-1) => max: (p-1)*(q-1) && min: max(p-1, q-1)
	printf("lambda_n: %lu\n", lambda_n);
	assert(lambda_n > rsa_data.exponent);
	
	rsa_data.d_inverse = mod_mult_inverse(rsa_data.exponent, lambda_n);
	printf("d_inverse: %lu\n", rsa_data.d_inverse);
	uint128_t m = (uint128_t)rsa_data.exponent * rsa_data.d_inverse;
	assert(m % lambda_n == 1); // assert that d_inverse really is the modular multiplicitive inverse of exponent (mod lambda_n)

	WRITE(STDOUT_FILENO, "e is 65537 (0x10001)\n"); // TODO: change if making the exponent changable
	WRITE(STDOUT_FILENO, "-----BEGIN RSA PRIVATE KEY-----\n");
	// print_base64(STDOUT_FILENO, rsa_data.d_inverse, true);
	print_private_key(STDOUT_FILENO, rsa_data);
	WRITE(STDOUT_FILENO, "\n-----END RSA PRIVATE KEY-----\n");
	// printf("bits: %lu\n", count_base64_bits("MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAuYi2huNuGZDQ/ruFnjnIj1UjVAHOJ5axk0jfJMWdyPDTfaxGeLfA7JyOMbs60pdUF+/vPCgx2SIb5CPARfkSFQIDAQABAkA9wgM3/UZt3iWjVVpR49wd0fIziXJM/T1Y0H3uqJUwCF/Hyop+LjPshH2QH7Anmtw4diJAmhKKk5GoxtZtpKDVAiEA9ebXRbIxjmjlD2RTLIq09QXwVCHq4nkxZVOlOvXf+DcCIQDBJzpd9HtyYUIAy8W4vZkrkrpNU2KmN90i5fdpq9SKEwIgCKYK0j+3MHwN+mGb70gdnzSLRFpBCaAblaXAfPdi3jcCIAO+NN1ZPYMr61GEoWJBGlTD1SRmd0TtVDW26yJ7F/VNAiEArutOMI4uQlrImWQTAeY1i3QUJOW8/4Sq2g5dLlQ9rdk="));
	// printf("bits: %lu\n", count_base64_bits("MIIBPAIBAAJBANnJCBLDjRKjqkYnXBoR/VrCYlzN8YdrXKspMytsrbEnZEoAeilxNkqDzxxjdgjmPSgFXaD0BaOfK/aNOzGrOLMCAwEAAQJBAL+K9/bI1sKV/6RD6dVkDRhN7oUA/HTGEHLZgY+nvfwXsOs5fSsE59tToUjrfzrVpYMBvDyLF5KrInWJdX6U+AECIQD8leNmQp8OwzVfA9uvuMyZTgJbmkMZdZLdCtEF0CmFgQIhANy6ti22ayxS/UzmaRxgR9QimsyYZ/6zj6SnZFPCdaAzAiAeE8ssViqSm3QziEYUurDCYKOvPMNYuMNwRuV1B8CqAQIhAJpoDkraAgzGnSTvRXYxL+4IqwsWTiFRUNmYs0kYjhobAiEAnOTwrDuGwlvtkp3agNtx4BX/FTT4uGh0hsi+QXKrPCU="));
printf("bits: %lu\n", count_base64_bits("MFACAQACCEVCVifkZdhSAgMAAQACCIExVVKFUHAlAgkAwePcdgw9Kz8CCQCFnhRxb4fc8wIIgTFVUoVQcCUCCIExVVKFUHAlAgjiU+z3jVnjhw=="));
printf("bits: %lu\n", count_base64_bits("MIIBOwIBAAJBAMLh8BxMEm/x+wDjpcMAeCANVFUfKdp9XR2H4VAnCK7b3x6SBD0vq/e5iyp+zPDMiG2A263x6eQCRbUOXMpU1txEWgCk4w=="));
	uint8_t buf[128]; // RSAPrivateKey (with version = TWO_PRIME) should only need at most 93 bytes
	uint8_t len = write_asn1_integer_unsigned_buf(buf, 0x10001);
	print_base64_buf(STDERR_FILENO, buf, len, true);
	// printf("bits: %lu\n", count_base64_bits("pRprL7lJbuE="));
}

void run_cmd(char *cmd, char **args) {
	if (ft_streq(cmd, "genrsa")) {
		gen_rsa(args);
		return;
	}
	print_incorrect_command(cmd);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		print_help();
		return EXIT_FAILURE;
	}
	run_cmd(argv[1], &argv[2]);
	return EXIT_SUCCESS;
} 

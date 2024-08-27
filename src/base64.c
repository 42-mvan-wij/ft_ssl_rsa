#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

static size_t ft_strlen(char const *str) {
	size_t len = 0;
	while (str[len] != '\0') {
		len++;
	}
	return len;
}


void print_base64_buf(int fd, void *n, size_t len, bool padding) {
	static char const base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char buffer[128];
	size_t index = 0;
	uint8_t pad = (3 - (len % 3)) % 3;

	uint32_t n_buf = 0;
	uint8_t bits = 0;

	size_t n_index = 0;

	uint8_t *nn = n;

	if (len == 0) {
		return;
	}

	while (true) {
		if (n_index < len && bits <= 24 - 8) {
			n_buf |= nn[n_index] << (24 - 8 - bits);
			bits += 8;
			n_index++;
		}

		uint8_t r = (n_buf >> (24 - 6)) & 0b111111;

		buffer[index] = base[r];
		index++;
		if (index == sizeof(buffer)) {
			write(fd, buffer, index);
			index = 0;
		}

		if (n_index == len && bits <= 6) {
			break;
		}

		n_buf <<= 6;
		bits -= 6;
	}

	if (index != 0) {
		write(fd, buffer, index);
	}
	if (padding && pad > 0) {
		write(fd, "===", pad);
	}
}

void print_base64(int fd, uint64_t n, bool padding) {
	uint8_t b[] = {
		(n >> 56) & 0xFF,
		(n >> 48) & 0xFF,
		(n >> 40) & 0xFF,
		(n >> 32) & 0xFF,
		(n >> 24) & 0xFF,
		(n >> 16) & 0xFF,
		(n >> 8)  & 0xFF,
		(n >> 0)  & 0xFF
	}; // x86_64 is little endian, this would cause problems when passing n in directly
	print_base64_buf(fd, b, 8, padding);
}

void base64_decode_buf(char *base64, uint8_t *buf) {
	static uint8_t const base[] = {
		['A'] = 0,
		['B'] = 1,
		['C'] = 2,
		['D'] = 3,
		['E'] = 4,
		['F'] = 5,
		['G'] = 6,
		['H'] = 7,
		['I'] = 8,
		['J'] = 9,
		['K'] = 10,
		['L'] = 11,
		['M'] = 12,
		['N'] = 13,
		['O'] = 14,
		['P'] = 15,
		['Q'] = 16,
		['R'] = 17,
		['S'] = 18,
		['T'] = 19,
		['U'] = 20,
		['V'] = 21,
		['W'] = 22,
		['X'] = 23,
		['Y'] = 24,
		['Z'] = 25,

		['a'] = 26,
		['b'] = 27,
		['c'] = 28,
		['d'] = 29,
		['e'] = 30,
		['f'] = 31,
		['g'] = 32,
		['h'] = 33,
		['i'] = 34,
		['j'] = 35,
		['k'] = 36,
		['l'] = 37,
		['m'] = 38,
		['n'] = 39,
		['o'] = 40,
		['p'] = 41,
		['q'] = 42,
		['r'] = 43,
		['s'] = 44,
		['t'] = 45,
		['u'] = 46,
		['v'] = 47,
		['w'] = 48,
		['x'] = 49,
		['y'] = 50,
		['z'] = 51,

		['0'] = 52,
		['1'] = 53,
		['2'] = 54,
		['3'] = 55,
		['4'] = 56,
		['5'] = 57,
		['6'] = 58,
		['7'] = 59,
		['8'] = 60,
		['9'] = 61,

		['+'] = 62,
		['/'] = 63,
	};

	size_t i = 0;
	size_t buf_index = 0;
	uint32_t byte_buf = 0;
	size_t bits = 0;
	while (base64[i] != '=' && base64[i] != '\0') {
		byte_buf |= (uint32_t)base[(uint8_t)base64[i]] << (sizeof(byte_buf) * 8 - 6 - bits);
		bits += 6;
		if (bits >= 8) {
			buf[buf_index] = byte_buf >> (sizeof(byte_buf) * 8 - 8);
			byte_buf <<= 8;
			bits -= 8;
			buf_index++;
		}
		i++;
	}
	if (bits > 0) {
		buf[buf_index] = byte_buf >> (sizeof(byte_buf) * 8 - 8);
	}
}

size_t base64_encode_len(size_t len_aka_octets, bool with_padding) {
	size_t full24 = len_aka_octets / 3;
	uint8_t extra_octets = len_aka_octets % 3;

	size_t extra_sextets = ((extra_octets * 8) + 5) / 6; // ceil_div(extra_octets * 8, 6)
	if (with_padding) {
		if (extra_octets > 0) {
			full24 += 1;
		}
		return full24 * 4;
	}
	return full24 * 4 + extra_sextets;
}

size_t base64_decode_len(size_t len_exclude_pad) {
	size_t full24 = len_exclude_pad / 4;
	size_t extra_sextets = len_exclude_pad % 4;
	assert(extra_sextets != 1);

	size_t extra_octets = (extra_sextets * 6) / 8;

	return full24 * 3 + extra_octets;
}

size_t base64_decode_len_str(char *base64) {
	size_t len = ft_strlen(base64);
	while (base64[len - 1] == '=') {
		len--;
	}
	return base64_decode_len(len);
}

size_t count_base64_bits(char *base64) { // FIXME: remove
	size_t len = ft_strlen(base64);
	while (base64[len - 1] == '=') {
		len--;
	}
	size_t padding = (4 - (len % 4)) % 4;
	return len * 6 - 2 * padding;
}

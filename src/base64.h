#pragma once

#include <stddef.h>
#include <stdint.h>

void print_base64_buf(int fd, void *n, size_t len, bool padding);
void print_base64(int fd, uint64_t n, bool padding);
void base64_decode_buf(char *base64, uint8_t *buf);
size_t base64_encode_len(size_t len_aka_octets, bool with_padding);
size_t base64_decode_len(size_t len_exclude_pad);
size_t base64_decode_len_str(char *base64);
size_t count_base64_bits(char *base64); // FIXME: remove


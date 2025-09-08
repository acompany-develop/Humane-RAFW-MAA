#pragma once

#include <stdio.h>
#include <stdint.h>

int from_hexstring(uint8_t *dest, const void *vsrc, size_t len);
char* to_hexstring(const uint8_t *buf, size_t size);
void print_hexstring(FILE *fp, uint8_t *source, size_t len);
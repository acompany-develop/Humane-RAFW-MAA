#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sstream>
#include <iomanip>
#include "hexutil.hpp"
#include "debug_print.hpp"

static char *hex_buffer = NULL;
static size_t hex_buffer_size = 0;
const char hex_table[] = "0123456789abcdef";

int from_hexstring(uint8_t *dest, const void *vsrc, size_t len)
{
    const uint8_t *src = (const uint8_t*)vsrc;

    for(int i = 0; i < len; ++i)
    {
        uint32_t v;
        if(sscanf((const char*)&src[i * 2], "%2xhh", &v) == 0) return -1;

        dest[i] = (uint8_t)v;
    }

    return 0;
}


char* to_hexstring(const uint8_t *buf, size_t size)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (size_t i = 0; i < size; ++i)
    {
        ss << std::setw(2) << static_cast<int>(buf[i]);
    }

    char *result = strdup(ss.str().c_str());

    return result;
}


void print_hexstring(FILE *fp, uint8_t *source, size_t len)
{
	for(int i = 0; i < len; ++i)
    {
		fprintf(fp, "%02x", source[i]);
	}

    fprintf(fp, "\n");
    return;
}
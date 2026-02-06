#include <stdint.h>
#include <stdio.h>
#include <string.h>

void os_io_seph_cmd_printf(const char *str, uint16_t charcount) {
    fwrite(str, 1, charcount, stderr);
}

size_t strlcpy(char *dst, const char *src, size_t dstlen) {
    const size_t source_length = strlen(src);

    if (dstlen > 0) {
        const size_t copy_length = (source_length >= dstlen) ? (dstlen - 1) : source_length;
        if (copy_length > 0) {
            memcpy(dst, src, copy_length);
        }
        dst[copy_length] = '\0';
    }

    return source_length;
}

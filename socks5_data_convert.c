#include "socks5.h"
#include <string.h>

socks5_error_t socks5_get_data_convert_func_pair(short cmd_type, socks5_data_proc_func_t* func0, socks5_data_proc_func_t* func1) {
    switch(cmd_type) {
        case SOCKS5_CONN_CMD_CONNECT:
            *func0 = socks5_data_convert_connect_0;
            *func1 = socks5_data_convert_connect_1;
            break;
        default:
            return SOCKS5_ERROR_DATA_CONV_NOT_FOUND;
    }
    return SOCKS5_SUCCESS;
}

socks5_error_t socks5_data_convert_connect_0(const void* in, size_t inlen, void** out, size_t* outlen) {
    *out = malloc(inlen);
    memcpy(*out, in, inlen);
    *outlen = inlen;

    return SOCKS5_SUCCESS;
}

socks5_error_t socks5_data_convert_connect_1(const void* in, size_t inlen, void** out, size_t* outlen) {
    *out = malloc(inlen);
    memcpy(*out, in, inlen);
    *outlen = inlen;

    return SOCKS5_SUCCESS;
}

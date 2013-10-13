#include <stdio.h>
#include <unistd.h>
#include "socks5.h"

char buffer[1024];
void * ptr;
#define _CALL _call
void _call(socks5_error_t err) {
    if(err == SOCKS5_SUCCESS)
        return;
    printf(" ** error : %d\n", err);
    exit(-1);
}

int main() {
    socks5_data_proc_func_t pfunc;
    size_t size;
    socks5_error_t err;
    socks5_connect_requ_t* prequ;
    socks5_connect_resp_t* presp;
    socks5_connect_info_t* pinfo;
    socks5_connect_resl_t resl;

    /*
    buffer[0] = 0x05;
    buffer[1] = 0x02;
    buffer[2] = 0x00;
    buffer[3] = 0x01;
    buffer[4] = 0xff;
    buffer[5] = 0x00;
    buffer[6] = 0x00;
    buffer[7] = 0x77;
    buffer[8] = 0x00;
    buffer[9] = 0xff;


    _CALL(socks5_pack_connect_requ_t(buffer, 10, &prequ));
    _CALL(socks5_unpack_connect_requ_t(prequ, &ptr, &size));

    _CALL(socks5_get_func_by_id(SOCKS5_FUNC_ID_CONNECT_CHECK, &pfunc));
    err = (*pfunc)(buffer, 10, &ptr, &size);

    if(err == SOCKS5_CONN_CHECK_SUCCESS) {
        _CALL(socks5_pack_connect_info_t(ptr, size, &pinfo));
    } else if(err == SOCKS5_CONN_CHECK_FAILED) {
        _CALL(socks5_pack_connect_resp_t(ptr, size, &presp));
    } else {
        _call(err);
    }

    buffer[0] = 0x05;
    buffer[1] = 0x00;
    buffer[2] = 0x00;
    buffer[3] = SOCKS5_CONN_ATYP_IPV6;
    buffer[4] = 0x11;
    buffer[5] = 0x11;
    buffer[6] = 0x11;
    buffer[7] = 0x11;
    buffer[8] = 0x22;
    buffer[9] = 0x22;
    buffer[10] = 0x22;
    buffer[11] = 0x22;
    buffer[12] = 0x33;
    buffer[13] = 0x33;
    buffer[14] = 0x33;
    buffer[15] = 0x33;
    buffer[16] = 0x44;
    buffer[17] = 0x44;
    buffer[18] = 0x44;
    buffer[19] = 0x44;
    buffer[20] = 0x10;
    buffer[21] = 0xff;

    _CALL(socks5_pack_connect_resp_t(buffer, 22, &presp));
    _CALL(socks5_unpack_connect_resp_t(presp, &ptr, &size));
    */

    _CALL(socks5_get_func_by_id(SOCKS5_FUNC_ID_CONNECT_RESP, &pfunc));
    resl.rep = SOCKS5_CONN_CHECK_SUCCESS;
    resl.addr_type = SOCKS5_CONN_ATYP_DOMAIN;
    resl.addr_len = 5;
    resl.addr[0] = 'r';
    resl.addr[1] = 'a';
    resl.addr[2] = 'p';
    resl.addr[3] = 'i';
    resl.addr[4] = 'd';
    resl.port = 0x1234;

    void * _ptr;
    size_t _size;
    _CALL(socks5_unpack_connect_resl_t(&resl, &_ptr, &_size));
    err = (*pfunc)(_ptr, _size, &ptr, &size);
    if(err == SOCKS5_CONN_RESP_SUCCESS || err == SOCKS5_CONN_RESP_DENIED) {
        _CALL(socks5_pack_connect_resp_t(ptr, size, &presp));
    }
    _call(err);
    return 0;
}

#include "socks5.h"
#include <string.h>
#include <assert.h>

socks5_error_t socks5_proc_connect_check(const void* requ, size_t requ_len, void** info, size_t* info_len) {
    socks5_error_t err;
    socks5_connect_requ_t* requ_struct;
    static socks5_connect_resp_t resp_struct;
    static socks5_connect_info_t info_struct;

    err = socks5_pack_connect_requ_t(requ, requ_len, &requ_struct);
    if(err != SOCKS5_SUCCESS) {
        return err;
    }

    switch(requ_struct->cmd) {
        case SOCKS5_CONN_CMD_CONNECT:
            info_struct.type = SOCKS5_CONN_TYPE_TCP;
            break;
        case SOCKS5_CONN_CMD_BIND:
        case SOCKS5_CONN_CMD_UDP_ASSOCIATE: // Unsupported cmd
            free(requ_struct);
            memset(&resp_struct, 0, sizeof(resp_struct));
            resp_struct.ver = 5;
            resp_struct.rep = SOCKS5_CONN_REP_CMD_NOT_SUPPORTED;
            resp_struct.rsv = SOCKS5_CONN_RSV;
            resp_struct.atyp = SOCKS5_CONN_ATYP_IPV4;

            err = socks5_unpack_connect_resp_t(&resp_struct, info, info_len);
            assert(err == SOCKS5_SUCCESS);
            return SOCKS5_CONN_CHECK_FAILED;
    }

    info_struct.addr_type = requ_struct->atyp;
    switch(requ_struct->atyp) {
        case SOCKS5_CONN_ATYP_IPV4:
            info_struct.addr_len = 4;
            memcpy(info_struct.addr, requ_struct->addr, 4);
            break;
        case SOCKS5_CONN_ATYP_IPV6:
            info_struct.addr_len = 16;
            memcpy(info_struct.addr, requ_struct->addr, 16);
            break;
        case SOCKS5_CONN_ATYP_DOMAIN:
            info_struct.addr_len = (size_t)requ_struct->addr[0];
            memcpy(info_struct.addr, requ_struct->addr + 1, info_struct.addr_len);
            break;
    }

    info_struct.port = requ_struct->port;

    free(requ_struct);
    err = socks5_unpack_connect_info_t(&info_struct, info, info_len);
    if(err != SOCKS5_SUCCESS) {
        return err;
    }
    return SOCKS5_CONN_CHECK_SUCCESS;
}

socks5_error_t socks5_proc_connect_resp(const void* resl, size_t resl_len, void** resp, size_t* resp_len) {
    socks5_error_t err;
    socks5_connect_resl_t* resl_struct;
    static socks5_connect_resp_t resp_struct;

    err = socks5_pack_connect_resl_t(resl, resl_len, &resl_struct);
    if(err != SOCKS5_SUCCESS) {
        return err;
    }

    resp_struct.ver = 5;
    resp_struct.rep = resl_struct->rep;
    resp_struct.rsv = SOCKS5_CONN_RSV;
    resp_struct.atyp = resl_struct->addr_type;
    switch(resl_struct->addr_type) {
    case SOCKS5_CONN_ATYP_IPV4:
    case SOCKS5_CONN_ATYP_IPV6:
        memcpy(resp_struct.addr, resl_struct->addr, resl_struct->addr_len);
        break;
    case SOCKS5_CONN_ATYP_DOMAIN:
        resp_struct.addr[0] = (char)resl_struct->addr_len;
        memcpy(resp_struct.addr + 1, resl_struct->addr, resl_struct->addr_len);
        break;
    }
    resp_struct.port = resl_struct->port;

    free(resl_struct);

    err = socks5_unpack_connect_resp_t(&resp_struct, resp, resp_len);
    if(err != SOCKS5_SUCCESS) {
        return err;
    }

    if(resp_struct.rep == SOCKS5_CONN_REP_SUCCESS) {
        return SOCKS5_CONN_RESP_SUCCESS;
    } else {
        return SOCKS5_CONN_RESP_DENIED;
    }
}

static socks5_error_t _convert_into_ipv4(const void*, size_t, char*, size_t*);
static socks5_error_t _convert_into_ipv6(const void*, size_t, char*, size_t*);
static socks5_error_t _convert_into_domain(const void*, size_t, char*, size_t*);
static socks5_error_t _convert_from_ipv4(const char*, void*, size_t*);
static socks5_error_t _convert_from_ipv6(const char*, void*, size_t*);
static socks5_error_t _convert_from_domain(const char*, void*, size_t*);

socks5_error_t socks5_pack_connect_requ_t(const void* data, size_t len, socks5_connect_requ_t** requ) {
    if(len < 6 || len > 262) {
        return SOCKS5_ERROR_WRONG_DATA_LEN;
    }

    *requ = (socks5_connect_requ_t*)malloc(sizeof(socks5_connect_requ_t));
    socks5_connect_requ_t* t = *requ;
    char* dp = (char*)data;
    socks5_error_t err;
    size_t adlen;

    t->ver = *(dp + 0);
    if(t->ver != 5) {
        free(t);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }

    t->cmd = *(dp + 1);
    if(t->cmd != SOCKS5_CONN_CMD_BIND &&
       t->cmd != SOCKS5_CONN_CMD_CONNECT &&
       t->cmd != SOCKS5_CONN_CMD_UDP_ASSOCIATE) {
           free(t);
           return SOCKS5_ERROR_WRONG_FORMAT;
       }

    t->rsv = *(dp + 2);
    if(t->rsv != SOCKS5_CONN_RSV) {
        free(t);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }

    t->atyp = *(dp + 3);
    if(t->atyp == SOCKS5_CONN_ATYP_IPV4) {
        err = _convert_into_ipv4(dp + 4, len - 4, t->addr, &adlen);
    } else if(t->atyp == SOCKS5_CONN_ATYP_DOMAIN) {
        err = _convert_into_domain(dp + 4, len - 4, t->addr, &adlen);
    } else if(t->atyp == SOCKS5_CONN_ATYP_IPV6) {
        err = _convert_into_ipv6(dp + 4, len - 4, t->addr, &adlen);
    } else {
        free(t);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }
    if(err != SOCKS5_SUCCESS) {
        free(t);
        return err;
    }

    if(len != 4 + adlen + 2) {
        return SOCKS5_ERROR_WRONG_DATA_LEN;
    }
    unsigned short hb = *(dp + 4 + adlen),
        lb = *(dp + 4 + adlen + 1);
    lb &= (0x00ff);
    hb &= (0x00ff);
    t->port = (hb << 8) + lb;

    return SOCKS5_SUCCESS;
}

socks5_error_t socks5_unpack_connect_requ_t(socks5_connect_requ_t* requ, void** data, size_t* len) {
    *data = malloc(sizeof(socks5_connect_requ_t));
    char* dp = *data;
    socks5_error_t err;
    size_t adlen;

    if(requ->ver != 5) {
        free(dp);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }
    *(dp + 0) = requ->ver;

    if(requ->cmd != SOCKS5_CONN_CMD_BIND &&
       requ->cmd != SOCKS5_CONN_CMD_CONNECT &&
       requ->cmd != SOCKS5_CONN_CMD_UDP_ASSOCIATE) {
        free(dp);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }
    *(dp + 1) = requ->cmd;

    if(requ->rsv != SOCKS5_CONN_RSV) {
        free(dp);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }
    *(dp + 2) = requ->rsv;

    if(requ->atyp == SOCKS5_CONN_ATYP_IPV4) {
        err = _convert_from_ipv4(requ->addr, dp + 4, &adlen);
    } else if(requ->atyp == SOCKS5_CONN_ATYP_DOMAIN) {
        err = _convert_from_domain(requ->addr, dp + 4, &adlen);
    } else if(requ->atyp == SOCKS5_CONN_ATYP_IPV6) {
        err = _convert_from_ipv6(requ->addr, dp + 4, &adlen);
    } else {
        free(dp);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }
    *(dp + 3) = requ->atyp;

    if(err != SOCKS5_SUCCESS) {
        free(dp);
        return err;
    }
    unsigned short hb = (requ->port >> 8),
        lb  = requ->port & 0x00ff;
    *(dp + 4 + adlen) = (char)hb;
    *(dp + 4 + adlen + 1) = (char)lb;

    *len = 4 + adlen + 2;

    void * ret = malloc(*len);
    memcpy(ret, (void*)dp, *len);
    free(dp);
    *data = ret;

    return SOCKS5_SUCCESS;
}

socks5_error_t socks5_pack_connect_info_t(const void* data, size_t len, socks5_connect_info_t** info) {
    if(len != sizeof(socks5_connect_info_t)) {
        return SOCKS5_ERROR_WRONG_DATA_LEN;
    }
    *info = (socks5_connect_info_t*)malloc(len);
    memcpy((void*)(*info), data, len);
    return SOCKS5_SUCCESS;
}

socks5_error_t socks5_unpack_connect_info_t(socks5_connect_info_t* info, void** data, size_t* len) {
    *len = sizeof(socks5_connect_info_t);
    *data = (socks5_connect_info_t*)malloc(*len);
    memcpy(*data, (void*)info, *len);
    return SOCKS5_SUCCESS;
}

socks5_error_t socks5_pack_connect_resl_t(const void* data, size_t len, socks5_connect_resl_t** resl) {
    if(len != sizeof(socks5_connect_resl_t)) {
        return SOCKS5_ERROR_WRONG_DATA_LEN;
    }
    *resl = (socks5_connect_resl_t*)malloc(len);
    memcpy((void*)(*resl), data, len);
    return SOCKS5_SUCCESS;
}

socks5_error_t socks5_unpack_connect_resl_t(socks5_connect_resl_t* resl, void** data, size_t* len) {
    *len = sizeof(socks5_connect_resl_t);
    *data = (socks5_connect_resl_t*)malloc(*len);
    memcpy(*data, (void*)resl, *len);
    return SOCKS5_SUCCESS;
}

#define _CK_REP(t) (\
    (t) == SOCKS5_CONN_REP_SUCCESS || \
    (t) == SOCKS5_CONN_REP_GENERAL_SERVER_FAILURE || \
    (t) == SOCKS5_CONN_REP_NOT_ALLOWED_BY_RULESET || \
    (t) == SOCKS5_CONN_REP_NETWORK_UNREACHABLE || \
    (t) == SOCKS5_CONN_REP_HOST_UNREACHABLE || \
    (t) == SOCKS5_CONN_REP_CONNECTION_REFUSED || \
    (t) == SOCKS5_CONN_REP_TTL_EXPIRED || \
    (t) == SOCKS5_CONN_REP_CMD_NOT_SUPPORTED || \
    (t) == SOCKS5_CONN_REP_ADDR_TYPE_NOT_SUPPORTED \
)
socks5_error_t socks5_pack_connect_resp_t(const void* data, size_t len, socks5_connect_resp_t** resp) {
    if(len < 6 || len > 262) {
        return SOCKS5_ERROR_WRONG_DATA_LEN;
    }

    *resp = (socks5_connect_resp_t*)malloc(sizeof(socks5_connect_resp_t));
    socks5_connect_resp_t* t = *resp;
    char* dp = (char*)data;
    socks5_error_t err;
    size_t adlen;

    t->ver = *(dp + 0);
    if(t->ver != 5) {
        free(t);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }

    t->rep = *(dp + 1);
    if(!_CK_REP(t->rep)) {
       free(t);
       return SOCKS5_ERROR_WRONG_FORMAT;
    }

    t->rsv = *(dp + 2);
    if(t->rsv != SOCKS5_CONN_RSV) {
        free(t);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }

    t->atyp = *(dp + 3);
    if(t->atyp == SOCKS5_CONN_ATYP_IPV4) {
        err = _convert_into_ipv4(dp + 4, len - 4, t->addr, &adlen);
    } else if(t->atyp == SOCKS5_CONN_ATYP_DOMAIN) {
        err = _convert_into_domain(dp + 4, len - 4, t->addr, &adlen);
    } else if(t->atyp == SOCKS5_CONN_ATYP_IPV6) {
        err = _convert_into_ipv6(dp + 4, len - 4, t->addr, &adlen);
    } else {
        free(t);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }
    if(err != SOCKS5_SUCCESS) {
        free(t);
        return err;
    }

    if(len != 4 + adlen + 2) {
        return SOCKS5_ERROR_WRONG_DATA_LEN;
    }
    unsigned short hb = *(dp + 4 + adlen),
        lb = *(dp + 4 + adlen + 1);
    lb &= (0x00ff);
    hb &= (0x00ff);
    t->port = (hb << 8) + lb;

    return SOCKS5_SUCCESS;
}

socks5_error_t socks5_unpack_connect_resp_t(socks5_connect_resp_t* resp, void** data, size_t* len) {
    *data = malloc(sizeof(socks5_connect_requ_t));
    char* dp = *data;
    socks5_error_t err;
    size_t adlen;

    if(resp->ver != 5) {
        free(dp);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }
    *(dp + 0) = resp->ver;

    if(!_CK_REP(resp->rep)) {
        free(dp);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }
    *(dp + 1) = resp->rep;

    if(resp->rsv != SOCKS5_CONN_RSV) {
        free(dp);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }
    *(dp + 2) = resp->rsv;

    if(resp->atyp == SOCKS5_CONN_ATYP_IPV4) {
        err = _convert_from_ipv4(resp->addr, dp + 4, &adlen);
    } else if(resp->atyp == SOCKS5_CONN_ATYP_DOMAIN) {
        err = _convert_from_domain(resp->addr, dp + 4, &adlen);
    } else if(resp->atyp == SOCKS5_CONN_ATYP_IPV6) {
        err = _convert_from_ipv6(resp->addr, dp + 4, &adlen);
    } else {
        free(dp);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }
    *(dp + 3) = resp->atyp;

    if(err != SOCKS5_SUCCESS) {
        free(dp);
        return err;
    }
    unsigned short hb = (resp->port >> 8),
        lb  = resp->port & 0x00ff;
    *(dp + 4 + adlen) = (char)hb;
    *(dp + 4 + adlen + 1) = (char)lb;

    *len = (4 + adlen + 2);

    void * ret = malloc(*len);
    memcpy(ret, (void*)dp, *len);
    free(dp);
    *data = ret;
    return SOCKS5_SUCCESS;
}
#undef _CK_REP

static socks5_error_t _convert_into_ipv4(const void* data, size_t mlen, char* buffer, size_t* adlen) {
    if(mlen < 4) {
        return SOCKS5_ERROR_WRONG_DATA_LEN;
    }
    int i;
    for(i = 0;i < 4;i ++) {
        buffer[i] = (char)(*((char*)data + i));
    }
    *adlen = 4;
    return SOCKS5_SUCCESS;
}

static socks5_error_t _convert_into_ipv6(const void* data, size_t mlen, char* buffer, size_t* adlen) {
    if(mlen < 16) {
        return SOCKS5_ERROR_WRONG_DATA_LEN;
    }
    int i;
    for(i = 0;i < 16;i ++) {
        buffer[i] = (char)(*((char*)data + i));
    }
    *adlen = 16;
    return SOCKS5_SUCCESS;
}

static socks5_error_t _convert_into_domain(const void* data, size_t mlen, char* buffer, size_t* adlen) {
    if(mlen < 1) {
        return SOCKS5_ERROR_WRONG_DATA_LEN;
    }
    size_t len = (size_t)(*((char*)data + 0));
    if(mlen < 1 + len) {
        return SOCKS5_ERROR_WRONG_DATA_LEN;
    }
    size_t i;
    for(i = 0;i <= len;i ++) {
        buffer[i] = (char)(*((char*)data + i));
    }
    *adlen = len + 1;

    return SOCKS5_SUCCESS;
}

static socks5_error_t _convert_from_ipv4(const char* buffer, void* data, size_t* len) {
    *len = 4;
    int i;
    for(i = 0;i < 4;i ++) {
        *((char*)data + i) = buffer[i];
    }
    return SOCKS5_SUCCESS;
}

static socks5_error_t _convert_from_ipv6(const char* buffer, void* data, size_t* len) {
    *len = 16;
    int i;
    for(i = 0;i < 16;i ++) {
        *((char*)data + i) = buffer[i];
    }
    return SOCKS5_SUCCESS;
}

static socks5_error_t _convert_from_domain(const char* buffer, void* data, size_t* len) {
    *len = (size_t)buffer[0] + 1;
    size_t i;
    for(i = 0;i < *len;i ++) {
        *((char*)data + i) = buffer[i];
    }
    return SOCKS5_SUCCESS;
}

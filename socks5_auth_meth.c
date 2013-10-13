#include "socks5.h"

socks5_error_t socks5_proc_auth_meth(const void* requ, size_t requ_len, void** resp, size_t* resp_len) {
    socks5_error_t err;
    size_t i;
    int method_id;
    socks5_auth_meth_requ_t* requ_struct;
    static socks5_auth_meth_resp_t resp_struct;

    err = socks5_pack_auth_meth_requ_t(requ, requ_len, &requ_struct);
    if(err != SOCKS5_SUCCESS) {
        return err;
    }

    for(i = 0;i < (size_t)requ_struct->nmethods;i ++) {
        method_id = (short)requ_struct->methods[i];
        if(method_id == SOCKS5_AUTH_METH_NO_AUTH) {
            resp_struct.ver = 5;
            resp_struct.method = SOCKS5_AUTH_METH_NO_AUTH;

            err = socks5_unpack_auth_meth_resp_t(&resp_struct, resp, resp_len);
            if(err != SOCKS5_SUCCESS) {
                return err;
            }
            return SOCKS5_SUCCESS;
        }
    }

    resp_struct.ver = 5;
    resp_struct.method = SOCKS5_AUTH_METH_DENIED;

    err = socks5_unpack_auth_meth_resp_t(&resp_struct, resp, resp_len);
    if(err != SOCKS5_SUCCESS) {
        return err;
    }
    return SOCKS5_SUCCESS;
}


socks5_error_t socks5_pack_auth_meth_requ_t(const void* data, size_t len, socks5_auth_meth_requ_t** requ) {
    if(len < 2 || len > 257) {
        return SOCKS5_ERROR_WRONG_DATA_LEN;
    }

    *requ = (socks5_auth_meth_requ_t*)malloc(sizeof(socks5_auth_meth_requ_t));

    socks5_auth_meth_requ_t* t = *requ;
    char * dp = (char*)data;
    size_t i;

    t->ver = *(dp + 0);
    if(t->ver != 5) {
        free(*requ);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }

    t->nmethods = (size_t)(*(dp + 1));
    if(t->nmethods + 2 != len) {
        free(*requ);
        return SOCKS5_ERROR_WRONG_DATA_LEN;
    }

    for(i = 0;i < t->nmethods;i ++) {
        t->methods[i] = *(dp + 2 + i);
    }

    return SOCKS5_SUCCESS;
}

socks5_error_t socks5_unpack_auth_meth_requ_t(const socks5_auth_meth_requ_t* requ, void** data, size_t* len) {
    size_t tot_len = 2 + requ->nmethods;
    size_t i;

    *len = tot_len;
    *data = malloc(tot_len);

    char* dp = (char*)(*data);

    if(requ->ver != 5) {
        free(dp);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }
    *(dp + 0) = requ->ver;

    *(dp + 1) = (char)(requ->nmethods);

    for(i = 0;i < requ->nmethods;i ++) {
        *(dp + 2 + i) = requ->methods[i];
    }

    return SOCKS5_SUCCESS;
}

socks5_error_t socks5_pack_auth_meth_resp_t(const void* data, size_t len, socks5_auth_meth_resp_t** resp) {
    if(len != 2) {
        return SOCKS5_ERROR_WRONG_DATA_LEN;
    }

    *resp = (socks5_auth_meth_resp_t*)malloc(sizeof(socks5_auth_meth_resp_t));

    socks5_auth_meth_resp_t* t = *resp;
    char* dp = (char*)data;

    t->ver = *(dp + 0);
    if(t->ver != 5) {
        free(t);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }

    t->method = *(dp + 1);

    return SOCKS5_SUCCESS;
}

socks5_error_t socks5_unpack_auth_meth_resp_t(const socks5_auth_meth_resp_t* resp, void** data, size_t* len) {
    *len = 2;
    *data = malloc(*len);

    char* dp = (char*)(*data);
    if(resp->ver != 5) {
        free(dp);
        return SOCKS5_ERROR_WRONG_FORMAT;
    }
    *(dp + 0) = resp->ver;
    *(dp + 1) = resp->method;

    return SOCKS5_SUCCESS;
}


socks5_error_t socks5_get_auth_meth_func(short auth_meth_id, socks5_data_proc_func_t* func) {
    socks5_data_proc_func_t ret;
    switch(auth_meth_id) {
        case SOCKS5_AUTH_METH_NO_AUTH:
            ret = socks5_auth_meth_no_auth;
            break;
        default:
            return SOCKS5_ERROR_AUTH_METH_NOT_FOUND;
    }
    *func = ret;
    return SOCKS5_SUCCESS;
}

socks5_error_t socks5_auth_meth_no_auth(const void* indat, size_t inlen, void** outdat, size_t* outlen) {
    *outdat = NULL;
    *outlen = 0;

    return SOCKS5_AUTH_SUCCESS;
}

socks5_error_t socks5_auth_meth_usr_psw(const void* indat, size_t inlen, void** outda, size_t* outlen) {
    /* Not implemented */
    return SOCKS5_AUTH_DENIED;
}

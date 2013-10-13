#include "socks5.h"

/* general util functions impelemented here */
socks5_error_t socks5_get_func_id(socks5_data_proc_func_t func, socks5_func_id_t* id) {
    socks5_func_id_t ret;

    if(func == socks5_proc_auth_meth) {
        ret = SOCKS5_FUNC_ID_AUTH_METH;
    } else if(func == socks5_proc_connect_check) {
        ret = SOCKS5_FUNC_ID_CONNECT_CHECK;
    } else if(func == socks5_proc_connect_resp) {
        ret = SOCKS5_FUNC_ID_CONNECT_RESP;
    } else if(func == socks5_auth_meth_no_auth) {
        ret = SOCKS5_FUNC_ID_AUTH_METH_NO_AUTH;
    } else if(func == socks5_auth_meth_usr_psw) {
        ret = SOCKS5_FUNC_ID_AUTH_METH_USR_PSW;
    } else if(func == socks5_data_convert_connect_0) {
        ret = SOCKS5_FUNC_ID_DCFUNC_CONNECT_0;
    } else if(func == socks5_data_convert_connect_1) {
        ret = SOCKS5_FUNC_ID_DCFUNC_CONNECT_1;
    }else {
        return SOCKS5_ERROR_FUNCTION_NOT_FOUND;
    }

    *id = ret;
    return SOCKS5_SUCCESS;
}

socks5_error_t socks5_get_func_by_id(socks5_func_id_t id, socks5_data_proc_func_t* func) {
    socks5_data_proc_func_t ret;
    switch(id) {
        case SOCKS5_FUNC_ID_AUTH_METH:
            ret = socks5_proc_auth_meth;
            break;
        case SOCKS5_FUNC_ID_CONNECT_CHECK:
            ret = socks5_proc_connect_check;
            break;
        case SOCKS5_FUNC_ID_CONNECT_RESP:
            ret = socks5_proc_connect_resp;
            break;
        case SOCKS5_FUNC_ID_AUTH_METH_NO_AUTH:
            ret = socks5_auth_meth_no_auth;
            break;
        case SOCKS5_FUNC_ID_AUTH_METH_USR_PSW:
            ret = socks5_auth_meth_usr_psw;
            break;
        case SOCKS5_FUNC_ID_DCFUNC_CONNECT_0:
            ret = socks5_data_convert_connect_0;
            break;
        case SOCKS5_FUNC_ID_DCFUNC_CONNECT_1:
            ret = socks5_data_convert_connect_1;
            break;
        default:
            return SOCKS5_ERROR_FUNC_ID_NOT_FOUND;
    }

    *func = ret;
    return SOCKS5_SUCCESS;
}

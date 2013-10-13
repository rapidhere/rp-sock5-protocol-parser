#ifndef SOCKS5_H_INCLUDED
#define SOCKS5_H_INCLUDED

#include <unistd.h>
#include <stdlib.h>

/* All error code define here
 * The possible return code of all functions are these
*/
typedef unsigned short socks5_error_t;
#define SOCKS5_SUCCESS                          0
#define SOCKS5_ERROR_WRONG_FORMAT               1                       // The data was dropped beacause of wrong format
#define SOCKS5_ERROR_WRONG_DATA_LEN             2                       // The data length of data is too long or too short when transfer or untransfer
#define SOCKS5_ERROR_FUNCTION_NOT_FOUND         3                       // Cannot found the function when get function id
#define SOCKS5_ERROR_FUNC_ID_NOT_FOUND          4                       // Cannot found the func_id when get function
#define SOCKS5_ERROR_AUTH_METH_NOT_FOUND        5                       // Cannot found specific authentiaction method function
#define SOCKS5_ERROR_DATA_CONV_NOT_FOUND        6                       // Cannot found specific data convert function
#define SOCKS5_AUTH_METH_SUCCESS                (SOCKS5_SUCCESS)        // Found the Authentication method
#define SOCKS5_AUTH_METH_FAILED                 7                       // Cannot found the authentication method
#define SOCKS5_AUTH_SUCCESS                     (SOCKS5_SUCCESS)        // Authentication succesfully
#define SOCKS5_AUTH_DENIED                      8                       // Authentiaction failed
#define SOCKS5_CONN_CHECK_SUCCESS               (SOCKS5_SUCCESS)        // Can make further connect
#define SOCKS5_CONN_CHECK_FAILED                9                       // Cannot make further connect
#define SOCKS5_CONN_RESP_SUCCESS                (SOCKS5_SUCCESS)        // Can make further connect
#define SOCKS5_CONN_RESP_DENIED                 10                      // Cannot make further connect

/* This part define the function id for data process functions
 * each data process function has its own unqiue id
*/
typedef unsigned short socks5_func_id_t;

/* Standard Callback Data Process Function Type */
typedef socks5_error_t (*socks5_data_proc_func_t)(const void* requ, size_t requ_len, void** resp_data, size_t* resp_len);

socks5_error_t socks5_get_func_id(socks5_data_proc_func_t, socks5_func_id_t*);
socks5_error_t socks5_get_func_by_id(socks5_func_id_t, socks5_data_proc_func_t*);



/* This Part Define the first step of socks5
 * Client need to retrieve a authentication method from server
 * So far we only support NO_AUTH
*/
#define SOCKS5_AUTH_METH_NO_AUTH    0x00
#define SOCKS5_AUTH_METH_GSSAPI     0x01        // Won't be supported in a coming long period
#define SOCKS5_AUTH_METH_USR_PSW    0x02        // Not implemented
#define SOCKS5_AUTH_METH_DENIED     0xFF        // the authentication is denied

#define MAX_AUTH_METH_REQU_NMETHOD 255

/* the auth meth require*/
typedef struct _SOCKS5_AUTH_METH_REQU {
    char ver;
    size_t nmethods;
    char methods[MAX_AUTH_METH_REQU_NMETHOD];
} socks5_auth_meth_requ_t;

socks5_error_t socks5_pack_auth_meth_requ_t(const void*, size_t, socks5_auth_meth_requ_t**);
socks5_error_t socks5_unpack_auth_meth_requ_t(const socks5_auth_meth_requ_t*, void**, size_t*);


/* the auth meth resp */
typedef struct _SOCKS5_AUTH_METH_RESP {
    char ver;
    char method;
} socks5_auth_meth_resp_t;

socks5_error_t socks5_pack_auth_meth_resp_t(const void*, size_t, socks5_auth_meth_resp_t**);
socks5_error_t socks5_unpack_auth_meth_resp_t(const socks5_auth_meth_resp_t*, void**, size_t*);

/* This funtion is used to find out the authentication method with the client
*  Input a require and return SOCKS5_AUTH_METH_SUCCESS for found the authentication method
*  and return SOCKS5_AUTH_METH_FAILED for cannot found the authencation and write the a dennied resp into pointer
*  and for other return code, there's other thing wrong while processing the data, and nothing will write into pointer
*/
#define SOCKS5_FUNC_ID_AUTH_METH 1
socks5_error_t socks5_proc_auth_meth(const void* , size_t, void**, size_t*);

/* get authentication function */
socks5_error_t socks5_get_auth_meth_func(short, socks5_data_proc_func_t*);

/* the authentication function's return data in pointer is used to send to server
 * you should check if these data is null and then don't send it
 * the function will return SOCKS5_AUTH_SUCCESS if authenticate successfully
 * return SOCKS5_AUTH_DENIED if authenticate failed
 * or other code to indicate errors
*/
#define SOCKS5_FUNC_ID_AUTH_METH_NO_AUTH 2
socks5_error_t socks5_auth_meth_no_auth(const void*, size_t, void**, size_t*);
#define SOCKS5_FUNC_ID_AUTH_METH_USR_PSW 3
socks5_error_t socks5_auth_meth_usr_psw(const void*, size_t, void**, size_t*);          // Not support in current version



/* After authentication, client can request a connect to the destination
 * first the client send the request, and proxy server will check the request is legal or not
 * if the request is legal, then we'll make further connection
*/
#define SOCKS5_CONN_RSV 0x00                // The RSV Field of SOCKS5

/* Requeset cmds */
#define SOCKS5_CONN_CMD_CONNECT        0x01
#define SOCKS5_CONN_CMD_BIND           0x02        // Not supported
#define SOCKS5_CONN_CMD_UDP_ASSOCIATE  0x03

/* The address type */
#define SOCKS5_CONN_ATYP_IPV4          0x01
#define SOCKS5_CONN_ATYP_DOMAIN        0x03
#define SOCKS5_CONN_ATYP_IPV6          0x04

/* The reply code */
#define SOCKS5_CONN_REP_SUCCESS                        0x00
#define SOCKS5_CONN_REP_GENERAL_SERVER_FAILURE         0x01
#define SOCKS5_CONN_REP_NOT_ALLOWED_BY_RULESET         0x02
#define SOCKS5_CONN_REP_NETWORK_UNREACHABLE            0x03
#define SOCKS5_CONN_REP_HOST_UNREACHABLE               0x04
#define SOCKS5_CONN_REP_CONNECTION_REFUSED             0x05
#define SOCKS5_CONN_REP_TTL_EXPIRED                    0x06
#define SOCKS5_CONN_REP_CMD_NOT_SUPPORTED              0x07
#define SOCKS5_CONN_REP_ADDR_TYPE_NOT_SUPPORTED        0x08

/* The connection type */
#define SOCKS5_CONN_TYPE_TCP   0x00
#define SOCKS5_CONN_TYPE_UDP   0x01

#define SOCKS5_MAX_DOMAIN_LEN 255

/* the connection require send from client */
typedef struct _SOCKS5_CONNECT_REQU {
    char ver;
    char cmd;
    char rsv;
    char atyp;
    char addr[SOCKS5_MAX_DOMAIN_LEN + 1];       // Note: without termiate '\0'; the extra space is used to store the length of domain
    unsigned short port;
} socks5_connect_requ_t;

socks5_error_t socks5_pack_connect_requ_t(const void*, size_t, socks5_connect_requ_t**);
socks5_error_t socks5_unpack_connect_requ_t(socks5_connect_requ_t*, void**, size_t*);

/* if the connection requeset is legal, then return the connect info back to program */
typedef struct _SOCKS5_CONNECT_INFO {
    short type;           // SOCKS5_CONN_TYPE_TCP or SOCKS5_CONN_TYPE_UDP
    short addr_type;
    size_t addr_len;
    char addr[SOCKS5_MAX_DOMAIN_LEN + 1];
    unsigned short port;
} socks5_connect_info_t;

socks5_error_t socks5_pack_connect_info_t(const void*, size_t, socks5_connect_info_t**);
socks5_error_t socks5_unpack_connect_info_t(socks5_connect_info_t*, void**, size_t*);

/* The connect result */
typedef struct _SOCKS5_CONNECT_RESL {
    char rep;                               // one of the code in SOCKS5_CONN_REP_*
    short addr_type;
    size_t addr_len;
    char addr[SOCKS5_MAX_DOMAIN_LEN + 1];
    unsigned short port;
} socks5_connect_resl_t;

socks5_error_t socks5_pack_connect_resl_t(const void*, size_t, socks5_connect_resl_t**);
socks5_error_t socks5_unpack_connect_resl_t(socks5_connect_resl_t*, void**, size_t*);

/* The response send back to client */
typedef struct _SOCKS5_CONNECT_RESP {
    char ver;
    char rep;
    char rsv;
    char atyp;
    char addr[SOCKS5_MAX_DOMAIN_LEN + 1];
    unsigned short port;
} socks5_connect_resp_t;

socks5_error_t socks5_pack_connect_resp_t(const void*, size_t, socks5_connect_resp_t**);
socks5_error_t socks5_unpack_connect_resp_t(socks5_connect_resp_t*, void**, size_t*);

/* This function handle a client connect requirment
*  And check if the requirment is correct
*  If the requirment is correct, it'll return SOCKS5_CONN_CHECK_SUCCESS, and write a info_struct into pointer
*  which can use to indicate further connect
*  If the requirement is something wrong, it'll return SOCKS5_CONN_FAILED, and write a resp_struct into pointer
*  and the server need to send back the response. The common scence for this return code is the format of require
*  is correct but we don't support it
*  Finally, for other return code, there is something wrong with the requiement and the nothing will write into pointer
*/
#define SOCKS5_FUNC_ID_CONNECT_CHECK 4
socks5_error_t socks5_proc_connect_check(const void*, size_t, void**, size_t*);

/* This function handle a socket info(socks5_connect_resl_t) and build up the response for responsing
 * If there's further connect, it will reutrn SOCKS5_CONN_RESP_SUCCESS and the resp will write into pointer
 * If there's no further connect, it will return SOCKS5_CONN_RESP_DENIED and the resp will wirte into pointer
 * If anything else wrong, it will return specified code and nothing will wirte into pointer
*/
#define SOCKS5_FUNC_ID_CONNECT_RESP 5
socks5_error_t socks5_proc_connect_resp(const void*, size_t, void**, size_t*);



/* After the proxy server connect to the remote server, we can trasnfer data between client and remote server
 * for each SOCKS5_CONN_CMD_*, a pair of function is provided,
 * one for client to remote
 * and another for remote to client
 * for each data proc function, if data convert success, return SOCKS5_SUCCESS
 * else return specific error code
*/
socks5_error_t socks5_get_data_convert_func_pair(short, socks5_data_proc_func_t* ,socks5_data_proc_func_t*);

/* For SOCKS5_CONN_CMD_CONNECT */
#define SOCKS5_FUNC_ID_DCFUNC_CONNECT_0 6   // for client to remote
socks5_error_t socks5_data_convert_connect_0(const void*, size_t, void**, size_t*);
#define SOCKS5_FUNC_ID_DCFUNC_CONNECT_1 7   // for remote to client
socks5_error_t socks5_data_convert_connect_1(const void*, size_t, void**, size_t*);
#endif // SOCKS5_H_INCLUDED

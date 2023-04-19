#include "buf.h"
#include "net.h"
#include "icmp.h"
#include "ip.h"
#include "utils.h"
#include <stdint.h>
#include <string.h>
#include <windef.h>

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    // TO-DO
    buf_init(&txbuf, req_buf->len);
    icmp_hdr_t *hdr1 = (icmp_hdr_t *)(req_buf->data);
    icmp_hdr_t *hdr2 = (icmp_hdr_t *)(txbuf.data);
    hdr2->type = ICMP_TYPE_ECHO_REPLY;
    hdr2->code = 0;
    hdr2->checksum16 = 0;
    hdr2->id16 = hdr1->id16;
    hdr2->seq16 = hdr1->seq16;
    memcpy(txbuf.data+sizeof(icmp_hdr_t), req_buf->data+sizeof(icmp_hdr_t), req_buf->len-sizeof(icmp_hdr_t));
    hdr2->checksum16 = checksum16((uint16_t *)hdr2, req_buf->len);

    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    //接收到的包长度小于icmp报头长度则不处理
    if(buf->len < sizeof(icmp_hdr_t)) return;

    //如果是回显请求则会送一个回显应答
    icmp_hdr_t *hdr = (icmp_hdr_t *)buf->data;
    if(hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // TO-DO
    ip_hdr_t *ip_hdr = (ip_hdr_t *)recv_buf->data;
    int ip_hdr_len = (ip_hdr->hdr_len)*4;

    buf_init(&txbuf, sizeof(icmp_hdr_t)+ip_hdr_len+8);
    icmp_hdr_t *hdr = (icmp_hdr_t *)(txbuf.data);
    
    hdr->type = 3;
    hdr->code = code;
    hdr->id16 = 0;
    hdr->seq16 = 0;
    hdr->checksum16 = 0;

    //指针加偏移要转成void *，不然每个偏移都是这个指针类型的长度
    memcpy((void *)hdr+sizeof(icmp_hdr_t), ip_hdr, ip_hdr_len);
    
    memcpy((void *)hdr+sizeof(icmp_hdr_t)+ip_hdr_len, (void *)ip_hdr+ip_hdr_len, 8);
    hdr->checksum16 = checksum16((uint16_t *)hdr, sizeof(icmp_hdr_t)+ip_hdr_len+8);

    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}
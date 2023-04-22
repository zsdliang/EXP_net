#include "udp.h"
#include "buf.h"
#include "ip.h"
#include "icmp.h"
#include "net.h"
#include "utils.h"
#include <stdint.h>
#include <string.h>

/**
 * @brief udp处理程序表
 * 
 */
map_t udp_table;

/**
 * @brief udp伪校验和计算
 * 
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dst_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    // TO-DO
    //拷贝ip头部
    ip_hdr_t ip_hdr;
    memcpy(&ip_hdr,buf->data-sizeof(ip_hdr_t),sizeof(ip_hdr_t));
    udp_hdr_t *udp_hdr = (udp_hdr_t *)buf->data;
    uint16_t udp_len = swap16(udp_hdr->total_len16);
    //增加伪头部
    buf_add_header(buf, sizeof(udp_peso_hdr_t));
    udp_peso_hdr_t *peso_hdr = (udp_peso_hdr_t *)buf->data;
    memcpy(peso_hdr->src_ip,src_ip,NET_IP_LEN);
    memcpy(peso_hdr->dst_ip, dst_ip, NET_IP_LEN);
    peso_hdr->placeholder = 0;
    peso_hdr->protocol = ip_hdr.protocol;//发送的时候没有IP头怎么办？
    peso_hdr->total_len16 = swap16(udp_len);
    //数据长度为奇数则需要填充
    if(udp_len %2 == 1) {
        buf_add_padding(buf, 1);
    }
    uint16_t checksum = checksum16((uint16_t *)peso_hdr, sizeof(udp_peso_hdr_t)+(((udp_len+1)>>1)<<1));//向上取整
    if(udp_len % 2 == 1) {
        buf_remove_padding(buf, 1);
    }

    buf_remove_header(buf, sizeof(udp_peso_hdr_t));
    memcpy(buf->data-sizeof(ip_hdr_t), &ip_hdr, sizeof(ip_hdr_t));

    return checksum;
}

/**
 * @brief 处理一个收到的udp数据包
 * 
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    udp_hdr_t *hdr = (udp_hdr_t *)buf->data;
    if(buf->len < sizeof(udp_hdr_t) || buf->len < swap16(hdr->total_len16)) return;

    uint16_t checksum_keep = hdr->checksum16;
    hdr->checksum16 = 0;
    hdr->checksum16 = udp_checksum(buf, src_ip, net_if_ip);
    if(checksum_keep != hdr->checksum16) return;
    uint16_t dstport = swap16(hdr->dst_port16);
    udp_handler_t *handler = map_get(&udp_table, &dstport);
    if (handler)
    {
        buf_remove_header(buf,sizeof(udp_hdr_t));
        (*handler)(buf->data,swap16(hdr->total_len16),src_ip,swap16(hdr->src_port16));
    } else {
        buf_add_header(buf, sizeof(ip_hdr_t));

        icmp_unreachable(buf, src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    // TO-DO
    buf_add_header(buf, sizeof(udp_hdr_t));
    udp_hdr_t *hdr = (udp_hdr_t *)buf->data;
    hdr->src_port16 = swap16(src_port);
    hdr->dst_port16 = swap16(dst_port);
    hdr->checksum16 = 0;
    hdr->total_len16 = swap16(buf->len);
    hdr->checksum16 = udp_checksum(buf, net_if_ip, dst_ip);
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 * 
 */
void udp_init()
{
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 * 
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 * 
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 * 
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}
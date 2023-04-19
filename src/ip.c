#include "buf.h"
#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"
#include "utils.h"
#include <stdint.h>
#include <string.h>

uint32_t pkg_id;
uint32_t ip_data_max_len = 1500-sizeof(ip_hdr_t); 
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;

    //数据包长度小于ip头部长度则不处理
    if(buf->len < sizeof(ip_hdr_t)) return;

    //检验checksum
    uint16_t checkSum = hdr->hdr_checksum16;
    hdr->hdr_checksum16 = 0;
    hdr->hdr_checksum16 = checksum16((uint16_t *)hdr, hdr->hdr_len*4);
    //前后checksum不一致则不处理
    if(checkSum != hdr->hdr_checksum16) {
        return;
    }

    //数据包目的ip地址若不是本机地址则不处理
    if(memcmp(hdr->dst_ip,net_if_ip,NET_IP_LEN)) {
        return ;
    }

    //检查是否有填充
    if(buf->len > swap16(hdr->total_len16)) {
        buf_remove_padding(buf, buf->len - swap16(hdr->total_len16));
    }


    uint16_t protocol = hdr->protocol;
    
    //去掉ip报头
    buf_remove_header(buf, hdr->hdr_len*4);

    //其实有bug，去除hdr后hdr应不可用，但由于实际去除hdr只是移动数组下标，并不会有其它进程占用释放的空间，故hdr可继续使用
    if(net_in(buf, protocol, hdr->src_ip)==-1) {
        //未知协议则返回ICMP协议不可达信息
        buf_add_header(buf, hdr->hdr_len*4);
        icmp_unreachable(buf, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    //增加ip数据报头部
    buf_add_header(buf, sizeof(ip_hdr_t));

    //填写头部
    ip_hdr_t * hdr = (ip_hdr_t *)buf->data;
    hdr->hdr_len = sizeof(ip_hdr_t)/4;
    hdr->version = IP_VERSION_4;
    hdr->tos = 0;
    hdr->total_len16 = swap16(buf->len);
    hdr->id16 = swap16(id);
    hdr->flags_fragment16 = swap16((mf<<13)+offset);
    hdr->ttl = 64;
    hdr->protocol = protocol;
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);
    hdr->hdr_checksum16 = 0;
    hdr->hdr_checksum16 = checksum16((uint16_t *)hdr, hdr->hdr_len*4);
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    //检查上层传下来的数据包大小是否小于IP数据包最大大小
    if(buf->len <= ip_data_max_len) {
        ip_fragment_out(buf, ip, protocol, pkg_id++, 0, 0);
    } else {
        int offset = 0;
        int last;
        buf_t ip_buf;
        while(offset < buf->len) {
            last = (offset+ip_data_max_len) > buf->len?1:0;
            buf_init(&ip_buf, last?buf->len-offset:ip_data_max_len);
            memcpy(ip_buf.data, buf->data+offset, last?buf->len-offset:ip_data_max_len);
            ip_fragment_out(&ip_buf, ip, protocol, pkg_id, offset>>3, last?0:1);
            offset+=ip_data_max_len;
        }
        pkg_id++;
    }
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
    pkg_id = 0;
}
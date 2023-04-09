#include "ethernet.h"
#include "buf.h"
#include "config.h"
#include "net.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
#include <stdint.h>
#include <string.h>
uint8_t broad_cast_mac[NET_MAC_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
uint8_t my_mac_ethnet[NET_MAC_LEN] = NET_IF_MAC; 
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    // TO-DO
    if(buf->len < sizeof(ether_hdr_t)) {
        fprintf(stderr,"error,package length less than earth-net header length");
        return;
    }
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    uint16_t protocol16 = swap16(hdr->protocol16);
    uint8_t dst[NET_MAC_LEN];
    uint8_t src[NET_MAC_LEN];
    memcpy(dst,hdr->dst,NET_MAC_LEN);
    memcpy(src,hdr->src,NET_MAC_LEN);
    buf_remove_header(buf, sizeof(ether_hdr_t));
    
    if(!memcmp(dst,broad_cast_mac,NET_MAC_LEN)||!memcmp(dst,my_mac_ethnet,NET_MAC_LEN)) {
        net_in(buf, protocol16, src);
    }
}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    // TO-DO
    //padding if less than 46 byte
    if(buf->len < 46) {
        buf_add_padding(buf, 46-buf->len);
    }
    //creat earth net header
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    memcpy(hdr->dst, mac,NET_MAC_LEN);
    memcpy(hdr->src, my_mac_ethnet,NET_MAC_LEN);
    hdr->protocol16=swap16(protocol);
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 * 
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}

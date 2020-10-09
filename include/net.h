#ifndef _Net_H
#define _Net_H

#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#ifndef _TYPEDEF_STRUCT_NET
#define _TYPEDEF_STRUCT_NET
typedef struct net Net;
#endif

typedef enum operators {
    UNKN_OPR = 0,
    TM,
    CHT,
    VRZ,
    APTG,
    SD, /* SIPdroid */
    ATT
} Opr;

typedef enum proto {
    UNKN_PROTO = 0,

    IPv4 = IPPROTO_IP,
    IPv6 = IPPROTO_IPV6,

    ESP = IPPROTO_ESP,

    TCP = IPPROTO_TCP,
    UDP = IPPROTO_UDP
} Proto;

struct net {
    /* IP version, can be IPv4 or IPv6 */
    Opr opr;
    Proto ipv;

    char *src_ip;
    char *dst_ip;

    char *x_src_ip; /* Expected src IP addr */
    char *x_dst_ip; /* Expected dst IP addr */

    char *tmp_dst_ip; /*  */
    uint32_t tmp_esp_seq; /*  */

    union {
        struct iphdr ip4hdr;
        struct ip6_hdr ip6hdr;
    };

    size_t hdrlen;
    uint16_t plen;
    union {
        Proto pro;
        Proto nxt;
    };

    char *(*set_ip)(Net *self, char *ip);
    char *(*set_ip6)(Net *self, char *ip6);
    struct ip6_hdr *(*set_hdr)(Net *self, void *structptr, Proto p);
    uint8_t *(*dissect)(Net *self, uint8_t *pkt, size_t pkt_len);
    Net *(*fmt_rep)(Net *self);
    void (*show_info)(Net *self);
};


void init_net(Net *self, char *opr);


char *set_ip_addr(Net *self, char *ip);


char *set_ip6_addr(Net *self, char *ip6);


struct ip6_hdr *set_ip6hdr(Net *self, void *structptr, Proto p);

/**
 * dissect_net()
 * Dissect Net packets, includes Net packet header and packet payload. Return
 * a pointer point to the begining of next header in @pkt if success, otherwise
 * NULL is returned.
 *
 * @self: to be filled Net structure
 * @pkt: pointer point to the begining of Net packet header
 * @pkt_len: packet length from packet header to the end of packet
 */
uint8_t *dissect_ip4(Net *self, uint8_t *pkt, size_t pkt_len);

uint8_t *dissect_ip6(Net *self, uint8_t *pkt, size_t pkt_len);

Net *fmt_net_rep(Net *self);

uint8_t *l2_set_ip_pos(Net *self, uint8_t *data);

void get_ipsec_tnl_info(Net *self);

void show_pkt_info(Net *self);

#endif

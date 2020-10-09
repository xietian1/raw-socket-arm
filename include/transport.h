#ifndef _TRANSPORT_H
#define _TRANSPORT_H

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "net.h"
#include "utils.h"

#define UDP_MAXDATAGRAM \
    IP_MAXPACKET - sizeof(struct ip6_hdr) - sizeof(struct udphdr)

#define TCP_MAXSEGMENT \
    IP_MAXPACKET - sizeof(struct ip6_hdr) - sizeof(struct tcphdr)

#ifndef _TYPEDEF_STRUCT_TXP
#define _TYPEDEF_STRUCT_TXP
typedef struct txp Txp;
#endif

struct txp {
    Proto p;

    uint16_t x_src_port; /* Expected src port to CSCF */
    uint16_t x_dst_port; /* Expected dst port to CSCF */

    uint32_t x_tx_seq; /* Expected tx sequence number */
    uint32_t x_tx_ack; /* Expected tx acknowledge number */

    struct tcphdr thdr;
    struct udphdr uhdr;
    uint8_t hdrlen;

    uint8_t *pl;
    uint16_t plen;


    uint8_t *(*set_pl)(Txp *self, uint8_t *data, size_t plen);
    ssize_t (*fmt_txp_data)(Txp *self, uint8_t *buf, size_t buflen);
    uint8_t *(*dissect)(Net *net, Txp *self, uint8_t *txp_data, Proto p, size_t txp_len);
    Txp *(*fmt_rep)(Txp *self, Net *net, uint8_t *data, size_t dlen);
    void (*show_info)(Txp *self);
};
uint16_t chksum (uint16_t *addr, int len);

uint16_t cal_ipv4_cksm(struct iphdr iphdr);

void init_txp(Txp *self);

int passive_tcp(char *port);

int active_tcp(char *dst, char *port);

/* Copy the content in b to a */
Txp *cpy_txp(Txp *a, Txp *b);

void set_txp_info(Txp *self);

uint8_t *set_txp_pl(Txp *self, uint8_t *data, size_t plen);

ssize_t fmt_txp_data(Txp *self, uint8_t *buf, size_t buflen);

uint8_t *dissect_txp(Net *net, Txp *self, uint8_t *txp_data, Proto p, size_t txp_len);

Txp *fmt_txp_rep(Txp *self, Net *net, uint8_t *data, size_t dlen);

int estab_tcp_conn(Mode m, char *ip, char *port);

ssize_t tx_notification(int fd);

ssize_t wait_notification(int fd);

void show_txp_info(Txp *self);

#endif

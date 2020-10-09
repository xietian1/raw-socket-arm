#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "transport.h"
#include "utils.h"

/* Computing the internet checksum (RFC 1071) */
uint16_t chksum (uint16_t *addr, int len)
{
    int count = len;
    uint16_t res;
    register uint32_t sum = 0;

    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    if (count > 0) {
        sum += *(uint8_t *)addr;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    res = ~sum;

    return res;
}

uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    bzero(&iphdr.check, sizeof(iphdr.check));
    return chksum((uint16_t *)&iphdr, sizeof(struct iphdr));
}

static uint16_t cal_tcp4_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    uint8_t buf[IP_MAXPACKET];
    uint8_t *ptr;
    uint8_t ofs_and_resv;
    uint8_t EMPTY[2] = {0};
    uint16_t seglen;
    size_t cksmlen = 0;
    Data preq_info[] = {
        {(uint8_t *)&iphdr.saddr, sizeof(iphdr.saddr)},
        {(uint8_t *)&iphdr.daddr, sizeof(iphdr.daddr)},
        {EMPTY, 1}, /* Reserved 1 bytes */
        {(uint8_t *)&iphdr.protocol, sizeof(iphdr.protocol)},
        {(uint8_t *)&seglen, sizeof(seglen)},

        {(uint8_t *)&tcphdr.th_sport, sizeof(tcphdr.th_sport)},
        {(uint8_t *)&tcphdr.th_dport, sizeof(tcphdr.th_dport)},
        {(uint8_t *)&tcphdr.th_seq, sizeof(tcphdr.th_seq)},
        {(uint8_t *)&tcphdr.th_ack, sizeof(tcphdr.th_ack)},
        {(uint8_t *)&ofs_and_resv, sizeof(ofs_and_resv)},
        {(uint8_t *)&tcphdr.th_flags, sizeof(tcphdr.th_flags)},
        {(uint8_t *)&tcphdr.th_win, sizeof(tcphdr.th_win)},
        {EMPTY, 2}, /* Reserved for TCP checksum */
        {(uint8_t *)&tcphdr.th_urp, sizeof(tcphdr.th_urp)},

        {pl, plen}
    };

    ptr = &buf[0];
    seglen = htons((uint16_t)(sizeof(tcphdr) + plen));
    ofs_and_resv = (tcphdr.th_off << 4) + tcphdr.th_x2;

    for (size_t i = 0; i < sizeof(preq_info) / sizeof(Data); i++) {
        memcpy (ptr, preq_info[i].data, preq_info[i].len);
        ptr += preq_info[i].len;
        cksmlen += preq_info[i].len;
    }

    /* Pad to the next 16-bit boundary */
    for (size_t i = 0; i < plen % 2; i++, ptr++) {
        *ptr = 0;
        ptr++;
        cksmlen++;
    }

    return chksum((uint16_t *)buf, cksmlen);
}

static uint16_t cal_udp4_cksm(struct iphdr iphdr, struct udphdr udphdr, uint8_t *pl, int plen)
{
    uint8_t buf[IP_MAXPACKET];
    uint8_t *ptr;
    uint8_t EMPTY[3] = {0};
    uint16_t datlen;
    size_t cksmlen = 0;
    Data preq_info[] = {
        {(uint8_t *)&iphdr.saddr, sizeof(iphdr.saddr)},
        {(uint8_t *)&iphdr.daddr, sizeof(iphdr.daddr)},
        {EMPTY, 1}, /* 24 bits zero in pseudo-header */
        {(uint8_t *)&iphdr.protocol, sizeof(iphdr.protocol)},
        {(uint8_t *)&datlen, sizeof(datlen)},

        {(uint8_t *)&udphdr.source, sizeof(udphdr.source)},
        {(uint8_t *)&udphdr.dest, sizeof(udphdr.dest)},
        {(uint8_t *)&udphdr.len, sizeof(udphdr.len)},
        {EMPTY, 2}, /* Reserved for UDP checksum */

        {pl, plen}
    };

    ptr = &buf[0];
    datlen = htons((uint16_t)(sizeof(udphdr) + plen));

    for (size_t i = 0; i < sizeof(preq_info) / sizeof(Data); i++) {
        memcpy (ptr, preq_info[i].data, preq_info[i].len);
        ptr += preq_info[i].len;
        cksmlen += preq_info[i].len;
    }

    /* Pad to the next 16-bit boundary */
    for (size_t i = 0; i < plen % 2; i++, ptr++) {
        *ptr = 0;
        ptr++;
        cksmlen++;
    }


    return chksum((uint16_t *)buf, cksmlen);
}

/* Build IPv6 TCP pseudo-header and calculate checksum (8.1 of RFC 2460) */
static uint16_t cal_tcp6_cksm(struct ip6_hdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    uint8_t buf[IP_MAXPACKET];
    uint8_t *ptr;
    uint8_t ofs_and_resv;
    uint8_t EMPTY[3] = {0};
    uint32_t seglen;
    size_t cksmlen = 0;
    Data preq_info[] = {
        {(uint8_t *)&iphdr.ip6_src, sizeof(iphdr.ip6_src)},
        {(uint8_t *)&iphdr.ip6_dst, sizeof(iphdr.ip6_dst)},
        {(uint8_t *)&seglen, sizeof(seglen)},
        {EMPTY, 3}, /* 24 bits zero in pseudo-header */
        {(uint8_t *)&iphdr.ip6_nxt, sizeof(iphdr.ip6_nxt)},

        {(uint8_t *)&tcphdr.th_sport, sizeof(tcphdr.th_sport)},
        {(uint8_t *)&tcphdr.th_dport, sizeof(tcphdr.th_dport)},
        {(uint8_t *)&tcphdr.th_seq, sizeof(tcphdr.th_seq)},
        {(uint8_t *)&tcphdr.th_ack, sizeof(tcphdr.th_ack)},
        {(uint8_t *)&ofs_and_resv, sizeof(ofs_and_resv)},
        {(uint8_t *)&tcphdr.th_flags, sizeof(tcphdr.th_flags)},
        {(uint8_t *)&tcphdr.th_win, sizeof(tcphdr.th_win)},
        {EMPTY, 2}, /* Reserved for TCP checksum */
        {(uint8_t *)&tcphdr.th_urp, sizeof(tcphdr.th_urp)},

        {pl, plen}
    };

    ptr = &buf[0];
    seglen = htonl(sizeof(tcphdr) + plen);
    ofs_and_resv = (tcphdr.th_off << 4) + tcphdr.th_x2;

    for (size_t i = 0; i < sizeof(preq_info) / sizeof(Data); i++) {
        memcpy (ptr, preq_info[i].data, preq_info[i].len);
        ptr += preq_info[i].len;
        cksmlen += preq_info[i].len;
    }

    /* Pad to the next 16-bit boundary */
    for (size_t i = 0; i < plen % 2; i++, ptr++) {
        *ptr = 0;
        ptr++;
        cksmlen++;
    }

    return chksum((uint16_t *)buf, cksmlen);
}

/* Build IPv6 UDP pseudo-header and calculate checksum (8.1 of RFC 2460) */
static uint16_t cal_udp6_cksm(struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *pl, int plen)
{
    uint8_t buf[IP_MAXPACKET];
    uint8_t *ptr;
    uint8_t EMPTY[3] = {0};
    size_t cksmlen = 0;
    Data preq_info[] = {
        {(uint8_t *)&iphdr.ip6_src.s6_addr, sizeof(iphdr.ip6_src.s6_addr)},
        {(uint8_t *)&iphdr.ip6_dst.s6_addr, sizeof(iphdr.ip6_dst.s6_addr)},
        {(uint8_t *)&udphdr.len, sizeof(udphdr.len)},
        {EMPTY, 3}, /* 24 bits zero in pseudo-header */
        {(uint8_t *)&iphdr.ip6_nxt, sizeof(iphdr.ip6_nxt)},

        {(uint8_t *)&udphdr.source, sizeof(udphdr.source)},
        {(uint8_t *)&udphdr.dest, sizeof(udphdr.dest)},
        {(uint8_t *)&udphdr.len, sizeof(udphdr.len)},
        {EMPTY, 2}, /* Reserved for TCP checksum */

        {pl, plen}
    };

    ptr = &buf[0];

    for (size_t i = 0; i < sizeof(preq_info) / sizeof(Data); i++) {
        memcpy (ptr, preq_info[i].data, preq_info[i].len);
        ptr += preq_info[i].len;
        cksmlen += preq_info[i].len;
    }

    /* Pad to the next 16-bit boundary */
    for (size_t i = 0; i < plen % 2; i++, ptr++) {
        *ptr = 0;
        ptr++;
        cksmlen++;
    }

    return chksum((uint16_t *)buf, cksmlen);
}


inline static size_t fmt_tcp_segm(Txp *self, uint8_t *buf)
{
    size_t nb = 0;

    memcpy(buf, &self->thdr, self->hdrlen);
    nb += self->hdrlen;
    memcpy(buf + nb, self->pl, self->plen);
    nb += self->plen;

    return nb;
}


inline static size_t fmt_udp_dgram(Txp *self, uint8_t *buf)
{
    size_t nb = 0;

    memcpy(buf, &self->uhdr, self->hdrlen);
    nb += self->hdrlen;
    memcpy(buf + nb, self->pl, self->plen);
    nb += self->plen;

    return nb;
}


inline static uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    size_t tcphdrlen = sizeof(struct tcphdr);
    if (segm_len < tcphdrlen) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return NULL;
    }

    self->p = IPPROTO_TCP;

    memcpy(&self->thdr, segm, tcphdrlen);
    self->hdrlen = tcphdrlen;

    memcpy(self->pl, segm + tcphdrlen, segm_len - tcphdrlen);
    self->plen = segm_len - tcphdrlen;

    /* Check IP addr & port to determine the next seq and ack value */
    uint32_t p_nxt_seq = htonl(self->thdr.th_ack);
    uint32_t p_nxt_ack = htonl(self->thdr.th_seq) + self->plen;

    if (strcmp(net->src_ip, net->x_dst_ip) == 0 &&
            strcmp(net->dst_ip, net->x_src_ip) == 0 &&
            ntohs(self->thdr.th_sport) == self->x_dst_port &&
            ntohs(self->thdr.th_dport) == self->x_src_port) {
        self->x_tx_seq = p_nxt_seq > self->x_tx_seq ? p_nxt_seq : self->x_tx_seq;
        self->x_tx_ack = p_nxt_ack > self->x_tx_ack ? p_nxt_ack : self->x_tx_ack;
        /*
        self->x_tx_seq = p_nxt_seq;
        self->x_tx_ack = p_nxt_ack;
        */
    }


    return segm + tcphdrlen;
}


inline static uint8_t *dissect_udp(Txp *self, uint8_t *dgram, size_t dgram_len)
{
    size_t udphdrlen = sizeof(struct udphdr);
    if (dgram_len < udphdrlen) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return NULL;
    }

    self->p = IPPROTO_UDP;

    memcpy(&self->uhdr, dgram, udphdrlen);
    self->hdrlen = udphdrlen;

    memcpy(self->pl, dgram + udphdrlen, dgram_len - udphdrlen);
    self->plen = dgram_len - udphdrlen;

    return dgram + udphdrlen;
}


Txp *fmt_tcp4_rep(Txp *self, struct iphdr *iphdr, uint8_t *data, size_t dlen)
{
    self->thdr.th_sport = htons(self->x_src_port);
    self->thdr.th_dport = htons(self->x_dst_port);

    self->thdr.th_seq = htonl(self->x_tx_seq);
    self->thdr.th_ack = htonl(self->x_tx_ack);

    self->x_tx_seq += dlen;
    if (dlen != 0) {
        self->thdr.th_flags |= TH_PUSH;
        memcpy(self->pl, data, dlen);
        self->plen = dlen;
    } else {
        self->thdr.th_flags &= ~TH_PUSH;
        self->plen = 0;
    }

    self->thdr.th_sum = cal_tcp4_cksm(*iphdr, self->thdr, self->pl, self->plen);

    /* th_x2, th_off, th_win and th_urp in tcphdr remain the same from sender */

    return self;
}

Txp *fmt_udp4_rep(Txp *self, struct iphdr *iphdr, uint8_t *data, size_t dlen)
{
    self->uhdr.source = htons(self->x_src_port);
    self->uhdr.dest = htons(self->x_dst_port);

    self->uhdr.len = htons(self->hdrlen + dlen);

    if (dlen != 0) {
        memcpy(self->pl, data, dlen);
        self->plen = dlen;
    } else {
        self->plen = dlen;
    }

    self->uhdr.check = cal_udp4_cksm(*iphdr, self->uhdr, self->pl, self->plen);

    return self;
}

Txp *fmt_tcp_rep(Txp *self, struct ip6_hdr *ip6hdr, uint8_t *data, size_t dlen)
{
    self->thdr.th_sport = htons(self->x_src_port);
    self->thdr.th_dport = htons(self->x_dst_port);

    self->thdr.th_seq = htonl(self->x_tx_seq);
    self->thdr.th_ack = htonl(self->x_tx_ack);

    self->x_tx_seq += dlen;

    if (dlen != 0) {
        self->thdr.th_flags |= TH_PUSH;
        memcpy(self->pl, data, dlen);
        self->plen = dlen;
    } else {
        self->thdr.th_flags &= ~TH_PUSH;
        self->plen = 0;
    }

    self->thdr.th_sum = cal_tcp6_cksm(*ip6hdr, self->thdr, self->pl, self->plen);

    /* th_x2, th_off, th_win and th_urp in tcphdr remain the same from sender */

    return self;
}


Txp *fmt_udp_rep(Txp *self, struct ip6_hdr *ip6hdr, uint8_t *data, size_t dlen)
{
    swap_uint16(&self->uhdr.source, &self->uhdr.dest);
    self->uhdr.len = htons(self->hdrlen + dlen);

    if (dlen != 0) {
        memcpy(self->pl, data, dlen);
        self->plen = dlen;
    } else {
        self->plen = dlen;
    }

    self->uhdr.check = cal_udp6_cksm(*ip6hdr, self->uhdr, self->pl, self->plen);

    return self;
}


static void show_tcp_info(Txp *self)
{
    puts("Tranport layer: TCP");

    printf("Src port: %u\n", ntohs(self->thdr.th_sport));
    printf("Dst port: %u\n", ntohs(self->thdr.th_dport));

    printf("TCP sequence: ");
    output_hex_from_bin((uint8_t *)&self->thdr.th_seq, sizeof(uint32_t));
    puts("");

    printf("TCP Ack: ");
    output_hex_from_bin((uint8_t *)&self->thdr.th_ack, sizeof(uint32_t));
    puts("");

    printf("TCP offset: %02x\n", self->thdr.th_off << 4 | self->thdr.th_x2);

    printf("TCP flags: ");
    output_hex_from_bin((uint8_t *)&self->thdr.th_flags, sizeof(uint8_t));
    puts("");

    printf("TCP win: ");
    output_hex_from_bin((uint8_t *)&self->thdr.th_win, sizeof(uint16_t));
    puts("");

    printf("TCP urgent pointer: ");
    output_hex_from_bin((uint8_t *)&self->thdr.th_urp, sizeof(uint16_t));
    puts("");

    printf("TCP checksum: ");
    output_hex_from_bin((uint8_t *)&self->thdr.th_sum, sizeof(uint16_t));
    puts("");
}


static void show_udp_info(Txp *self)
{
    puts("Tranport layer: UDP");

    printf("Src port: %u\n", ntohs(self->uhdr.source));
    printf("Dst port: %u\n", ntohs(self->uhdr.dest));

    printf("UDP length: %u\n", ntohs(self->uhdr.len));

    printf("UDP checksum: ");
    output_hex_from_bin((uint8_t *)&self->uhdr.check, sizeof(uint16_t));
    puts("");

}


inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));

    self->set_pl = set_txp_pl;
    self->fmt_txp_data = fmt_txp_data;
    self->dissect = dissect_txp;
    self->fmt_rep = fmt_txp_rep;
    self->show_info = show_txp_info;
}


int passive_tcp(char *port)
{
    int fd, listenfd = -1;
    socklen_t addrlen;
    struct sockaddr_in claddr;
    struct addrinfo hints, *res, *rp;

    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port, &hints, &res) != 0)
        perror("getaddrinfo()");

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if ((listenfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1)
            continue;

        int optval = 1;
        if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) == -1) {
            close(listenfd);
            continue;
        }

        if (bind(listenfd, rp->ai_addr, rp->ai_addrlen) == -1) {
            close(listenfd);
            continue;
        }

        break;
    }

    if (!rp) { /* No available address found */
        puts("No address structure available");
        exit(EXIT_FAILURE);
    }

    if (listen(listenfd, 1) == -1)
        perror("listen()");
    else
        puts("wait for connection...");

    addrlen = sizeof(struct sockaddr_in);
    if ((fd = accept(listenfd, (struct sockaddr*)&claddr, &addrlen)) == -1)
        perror("accept()");

    char clip[INET_ADDRSTRLEN];
    inet_ntop(claddr.sin_family, &claddr.sin_addr.s_addr, clip, sizeof(clip));
    printf("accept from %s\n", clip);

    freeaddrinfo(res);

    return fd;
}


int active_tcp(char *dst, char *port)
{
    int fd;
    struct addrinfo hints, *res, *rp;

    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(dst, port, &hints, &res) != 0)
        perror("getaddrinfo()");

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if ((fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) != -1)
            break;
    }

    if (!rp) { /* No available address found */
        puts("No address structure available");
        exit(EXIT_FAILURE);
    }

    if (connect(fd, rp->ai_addr, rp->ai_addrlen) == -1)
        perror("connect()");

    printf("connect to %s\n", dst);

    return fd;
}


Txp *cpy_txp(Txp *a, Txp *b)
{
    a->p = b->p;

    a->x_src_port = b->x_src_port;
    a->x_dst_port = b->x_dst_port;

    if (b->p == TCP)
        memcpy(&a->thdr, &b->thdr, b->hdrlen);
    else
        memcpy(&a->uhdr, &b->uhdr, b->hdrlen);

    a->hdrlen = b->hdrlen;
    memcpy(a->pl, b->pl, b->plen);

    return a;
}


uint8_t *set_txp_pl(Txp *self, uint8_t *data, size_t plen)
{
    self->plen = plen;
    memcpy(self->pl, data, self->plen);

    return self->pl;
}


ssize_t fmt_txp_data(Txp *self, uint8_t *buf, size_t buflen)
{
    if (!self || !buflen) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return -1;
    }

    if (self->p == TCP) {
        return fmt_tcp_segm(self, buf);
    } else if (self->p == UDP) {
        return fmt_udp_dgram(self, buf);
    } else {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return -1;
    }
}


uint8_t *dissect_txp(Net *net, Txp *self, uint8_t *txp_data, Proto p, size_t txp_len)
{
    if (p == TCP) {
        return dissect_tcp(net, self, txp_data, txp_len);
    } else if (p == UDP) {
        return dissect_udp(self, txp_data, txp_len);
    } else {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return NULL;
    }
}


Txp *fmt_txp_rep(Txp *self, Net *net, uint8_t *data, size_t dlen)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return NULL;
    }


    if (net->ipv == IPv4 && self->p == TCP) {
        self->hdrlen = sizeof(struct tcphdr);
        return fmt_tcp4_rep(self, &net->ip4hdr, data, dlen);
    } else if (net->ipv == IPv4 && self->p == UDP) {
        self->hdrlen = sizeof(struct udphdr);
        return fmt_udp4_rep(self, &net->ip4hdr, data, dlen);
    } else if (net->ipv == IPv6 && self->p == TCP) {
        self->hdrlen = sizeof(struct tcphdr);
        return fmt_tcp_rep(self, &net->ip6hdr, data, dlen);
    } else if (net->ipv == IPv6 && self->p == UDP) {
        self->hdrlen = sizeof(struct udphdr);
        return fmt_udp_rep(self, &net->ip6hdr, data, dlen);
    } else {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return NULL;
    }
}


int estab_tcp_conn(Mode m, char *ip, char *port)
{
    int fd;

    if (m == SERVER)
        fd = passive_tcp(port);
    else if (m == CLIENT)
        fd = active_tcp(ip, port);
    else
        return -1;

    return fd;
}


ssize_t tx_notification(int fd)
{
    ssize_t nb;

    if ((nb = write(fd, "Notification", strlen("Notification"))) == -1) {
        perror("write()");
        exit(EXIT_FAILURE);
    }

    return nb;
}

ssize_t wait_notification(int fd)
{
    ssize_t nb;
    char buf[BUFSIZE];

    if ((nb = read(fd, buf, sizeof(buf))) == -1) {
        perror("read()");
        exit(EXIT_FAILURE);
    }

    return nb;
}

void show_txp_info(Txp *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    if (self->p == TCP) {
        show_tcp_info(self);
    } else if (self->p == UDP) {
        show_udp_info(self);
    } else {
        fprintf(stderr, "Unknown transport layer protocol.");
    }
}

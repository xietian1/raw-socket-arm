#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "net.h"
#include "transport.h"
#include "esp.h"
#include "utils.h"

/* Check whether @ip is the ip address on host device */
inline static bool is_avl_ipaddr(char *ip)
{
    bool ret = false;
    int res;
    struct ifaddrs *ifaddr, *ifa;
    char lcl_ip[NI_MAXHOST] = {0};

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        res = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6),
                          lcl_ip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

        if (res == EAI_FAMILY)
            continue;

        if (strncmp(ip, lcl_ip, strlen(ip)) == 0) {
            ret = true;
            break;
        }
    }

    return ret;
}


inline static size_t set_hdr_plen(void *structptr, Proto p)
{
    if (p == TCP || p == UDP)
        return htons(((Txp *)structptr)->hdrlen + ((Txp *)structptr)->plen);
    else if (p == ESP)
        return htons(sizeof(EspHeader) + ((Esp *)structptr)->plen +
                     sizeof(EspTrailer) + ((Esp *)structptr)->authlen);
    else
        return 0;
}


inline static Net *fmt_ip4_rep_hdr(Net *self)
{
    self->ip4hdr.tot_len = htons(self->hdrlen + self->plen);

    if (inet_pton(AF_INET, self->x_src_ip, &(self->ip4hdr.saddr)) != 1) {
        fprintf(stderr, "src: %s\n", self->src_ip);
        perror("inet_pton()");
    }

    if (inet_pton(AF_INET, self->x_dst_ip, &(self->ip4hdr.daddr)) != 1) {
        fprintf(stderr, "dst: %s\n", self->dst_ip);
        perror("inet_pton()");
    }


    return self;
}


inline static Net *fmt_ip6_rep_hdr(Net *self)
{
    self->ip6hdr.ip6_plen = htons(self->plen);

    if (inet_pton(AF_INET6, self->x_src_ip, &(self->ip6hdr.ip6_src)) != 1) {
        fprintf(stderr, "src: %s\n", self->x_src_ip);
        perror("inet_pton()");
        return NULL;
    }

    if (inet_pton(AF_INET6, self->x_dst_ip, &(self->ip6hdr.ip6_dst)) != 1) {
        fprintf(stderr, "dst: %s\n", self->x_dst_ip);
        perror("inet_pton()");
        return NULL;
    }

    return self;
}


void init_net(Net *self, char *opr)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    if (strcmp(opr, "TM") == 0)
        self->opr = TM;
    if (strcmp(opr, "CHT") == 0)
        self->opr = CHT;
    if (strcmp(opr, "VRZ") == 0)
        self->opr = VRZ;
    if (strcmp(opr, "APTG") == 0)
        self->opr = APTG;
    if (strcmp(opr, "SD") == 0)
        self->opr = SD;
    if (strcmp(opr, "ATT") == 0)
        self->opr = ATT;

    if (self->opr == CHT || self->opr == APTG || self->opr == SD) {
        self->ipv = IPv4;
        self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
        self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
        self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
        self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
        self->hdrlen = sizeof(struct iphdr);
        self->dissect = dissect_ip4;
    } else if (self->opr == TM || self->opr == VRZ || self->opr == ATT) {
        self->ipv = IPv6;
        self->src_ip = (char *)malloc(INET6_ADDRSTRLEN * sizeof(char));
        self->dst_ip = (char *)malloc(INET6_ADDRSTRLEN * sizeof(char));
        self->x_src_ip = (char *)malloc(INET6_ADDRSTRLEN * sizeof(char));
        self->x_dst_ip = (char *)malloc(INET6_ADDRSTRLEN * sizeof(char));
        self->hdrlen = sizeof(struct ip6_hdr);
        self->dissect = dissect_ip6;
    } else {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->fmt_rep = fmt_net_rep;
    self->show_info = show_pkt_info;
}

uint8_t *dissect_ip4(Net *self, uint8_t *pkt, size_t pkt_len)
{
    if (!self || pkt_len < self->hdrlen) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return NULL;
    }
    memcpy(&self->ip4hdr, pkt, self->hdrlen);

    if (!inet_ntop(AF_INET, &(self->ip4hdr.saddr),
                   self->src_ip, INET_ADDRSTRLEN * sizeof(uint8_t)))
        perror("inet_ntop()");

    if (!inet_ntop(AF_INET, &(self->ip4hdr.daddr),
                   self->dst_ip, INET_ADDRSTRLEN * sizeof(uint8_t)))
        perror("inet_ntop()");

    self->plen = pkt_len - self->hdrlen;
    self->pro = self->ip4hdr.protocol;

    return pkt + self->hdrlen;

}

uint8_t *dissect_ip6(Net *self, uint8_t *pkt, size_t pkt_len)
{
    if (!self || pkt_len < self->hdrlen) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return NULL;
    }

    memcpy(&self->ip6hdr, pkt, self->hdrlen);

    if (!inet_ntop(AF_INET6, &(self->ip6hdr.ip6_src),
                   self->src_ip, INET6_ADDRSTRLEN * sizeof(uint8_t)))
        perror("inet_ntop()");

    if (!inet_ntop(AF_INET6, &(self->ip6hdr.ip6_dst),
                   self->dst_ip, INET6_ADDRSTRLEN * sizeof(uint8_t)))
        perror("inet_ntop()");

    self->plen = pkt_len - self->hdrlen;
    self->nxt = self->ip6hdr.ip6_nxt;

    //new add
    //show_pkt_info(self);
    get_ipsec_tnl_info(self);

    return pkt + self->hdrlen;
}

Net *fmt_net_rep(Net *self)
{
    /* Before calling fmt_net_rep, self->plen should be set correctly first */
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return NULL;
    }

    if (!is_avl_ipaddr(self->src_ip))
        swap_pointer((void *)&self->src_ip, (void *)&self->dst_ip);

    if (self->ipv == IPv4) {
        return fmt_ip4_rep_hdr(self);
    } else if (self->ipv == IPv6) {
        return fmt_ip6_rep_hdr(self);
    } else {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return NULL;
    }

}

uint8_t *l2_set_ip_pos(Net *self, uint8_t *data)
{
    if (inet_pton(AF_INET, self->x_src_ip, data+12) != 1) {
        fprintf(stderr, "src: %s\n", self->src_ip);
        perror("inet_pton()");
    }

    if (inet_pton(AF_INET, self->x_dst_ip, data+16) != 1) {
        fprintf(stderr, "dst: %s\n", self->dst_ip);
        perror("inet_pton()");
    }

    return data;
}

void get_ipsec_tnl_info(Net *self)
{
    int nb;
    int link[2];
    pid_t pid;
    char line[4096];
    char dir[8], src[16], dst[16];

    if (pipe(link)==-1)
        perror("pipe");

    if ((pid = fork()) == -1)
        perror("fork");

    if(pid == 0) {

        dup2 (link[1], STDOUT_FILENO);
        close(link[0]);
        close(link[1]);
        execl("/system/bin/ip", "ip", "xfrm", "policy", (char *)0);
        perror("execl");

    } else {

        close(link[1]);
        nb = read(link[0], line, sizeof(line));
        if (nb == 0)
            perror("read");
    }

    sscanf(line, "%*s %*s %*s %*s %*s %s %*s %*s %*s %*s %s %*s %s", dir, src, dst);


    if(strcmp(dir, "out") == 0) {
        strcpy(self->x_src_ip, src);
        strcpy(self->x_dst_ip, dst);
    } else {
        strcpy(self->x_src_ip, dst);
        strcpy(self->x_dst_ip, src);
    }

    return;
}

void show_pkt_info(Net *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    char buf1[INET6_ADDRSTRLEN] = {0};
    char buf2[INET6_ADDRSTRLEN] = {0};

    if (self->ipv == IPv4) {
        if (!inet_ntop(AF_INET, &(self->ip4hdr.saddr), buf1, sizeof(buf1)))
            perror("inet_ntop()");

        if (!inet_ntop(AF_INET, &(self->ip4hdr.daddr), buf2, sizeof(buf2)))
            perror("inet_ntop()");

    } else if (self->ipv == IPv6) {
        if (!inet_ntop(AF_INET6, &(self->ip6hdr.ip6_src), buf1, sizeof(buf1)))
            perror("inet_ntop()");

        if (!inet_ntop(AF_INET6, &(self->ip6hdr.ip6_dst), buf2, sizeof(buf2)))
            perror("inet_ntop()");

    } else {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    printf("IP version: %s\n", self->ipv == IPv4 ? "IPv4" : "IPv6");
    printf("Src IP: %s\n", buf1);
    printf("Dst IP: %s\n", buf2);
    printf("Payload length: %u\n", self->plen);

    Proto p = 0;
    if (self->ipv == IPv4)
        p = self->pro;
    else if (self->ipv == IPv6)
        p = self->nxt;


    switch(p) {
        case IPPROTO_IP:
            puts("IP nxt: IPv4");
            break;
        case IPPROTO_IPV6:
            puts("IP nxt: IPv6");
            break;
        case ESP:
            puts("IP nxt: ESP");
            break;
        case TCP:
            puts("IP nxt: TCP");
            break;
        case UDP:
            puts("IP nxt: UDP");
            break;
        default:
            fprintf(stderr, "Unknown IP nxt.");
    }
}

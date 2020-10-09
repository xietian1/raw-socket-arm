#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "dev.h"
#include "net.h"
#include "esp.h"
#include "replay.h"
#include "transport.h"
#include "utils.h"

inline static struct ifreq set_ifr_name(char *name)
{
    struct ifreq ifr;

    bzero(&ifr, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);

    return ifr;
}


inline static int get_ifr_mtu(struct ifreq *ifr)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd, SIOCGIFMTU, ifr) < 0) {
        perror("ioctl()");
        close(fd);
        exit(EXIT_FAILURE);
    }

    return ifr->ifr_mtu;
}


inline static struct sockaddr_ll init_addr(char *name)
{
    struct sockaddr_ll addr;
    bzero(&addr, sizeof(addr));

    addr.sll_family = AF_PACKET;
    addr.sll_halen = ETH_ALEN;

    struct if_nameindex *if_ni, *i;

    // if_nametoindex() get permission denied in some case
    if_ni = if_nameindex();
    if (if_ni == NULL) {
        perror("if_nameindex");
        exit(EXIT_FAILURE);
    }

    for(i = if_ni; ! (i->if_index == 0 && i->if_name == NULL); i++) {
        if(strcmp(i->if_name, name) == 0) {
            addr.sll_ifindex = i->if_index;
            break;
        }

    }
    if_freenameindex(if_ni);

    if (addr.sll_ifindex == 0) {
        perror("if_nameindex()");
        exit(EXIT_FAILURE);
    }

    return addr;
}


inline static int set_sock_fd(struct sockaddr_ll dev)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    bind(fd, (struct sockaddr *)&dev, sizeof(dev));

    return fd;
}


void init_dev(Dev *self, char *dev_name)
{
    if (!self || !dev_name || strlen(dev_name) + 1 > IFNAMSIZ) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    int mtu;
    struct ifreq ifr;

    ifr = set_ifr_name(dev_name);
    mtu = get_ifr_mtu(&ifr);

    self->name = strdup(dev_name);
    self->mtu = mtu;

    self->addr = init_addr(dev_name);
    self->fd = set_sock_fd(self->addr);

    self->frame = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));
    self->framelen = 0;

    self->is_up = check_dev_state;
    self->fmt_frame = fmt_frame;
    self->tx_frame = tx_frame;
    self->tx_frame_buf = tx_frame_buf;
    self->rx_frame = rx_frame;
    self->dissect_link_hdr = dissect_link_hdr;
    self->show_info = show_frame_info;

    self->linkhdr = (uint8_t *)malloc(LINKHDRLEN);

    self->dev_s = self;

    get_timestamp(&(self->base_time));
}


bool check_dev_state(Dev *self)
{
    int fd;
    struct ifreq ifr;

    bzero(&ifr, sizeof(ifr));
    fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_IP);

    strcpy(ifr.ifr_name, self->name);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
        perror("SIOCGIFFLAGS");

    close(fd);

    if (ifr.ifr_flags & IFF_RUNNING)
        return true;
    else
        return false;
}

char* get_dev_addr(Dev *self)
{

    int fd;
    struct ifreq ifr;

    /* IPv4 */
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, self->name, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

}

ssize_t fmt_frame(Dev *self, Net *net, Esp *esp, Txp *txp)
{
    if (!self || !net || !txp) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    if (net->ipv == IPv4)
        self->framelen = sizeof(struct iphdr) + net->plen;
    if (net->ipv == IPv6)
        self->framelen = sizeof(struct ip6_hdr) + net->plen;

    uint8_t txp_data_buf[txp->hdrlen + txp->plen];
    txp->fmt_txp_data(txp, txp_data_buf, txp->hdrlen + txp->plen);

    size_t nb = 0;

    if(net->opr == SD) {
        memcpy(self->frame, self->linkhdr, LINKHDRLEN);
        nb += LINKHDRLEN;
        self->framelen += LINKHDRLEN;
    }

    if (net->ipv == IPv4) {
        memcpy(self->frame+nb, &net->ip4hdr, sizeof(struct iphdr));
        nb += sizeof(struct iphdr);
    }

    if (net->ipv == IPv6) {
        memcpy(self->frame+nb, &net->ip6hdr, sizeof(struct ip6_hdr));
        nb += sizeof(struct ip6_hdr);
    }

    if (esp && net->nxt == ESP) {
        esp->fmt_esppkt(esp, self->frame + nb, self->framelen - nb);
        return self->framelen;
    }

    memcpy(self->frame + nb, txp_data_buf, txp->hdrlen + txp->plen);
    nb += txp->hdrlen + txp->plen;

    return self->framelen;
}


ssize_t tx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);

    nb = sendto(self->fd, self->frame, self->framelen,
                0, (struct sockaddr *)&self->addr, addrlen);

    if (nb <= 0)
        perror("sendto()");


    return nb;
}

ssize_t tx_frame_buf(Dev *self, int index)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);

    nb = sendto(self->fd, frame_buf.frame[index], frame_buf.framelen[index],
                0, (struct sockaddr *)&self->addr, addrlen);

    if (nb <= 0)
        perror("sendto()");

    return nb;
}

ssize_t rx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);

    nb = recvfrom(self->fd, self->frame, self->mtu,
                  0, (struct sockaddr *)&self->addr, &addrlen);
    if (nb <= 0)
        perror("recvfrom()");

    return nb;
}

void dissect_link_hdr(Dev *self)
{
    memcpy(self->linkhdr, self->frame, LINKHDRLEN);
    return ;
}

void show_frame_info(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    printf("Frame Length: %d\n", self->framelen);
}

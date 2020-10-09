#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "replay.h"
#include "dev.h"
#include "net.h"
#include "esp.h"
#include "sip.h"
#include "hmac.h"
#include "transport.h"
#include "utils.h"

struct frame_arr frame_buf;

inline static int chk_rdy_fd(int fd, double sec)
{
    HANDLE_ARG_ERR(fd >= 0);
    HANDLE_ARG_ERR(sec >= 0);

    int ret;
    fd_set fds;
    struct timeval tv;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    tv.tv_sec = (time_t)sec;
    tv.tv_usec = (suseconds_t)((sec - (time_t)sec) * 1e6);

    if ((ret = select(fd + 1, &fds, NULL, NULL, (sec ? &tv : NULL))) == -1) {
        perror("select()");
        exit(EXIT_FAILURE);
    }

    return ret;
}

inline static ssize_t cpy_frame(Dev *dev, long msec)
{
    if(frame_buf.count == MAXBUFCOUNT) {
        printf("frame_buf overflow\n");
        return 0;
    }

    memcpy(frame_buf.frame[frame_buf.count], dev->frame, dev->framelen);

    frame_buf.framelen[frame_buf.count] = dev->framelen;
    frame_buf.msec[frame_buf.count] = msec;
    frame_buf.count += 1;

    return dev->framelen;
}

inline static ssize_t tx_tcp_rep(Dev dev,
                                 Net net,
                                 Txp *txp,
                                 uint8_t *data, ssize_t dlen, long msec)
{
    size_t nb = dlen + sizeof(struct tcphdr);

    net.plen = nb;

    net.fmt_rep(&net);
    txp->fmt_rep(txp, &net, data, dlen);

    if (net.ipv == IPv4) {
        net.ip4hdr.tot_len = htons(net.hdrlen + net.plen);
        net.ip4hdr.check = cal_ipv4_cksm(net.ip4hdr);
    } else if (net.ipv == IPv6) {
        net.ip6hdr.ip6_plen = htons(net.plen);
    }

    dev.fmt_frame(&dev, &net, NULL, txp);

    if(msec == 0)
        return dev.tx_frame(&dev);
    else {
        cpy_frame(&dev, msec);
        return 0;
    }
}


inline static ssize_t tx_udp_rep(Dev dev,
                                 Net net,
                                 Txp *txp,
                                 uint8_t *data, ssize_t dlen, long msec)
{
    size_t nb = dlen + sizeof(struct udphdr);

    net.plen = nb;
    net.fmt_rep(&net);
    txp->fmt_rep(txp, &net, data, dlen);

    if (net.ipv == IPv4) {
        net.ip4hdr.tot_len = htons(net.hdrlen + net.plen);
        net.ip4hdr.check = cal_ipv4_cksm(net.ip4hdr);
    } else if (net.ipv == IPv6) {
        net.ip6hdr.ip6_plen = htons(net.plen);
    }

    dev.fmt_frame(&dev, &net, NULL, txp);
    return dev.tx_frame(&dev);
}

inline static ssize_t tx_esp_rep_iv(Dev dev,
                                    Net net,
                                    Esp esp,
                                    Txp *txp,
                                    uint8_t *data, ssize_t dlen, long msec)
{
    size_t nb = dlen;
    Proto net_nxt = net.ip6hdr.ip6_nxt;
    Proto esp_nxt = esp.tlr.nxt;

    txp->p = esp_nxt;

    net.ip6hdr.ip6_nxt = esp_nxt;

    if (esp_nxt == TCP) {
        nb += sizeof(struct tcphdr);
    } else if (esp_nxt == UDP) {
        nb += sizeof(struct udphdr);
    } else {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }







}







inline static ssize_t tx_esp_rep(Dev dev,
                                 Net net,
                                 Esp esp,
                                 Txp *txp,
                                 uint8_t *data, ssize_t dlen, long msec)
{

    size_t nb = dlen;
    Proto net_nxt = net.ipv == IPv4 ? net.ip4hdr.protocol : net.ip6hdr.ip6_nxt;
    Proto esp_nxt = esp.tlr.nxt;

    txp->p = esp_nxt;

    if (net.ipv == IPv4) {
        net.ip4hdr.protocol = esp_nxt;
    } else if (net.ipv == IPv6) {
        net.ip6hdr.ip6_nxt = esp_nxt;
    } else {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    if (esp_nxt == TCP) {
        nb += sizeof(struct tcphdr);
    } else if (esp_nxt == UDP) {
        nb += sizeof(struct udphdr);
    } else {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    esp.plen = nb;
    net.plen = nb;
    net.fmt_rep(&net);

    txp->fmt_rep(txp, &net, data, dlen);

    esp.fmt_rep(&esp, esp_nxt);
    net.plen = sizeof(EspHeader) + sizeof(EspTrailer) +
               esp.plen + esp.tlr.pad_len + esp.authlen;

    if (net.ipv == IPv4) {
        net.ip4hdr.protocol = net_nxt;
        net.ip4hdr.tot_len = htons(net.hdrlen + net.plen);
        net.ip4hdr.check = cal_ipv4_cksm(net.ip4hdr);
    } else if (net.ipv == IPv6) {
        net.ip6hdr.ip6_nxt = net_nxt;
        net.ip6hdr.ip6_plen = htons(net.plen);
    } else {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    if (esp_nxt == TCP) {
        memcpy(esp.pl, &txp->thdr, txp->hdrlen);
    }

    if (esp_nxt == UDP) {
        memcpy(esp.pl, &txp->uhdr, txp->hdrlen);
    }

    memcpy(esp.pl + txp->hdrlen, txp->pl, txp->plen);
    esp.set_auth(&esp, hmac_sha1_96);

    dev.fmt_frame(&dev, &net, &esp, txp);

    if(msec == 0)
        return dev.tx_frame(&dev);
    else {
        cpy_frame(&dev, msec);
        return 0;
    }
}

void init_frame_buf()
{
    frame_buf.count = 0;
}

void flush_frame_buf(Dev *dev, struct timespec start)
{
    struct timespec now;

    ssize_t n = 0;

    while( n != frame_buf.count ) {

        get_timestamp(&now);

        long d_sec, d_nsec;

        while(1) {

            d_sec = now.tv_sec - start.tv_sec;
            d_nsec = now.tv_nsec - start.tv_nsec;

            if(d_sec - (frame_buf.msec[n] / 1000) > 1)
                break;
            else if(d_sec - (frame_buf.msec[n] / 1000) == 1 &&
                    (d_nsec - (frame_buf.msec[n] % 1000 * 1000000)) + 1000000000 > 0)
                break;
            else if(d_sec - (frame_buf.msec[n] / 1000) == 0 &&
                    (d_nsec - (frame_buf.msec[n] % 1000 * 1000000)) > 0)
                break;
            else
                get_timestamp(&now);

        }
        dev->tx_frame_buf(dev, n);

        n +=1 ;

    }

    frame_buf.count = 0;

    return ;
}

bool str_exist(char *data, char *delimiter, int data_len) {
    for (int i = 0; i < data_len - strlen(delimiter); i++) {
        if (strncmp(data, delimiter, strlen(delimiter)) == 0) {
            return true;
        }
    }
    return false;
}

uint8_t *dissect_rx_data(Dev *dev, Net *net, Esp *esp, Txp *txp, Sip *sip)
{
    size_t len;
    uint8_t *data;
    uint8_t *sp;
    Proto p;

    if(net->opr == SD) {
        dev->frame = dev->frame+LINKHDRLEN;
        dev->framelen -= LINKHDRLEN;
    }

    data = net->dissect(net, dev->frame, dev->framelen);
    p = net->nxt;
    len = net->plen;


    if (p != ESP && p != TCP && p != UDP) {
        puts("replay.c line 254 not recognized p");
        return NULL;
    }


    if (p == ESP) {
        printf("dissect protocol before//should be esp 50:: %d\n", p);

        data = esp->dissect(esp, data, len);
        p = esp->tlr.nxt;
        len = esp->plen;

        printf("dissect protocol after, should be tcp 6 or udp 17:: %d\n", p);
    }



    data = txp->dissect(net, txp, data, p, len);

    len = txp->plen;

    sp = data;

    data = sip->dissect(sip, data, len);

    if(net->opr == SD) {
        dev->frame = dev->frame-LINKHDRLEN;
        dev->framelen += LINKHDRLEN;
    }

    if( (len > 0) /*&& (strcmp(net->src_ip, net->x_dst_ip) == 0)*/ && (((data) && ((sip->st == STA) || (sip->st == REQ))) || ((!data) && (!sip->push_flag)))) {
        memcpy(sip->msg_buf + sip->msg_len, sp, len);
        sip->msg_len += len;
        sip->diss_flag = true;
        sip->push_flag = true;
    }

    if(p == TCP && data && !(txp->thdr.th_flags & TH_PUSH))
        sip->push_flag = false;
    else if(p == TCP && data && (txp->thdr.th_flags & TH_PUSH))
        sip->push_flag = true;

    if(p == UDP &&((data) && ((sip->st == STA) || (sip->st == REQ))))
        sip->push_flag = true;

    return data;
}

uint8_t *dissect_rx_net(Dev *dev, Net *net)
{
    uint8_t *data;
    Proto p;

    data = net->dissect(net, dev->frame+LINKHDRLEN, dev->framelen-LINKHDRLEN);
    p = net->nxt;

    if (p != ESP && p != TCP && p != UDP) {
        return NULL;
    }

    return data;
}

uint8_t *wait_esp_tcp_ack(Dev *dev,
                          Net *net,
                          Esp *esp,
                          Txp *txp,
                          Sip *sip,
                          double sec)
{
    Txp t;

    bool is_t_out;
    struct timespec ts1, ts2;
    struct timespec timer = cnv_dbl_to_ts(sec);

    init_txp(&t);
    get_timestamp(&ts1);

    while (true) {
        get_timestamp(&ts2);

        is_t_out = sec != 0.0 && is_timeout(ts1, ts2, timer);

        if (is_t_out || !chk_rdy_fd(dev->fd, sec))
            return NULL;

        dev->framelen = dev->rx_frame(dev);
        dissect_rx_data(dev, net, esp, txp, sip);

        if (txp->plen == 0)
            break;

        if (txp->p == TCP)
            tx_esp_tcp_ack(dev, net, esp, txp);
    }

    return dev->frame;
}

uint8_t *wait_esp_tcp_seq(Dev *dev,
                          Net *net,
                          Esp *esp,
                          Txp *txp,
                          Sip *sip,
                          double sec)
{
    Txp t;

    bool is_t_out;
    struct timespec ts1, ts2;
    struct timespec timer = cnv_dbl_to_ts(sec);

    init_txp(&t);
    get_timestamp(&ts1);

    while (true) {
        get_timestamp(&ts2);

        is_t_out = sec != 0.0 && is_timeout(ts1, ts2, timer);

        if (is_t_out || !chk_rdy_fd(dev->fd, sec))
            return NULL;

        dev->framelen = dev->rx_frame(dev);
        dissect_rx_data(dev, net, esp, txp, sip);

        memset(sip->msg_buf, 0, sip->msg_len);
        sip->msg_len = 0;
        sip->diss_flag = false;
        sip->push_flag = false;


        if (htonl(txp->thdr.th_ack) == txp->x_tx_seq) {
            if (txp->p == TCP /* && txp->plen != 0 && enable_ack */)
                tx_esp_tcp_ack(dev, net, esp, txp);
            break;
        }

        if (txp->p == TCP /* && txp->plen != 0 && enable_ack */)
            tx_esp_tcp_ack(dev, net, esp, txp);
    }

    return dev->frame;
}

uint8_t *wait_sip_req(Dev *dev,
                      Net *net,
                      Esp *esp,
                      Txp *txp,
                      Sip *sip,
                      SipMeths m,
                      double sec,
                      bool enable_ack)
{
    bool is_sip;
    Txp t;

    bool is_t_out;
    struct timespec ts1, ts2;
    struct timespec timer = cnv_dbl_to_ts(sec);

    get_timestamp(&ts1);

    init_txp(&t);

    while (true) {
        get_timestamp(&ts2);

        is_t_out = sec != 0.0 && is_timeout(ts1, ts2, timer);

        if (is_t_out || !chk_rdy_fd(dev->fd, sec))
            return NULL;

        dev->framelen = dev->rx_frame(dev);
        is_sip = dissect_rx_data(dev, net, esp, txp, sip) ? true : false;

        if (txp->p == TCP && txp->plen != 0 && enable_ack)
            tx_esp_tcp_ack(dev, net, esp, txp);

        if (is_sip && sip->st == REQ && sip->meth == m)
            break;
    }

    return dev->frame;
}


uint8_t *wait_sip_sta(Dev *dev,
                      Net *net,
                      Esp *esp,
                      Txp *txp,
                      Sip *sip,
                      SipStats c,
                      double sec,
                      bool enable_ack)
{
    bool is_sip;
    Txp t;

    bool is_t_out;
    struct timespec ts1, ts2;
    struct timespec timer = cnv_dbl_to_ts(sec);

    init_txp(&t);
    get_timestamp(&ts1);

    while (true) {
        get_timestamp(&ts2);

        is_t_out = sec != 0.0 && is_timeout(ts1, ts2, timer);

        if (is_t_out || !chk_rdy_fd(dev->fd, sec))
            return NULL;

        dev->framelen = dev->rx_frame(dev);
        is_sip = dissect_rx_data(dev, net, esp, txp, sip) ? true : false;

        if (txp->p == TCP && txp->plen != 0 && enable_ack)
            tx_esp_tcp_ack(dev, net, esp, txp);

        if (is_sip && sip->st == STA && sip->stac == c)
            break;
    }

    return dev->frame;

}

uint8_t *wait_sip_all_stac(Dev *dev,
                           Net *net,
                           Esp *esp,
                           Txp *txp,
                           Sip *sip,
                           SipStats *target,
                           double sec,
                           bool enable_ack)
{
    bool is_sip;
    Txp t;

    bool is_t_out;
    struct timespec ts1, ts2;
    struct timespec timer = cnv_dbl_to_ts(sec);

    init_txp(&t);
    get_timestamp(&ts1);

    while (true) {
        get_timestamp(&ts2);

        is_t_out = sec != 0.0 && is_timeout(ts1, ts2, timer);

        if(sip->diss_flag == true) {
            goto diss_sip;
        }

        if (is_t_out || !chk_rdy_fd(dev->fd, sec))
            return NULL;

        dev->framelen = dev->rx_frame(dev);

        is_sip = dissect_rx_data(dev, net, esp, txp, sip) ? true : false;

        if (txp->p == TCP && txp->plen != 0 && enable_ack)
            tx_esp_tcp_ack(dev->dev_s, net, esp, txp);

        if (!is_sip || sip->st != STA)
            continue;

diss_sip:

        if(!sip->get_flds(sip))
            continue;

        if (chk_match_sip_stat(sip->stac, target))
            break;
    }

    return dev->frame;
}

uint8_t *wait_sip_all_meth(Dev *dev,
                           Net *net,
                           Esp *esp,
                           Txp *txp,
                           Sip *sip,
                           SipMeths *target,
                           double sec,
                           bool enable_ack)
{
    bool is_sip;
    Txp t;

    bool is_t_out;
    struct timespec ts1, ts2;
    struct timespec timer = cnv_dbl_to_ts(sec);

    init_txp(&t);
    get_timestamp(&ts1);

    while (true) {
        get_timestamp(&ts2);

        is_t_out = sec != 0.0 && is_timeout(ts1, ts2, timer);

        if(sip->diss_flag == true) {

            if(!sip->get_flds(sip))
                continue;

            if (chk_match_sip_meth(sip->meth, target))
                break;

            continue;
        }

        if (is_t_out || !chk_rdy_fd(dev->fd, sec))
            return NULL;

        dev->framelen = dev->rx_frame(dev);

        is_sip = dissect_rx_data(dev, net, esp, txp, sip) ? true : false;

        if (txp->p == TCP && txp->plen != 0 && enable_ack)
            tx_esp_tcp_ack(dev->dev_s, net, esp, txp);

        if (!is_sip || sip->st != REQ)
            continue;

        if(!sip->get_flds(sip))
            continue;

        if (chk_match_sip_meth(sip->meth, target))
            break;
    }

    return dev->frame;
}

uint8_t *wait_sip(Dev *dev,
                  Net *net,
                  Esp *esp,
                  Txp *txp,
                  Sip *sip,
                  SipMeths *req_arr,
                  SipStats *sta_arr,
                  double sec,
                  bool enable_ack)
{
    bool is_sip;
    Txp t;

    bool is_t_out;
    struct timespec ts1, ts2;
    struct timespec timer = cnv_dbl_to_ts(sec);

    init_txp(&t);
    puts("AFTER init_txp");
    get_timestamp(&ts1);

    while (true) {
        get_timestamp(&ts2);

        is_t_out = sec != 0.0 && is_timeout(ts1, ts2, timer);

        if (is_t_out || !chk_rdy_fd(dev->fd, sec))
            return NULL;

        if(sip->diss_flag == true) {

            if(!sip->get_flds(sip))
                continue;

            if (sip->st == REQ && (chk_match_sip_meth(sip->meth, req_arr)))
                break;

            if (sip->st == STA && (chk_match_sip_stat(sip->stac, sta_arr)))
                break;

            continue;
        }

        dev->framelen = dev->rx_frame(dev);
        is_sip = dissect_rx_data(dev, net, esp, txp, sip) ? true : false;

        if(is_sip){
            puts("this message is SIP!! ");
        }else{
            puts("this message is not SIP!!");
        }

        if (txp->p == TCP && txp->plen != 0 && enable_ack)
            tx_esp_tcp_ack(dev, net, esp, txp);

        if (!is_sip)
            continue;
        /*
                if(!sip->get_flds(sip))
                    continue;
        */
        if (sip->st == REQ && (chk_match_sip_meth(sip->meth, req_arr)))
            break;

        if (sip->st == STA && (chk_match_sip_stat(sip->stac, sta_arr)))
            break;

    }

    return dev->frame;
}

uint8_t *wait_pkt(Dev *dev,
                  Net *net,
                  double sec)
{

    bool is_t_out;
    struct timespec ts1, ts2;
    struct timespec timer = cnv_dbl_to_ts(sec);

    get_timestamp(&ts1);

    while (true) {
        get_timestamp(&ts2);

        is_t_out = sec != 0.0 && is_timeout(ts1, ts2, timer);

        if (is_t_out || !chk_rdy_fd(dev->fd, sec))
            return NULL;

        dev->framelen = dev->rx_frame(dev);
        dissect_rx_net(dev, net);

        if ((strcmp(net->x_src_ip, net->src_ip) == 0) && (strcmp( net->x_dst_ip, net->dst_ip) == 0)) {
            if(ntohl(*((uint32_t*)(dev->frame+LINKHDRLEN+20+8+4))) > 10000)
                continue;
            if(ntohl(*((uint32_t*)(dev->frame+LINKHDRLEN+20+8+4))) < 0)
                continue;
            net->tmp_esp_seq = ntohl(*((uint32_t*)(dev->frame+LINKHDRLEN+20+8+4)));
        }
        if ((strcmp(net->x_src_ip, net->src_ip) == 0) && (strcmp( /* net->tmp_dst_ip*/ "223.22.236.100", net->dst_ip) == 0))
            break;
    }

    return dev->frame;
}

ssize_t tx_esp_tcp_ack(Dev *dev, Net *net, Esp *esp, Txp *txp)
{
    if(net->opr == APTG || net->opr == VRZ) {
        txp->thdr.th_win = htons(46080); /* force set window size */
        return tx_tcp_rep(*dev, *net, txp, NULL, 0, 0);
    }
    net->nxt = ESP;
    return tx_esp_rep(*dev, *net, *esp, txp, NULL, 0, 0);
}


ssize_t tx_sip_inv(Dev *dev,
                   Net *net,
                   Esp *esp,
                   Txp *txp,
                   Sip *sip,
                   char *fname[2],
                   long msec)
{
    if (!dev || !net || !esp || !txp || !fname[0] || !fname[1]) {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    ssize_t nb0, nb1 = 0;
    uint8_t buf0[BUFSIZE], buf1[BUFSIZE];

    if (net->opr == CHT) {
        net->ip4hdr.protocol = ESP;
        net->nxt = ESP;
    } else if (net->opr == ATT) {
        net->ip6hdr.ip6_nxt = ESP;
        net->nxt = ESP;
    }
    else if (net->opr == TM) {
        net->ip6hdr.ip6_nxt = ESP;
        net->nxt = ESP;
    } else if (net->opr == VRZ) {
        net->ip6hdr.ip6_nxt = TCP;
        net->nxt = TCP;
    } else if (net->opr == APTG) {
        net->ip4hdr.protocol = TCP;
        net->nxt = TCP;
    } else if (net->opr == SD) {
        net->ip4hdr.protocol = UDP;
        net->nxt = UDP;
    } else {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    //att volte is different
    if(net->opr == ATT){
        esp->tlr.nxt = TCP;



    }else{
        esp->tlr.nxt = TCP;

        nb0 = read_file(fname[0], buf0);
        if(net->opr == CHT || net->opr == TM || net->opr == VRZ || net->opr == APTG || net->opr == ATT)
            nb1 = read_file(fname[1], buf1);

        nb0 = compose_sip(net, sip, buf0, nb0);

        if(net->opr == CHT || net->opr == TM || net->opr == VRZ || net->opr == APTG || net->opr == ATT) {
            nb1 = compose_sip(net, sip, buf1, nb1);
        }

        if (net->opr == TM || net->opr == CHT ) {
            tx_esp_rep(*dev, *net, *esp, txp, buf0, nb0, msec);
            tx_esp_rep(*dev, *net, *esp, txp, buf1, nb1, msec);
        } else if(net->opr == APTG || net->opr == VRZ) {
            txp->p = TCP;
            tx_tcp_rep(*dev, *net, txp, buf0, nb0, msec);
            tx_tcp_rep(*dev, *net, txp, buf1, nb1, msec);
        } else if(net->opr == SD) {
            txp->p = UDP;
            tx_udp_rep(*dev, *net, txp, buf0, nb0, msec);
        }
    }



    return nb0 + nb1;
}


ssize_t tx_sip_prack(Dev *dev,
                     Net *net,
                     Esp *esp,
                     Txp *txp,
                     Sip *sip,
                     char *fname)
{
    if (!dev || !net || !esp || !txp || !fname) {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    ssize_t nb;
    uint8_t buf[BUFSIZE];

    if (net->opr == CHT) {
        net->ip4hdr.protocol = ESP;
        net->nxt = ESP;
        esp->tlr.nxt = UDP;
    } else if (net->opr == TM) {
        net->ip6hdr.ip6_nxt = ESP;
        net->nxt = ESP;
        esp->tlr.nxt = TCP;
    } else if (net->opr == VRZ) {
        net->ip6hdr.ip6_nxt = UDP;
        net->nxt = UDP;
    } else if (net->opr == APTG) {
        net->ip4hdr.protocol = UDP;
        net->nxt = UDP;
    } else {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    nb = read_file(fname, buf);

    nb = compose_sip(net, sip, buf, nb);

    if (net->opr == TM || net->opr == CHT ) {
        tx_esp_rep(*dev, *net, *esp, txp, buf, nb, 0);
    } else if(net->opr == APTG || net->opr == VRZ) {
        /* modify destination port temporarily */
        uint16_t tmp_port = txp->x_dst_port;
        txp->x_dst_port = txp->x_src_port;
        txp->p = UDP;
        tx_udp_rep(*dev, *net, txp, buf, nb, 0);
        txp->x_dst_port = tmp_port;
    }

    return nb;
}


ssize_t tx_sip_ok(Dev *dev,
                  Net *net,
                  Esp *esp,
                  Txp *txp,
                  Sip *sip,
                  char *fname[2],
                  long msec)
{
    if (!dev || !net || !esp || !txp || !fname) {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    ssize_t nb0, nb1 = 0;
    uint8_t buf0[BUFSIZE], buf1[BUFSIZE];

    if (net->opr == CHT) {
        net->ip4hdr.protocol = ESP;
        net->nxt = ESP;
    } else if (net->opr == TM) {
        net->ip6hdr.ip6_nxt = ESP;
        net->nxt = ESP;
    } else if (net->opr == VRZ) {
        net->ip6hdr.ip6_nxt = TCP;
        net->nxt = TCP;
    } else if (net->opr == APTG) {
        net->ip4hdr.protocol = TCP;
        net->nxt = TCP;
    } else if (net->opr == SD) {
        net->ip4hdr.protocol = UDP;
        net->nxt = UDP;
    } else {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    esp->tlr.nxt = TCP;

    nb0 = read_file(fname[0], buf0);
    if(net->opr == CHT || net->opr == TM || net->opr == VRZ || net->opr == APTG )
        nb1 = read_file(fname[1], buf1);

    nb0 = compose_sip(net, sip, buf0, nb0);

    if(net->opr == CHT || net->opr == TM || net->opr == VRZ || net->opr == APTG ) {
        nb1 = compose_sip(net, sip, buf1, nb1);
    }

    if (net->opr == TM || net->opr == CHT ) {
        tx_esp_rep(*dev, *net, *esp, txp, buf0, nb0, msec);
        tx_esp_rep(*dev, *net, *esp, txp, buf1, nb1, msec);
    } else if(net->opr == APTG || net->opr == VRZ) {
        txp->p = TCP;
        tx_tcp_rep(*dev, *net, txp, buf0, nb0, msec);
        tx_tcp_rep(*dev, *net, txp, buf1, nb1, msec);
    } else if(net->opr == SD) {
        txp->p = UDP;
        tx_udp_rep(*dev, *net, txp, buf0, nb0, msec);
    }

    return nb0 + nb1;
}


ssize_t tx_sip_ack(Dev *dev,
                   Net *net,
                   Esp *esp,
                   Txp *txp,
                   Sip *sip,
                   char *fname)
{
    if (!dev || !net || !esp || !txp || !fname) {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    ssize_t nb;
    uint8_t buf[BUFSIZE];

    if (net->opr == CHT) {
        net->ip4hdr.protocol = ESP;
        net->nxt = ESP;
    } else if (net->opr == TM) {
        net->ip6hdr.ip6_nxt = ESP;
        net->nxt = ESP;
    } else if (net->opr == APTG) {
        net->ip4hdr.protocol = TCP;
        net->nxt = TCP;
    } else {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }
    esp->tlr.nxt = TCP;

    nb = read_file(fname, buf);

    nb = compose_sip(net, sip, buf, nb);

    if (net->opr == TM || net->opr == CHT ) {
        tx_esp_rep(*dev, *net, *esp, txp, buf, nb, 0);
    } else if(net->opr == APTG) {
        txp->p = TCP;
        tx_tcp_rep(*dev, *net, txp, buf, nb, 0);
    }

    return nb;
}

ssize_t tx_sip_cancel(Dev *dev,
                      Net *net,
                      Esp *esp,
                      Txp *txp,
                      Sip *sip,
                      char *fname[2],
                      long msec)
{
    if (!dev || !net || !esp || !txp || !fname[0] || !fname[1]) {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    ssize_t nb0, nb1 = 0;
    uint8_t buf0[BUFSIZE], buf1[BUFSIZE];

    if (net->opr == CHT) {
        net->ip4hdr.protocol = ESP;
        net->nxt = ESP;
    } else if (net->opr == TM) {
        net->ip6hdr.ip6_nxt = ESP;
        net->nxt = ESP;
    } else if (net->opr == VRZ) {
        net->ip6hdr.ip6_nxt = TCP;
        net->nxt = TCP;
    } else if (net->opr == APTG) {
        net->ip4hdr.protocol = TCP;
        net->nxt = TCP;
    } else {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    esp->tlr.nxt = TCP;

    nb0 = read_file(fname[0], buf0);
    nb0 = compose_sip(net, sip, buf0, nb0);

    if(net->opr == TM) {
        nb1 = read_file(fname[1], buf1);
        nb1 = compose_sip(net, sip, buf1, nb1);
    }

    if (net->opr == CHT) {
        tx_esp_rep(*dev, *net, *esp, txp, buf0, nb0, msec);
    } else if (net->opr == TM) {
        tx_esp_rep(*dev, *net, *esp, txp, buf0, nb0, msec);
        tx_esp_rep(*dev, *net, *esp, txp, buf1, nb1, msec);
    } else if (net->opr == APTG) {
        txp->p = TCP;
        tx_tcp_rep(*dev, *net, txp, buf0, nb0, msec);
    } else {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    return nb0 + nb1;
}

ssize_t tx_sip_update(Dev *dev,
                      Net *net,
                      Esp *esp,
                      Txp *txp,
                      Sip *sip,
                      char *fname[2],
                      long msec)
{
    if (!dev || !net || !esp || !txp || !fname[0] || !fname[1]) {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    ssize_t nb0, nb1;
    uint8_t buf0[BUFSIZE], buf1[BUFSIZE];

    if (net->opr == CHT) {
        net->ip4hdr.protocol = ESP;
        net->nxt = ESP;
    } else if (net->opr == TM) {
        net->ip6hdr.ip6_nxt = ESP;
        net->nxt = ESP;
    } else if (net->opr == APTG) {
        net->ip4hdr.protocol = TCP;
        net->nxt = TCP;
    } else {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    esp->tlr.nxt = TCP;

    nb0 = read_file(fname[0], buf0);
    nb1 = read_file(fname[1], buf1);

    nb0 = compose_sip(net, sip, buf0, nb0);
    nb1 = compose_sip(net, sip, buf1, nb1);

    tx_esp_rep(*dev, *net, *esp, txp, buf0, nb0, msec);
    tx_esp_rep(*dev, *net, *esp, txp, buf1, nb1, msec);

    return nb0 + nb1;
}

ssize_t tx_pkt(Dev *dev,
               Net *net)
{
    l2_set_ip_pos(net, dev->frame+LINKHDRLEN);

    bzero((dev->frame+LINKHDRLEN+10), 2);
    *((uint16_t *)(dev->frame+LINKHDRLEN+10)) = chksum((uint16_t *)(dev->frame+LINKHDRLEN), sizeof(struct iphdr));

    *((uint32_t*)(dev->frame+LINKHDRLEN+20+8+4)) = htonl(net->tmp_esp_seq+1);
    net->tmp_esp_seq += 1;

    dev->tx_frame(dev);
    return 0;
}

ssize_t tx_sip_by_stac(Dev *dev,
                       Net *net,
                       Esp *esp,
                       Txp *txp,
                       Sip *sip)
{
    if (!dev || !net || !esp || !txp) {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    ssize_t nb = 0;

    if (sip->rep_stac == UNKN_STAT) {
        nb = tx_sip_inv(dev, net, esp, txp, sip, invite, 0);
        puts("INV");
    }

    if (sip->rep_stac == TRY)
        puts("TRY");

    if (sip->rep_stac == SPROC) {
        nb = tx_sip_prack(dev, net, esp, txp, sip, prack);
        puts("PRACK");
    }

    if (sip->rep_stac == RING)
        puts("RING");

    get_timestamp(&(sip->ts));
    return nb;
}

void kpt_session_alive(Dev *dev,
                       Net *net,
                       Esp *esp,
                       Txp *txp,
                       Sip *sip,
                       double sec)
{
    Txp t;

    double intvl = 8.0;
    bool is_t_out, intvl_t_out;
    struct timespec ts1, ts2;
    struct timespec ts_intvl1, ts_intvl2;
    struct timespec timer = cnv_dbl_to_ts(sec);
    struct timespec timer_intvl = cnv_dbl_to_ts(intvl);

    init_txp(&t);
    get_timestamp(&ts1);

    /* Get RTP Prototype */
    puts("Get RTP Prototype");
    while (true) {
        get_timestamp(&ts2);

        is_t_out = sec != 0.0 && is_timeout(ts1, ts2, timer);

        if (is_t_out || !chk_rdy_fd(dev->fd, sec))
            return;

        dev->framelen = dev->rx_frame(dev);

        dissect_rx_data(dev, net, esp, txp, sip);

        if (txp->p == UDP && txp->plen != 0 && (strcmp(net->dst_ip, net->x_src_ip) == 0))
            break;
    }
    /* Forge RTP */
    /* IP and Port will be AUTO swaped when fmt_net_rep and fmt_txp_rep */

    strcpy(net->x_src_ip, net->dst_ip);
    strcpy(net->x_dst_ip, net->src_ip);
    txp->x_src_port = ntohs(txp->uhdr.dest);
    txp->x_dst_port = ntohs(txp->uhdr.source);

    /* Send RTP with Interval */
    puts("Send RTP with Interval");
    get_timestamp(&ts_intvl1);
    while (true) {
        get_timestamp(&ts2);
        get_timestamp(&ts_intvl2);

        is_t_out = is_timeout(ts1, ts2, timer);
        if (is_t_out)
            return;

        intvl_t_out = is_timeout(ts_intvl1, ts_intvl2, timer_intvl);
        if(intvl_t_out) {
            tx_udp_rep(*dev, *net, txp, txp->pl, txp->plen, 0);
            get_timestamp(&ts_intvl1);
        }
    }
    return;
}

/* Ring, 3G, VoLTE, VoWIFI, external */
int get_call_sys_type(Net *net , Sip *sip)
{
    if(net->opr == CHT) {
        if(sip->as != NULL && strcmp( sip->as, "45") == 0)
            return 0;
        /*
        if()
        	return 1;
        */
        /*
        if()
        	return 2;
        */
        if(sip->as != NULL && strcmp( sip->as, "41") == 0)
            return 3;
        if(sip->as != NULL && strcmp( sip->as, "38") == 0)
            return 4;
    }
    if(net->opr == TM) {
        if(sip->owner != NULL && strcmp( sip->owner, "SAMSUNG-IMS-UE") == 0)
            return 0;
        /*
        if()
        	return 1;
        */
        /*
        if()
        	return 2;
        */
        if(sip->as != NULL && strcmp( sip->as, "38") == 0)
            return 3;
        /*
        if()
        	return 4;
        */
    }
    return -1;
}

inline static void record_txp(Net *net, Esp *esp, Txp *txp)
{
    extern EspHeader esp_hdr_rec;

    if (net->nxt == ESP && strcmp(net->x_src_ip, net->src_ip) == 0) {
        esp_hdr_rec.spi = esp->hdr.spi;
        esp_hdr_rec.seq = ntohl(esp->hdr.seq);
    }

    if (txp->p == TCP && strcmp(net->x_src_ip, net->src_ip) == 0) {
        txp->x_tx_seq = ntohl(txp->thdr.th_seq) + txp->plen;
        txp->x_tx_ack = ntohl(txp->thdr.th_ack);
        txp->x_src_port = ntohs(txp->thdr.th_sport);
        txp->x_dst_port = ntohs(txp->thdr.th_dport);
    }

    if (txp->p == TCP && strcmp(net->x_src_ip, net->dst_ip) == 0) {
        txp->x_tx_seq = ntohl(txp->thdr.th_ack);
        txp->x_tx_ack = ntohl(txp->thdr.th_seq) + txp->plen;
        txp->x_src_port = ntohs(txp->thdr.th_dport);
        txp->x_dst_port = ntohs(txp->thdr.th_sport);
    }
}

void get_session_info(Dev *dev, Net *net, Esp *esp, Txp *txp, Sip *sip)
{
    extern EspHeader esp_hdr_rec;

    while(net->opr == APTG) {

        wait_sip(dev, net, esp, txp, sip, meth_null, stat_ok, 0, DISABLE_TCP_ACK);
        puts("OK");

        if(txp->p == TCP) {

            record_txp(net, esp, txp);
            break;
        }

        strcpy(net->x_src_ip, net->dst_ip);
        strcpy(net->x_dst_ip, net->src_ip);

    }

    wait_sip(dev, net, esp, txp, sip, meth_bye, stat_null, 0, DISABLE_TCP_ACK);
    puts("BYE");

    /* Since BYE message is sent from remote, the expected src/dst ports and
       expected src/dst addresses need to be assigned conversely */
    if(txp->p == TCP) {
        txp->x_src_port = ntohs(txp->thdr.th_dport);
        txp->x_dst_port = ntohs(txp->thdr.th_sport);
    }
    strcpy(net->x_src_ip, net->dst_ip);
    strcpy(net->x_dst_ip, net->src_ip);

    wait_sip(dev, net, esp, txp, sip, meth_null, stat_ok, 0, DISABLE_TCP_ACK);
    puts("OK");
    record_txp(net, esp, txp);

    wait_esp_tcp_ack(dev, net, esp, txp, sip, 5);
}

void get_twin_register_info(Dev *dev, Net *net, Esp *esp, Txp *txp, Sip *sip)
{
    extern EspHeader esp_hdr_rec;

    wait_sip(dev, net, esp, txp, sip, meth_reg, stat_null, 0, DISABLE_TCP_ACK);
    puts("REGISTER");

    dissect_link_hdr(dev);

    strcpy(net->x_src_ip, net->src_ip);
    strcpy(net->x_dst_ip, net->dst_ip);
    txp->x_src_port = ntohs(txp->uhdr.source);
    txp->x_dst_port = ntohs(txp->uhdr.dest);
    printf("kill the twinkle user (fuser -k [port]/udp)\n");
    printf("waiting for 10 seconds\n");
    sleep(10);
    puts("REGISTER FINISH");
    return ;
}
void get_register_info(Dev *dev, Net *net, Esp *esp, Txp *txp, Sip *sip)
{
    extern EspHeader esp_hdr_rec;

    wait_sip(dev, net, esp, txp, sip, meth_reg, stat_null, 0, DISABLE_TCP_ACK);
    puts("REGISTER");

    if(net->opr == SD) {
        dissect_link_hdr(dev);
        strcpy(net->x_src_ip, net->src_ip);
        strcpy(net->x_dst_ip, net->dst_ip);
        txp->x_src_port = ntohs(txp->uhdr.source);
        txp->x_dst_port = ntohs(txp->uhdr.dest);
        while (wait_sip(dev, net, esp, txp, sip, meth_reg_all, stat_reg_all, 5, DISABLE_TCP_ACK))
            ;
        puts("REGISTER FINISH");
        return ;
    }

    wait_sip(dev, net, esp, txp, sip, meth_reg, stat_null, 0, DISABLE_TCP_ACK);
    puts("REGISTER");

    strcpy(net->x_src_ip, net->src_ip);
    strcpy(net->x_dst_ip, net->dst_ip);

    if (txp->p == TCP) {
        txp->x_src_port = ntohs(txp->thdr.th_sport);
        txp->x_dst_port = ntohs(txp->thdr.th_dport);
    } else {
        txp->x_src_port = ntohs(txp->uhdr.source);
        txp->x_dst_port = ntohs(txp->uhdr.dest);
    }

    wait_sip(dev, net, esp, txp, sip, meth_null, stat_ok, 0, DISABLE_TCP_ACK);
    puts("OK");
    record_txp(net, esp, txp);


    wait_sip(dev, net, esp, txp, sip, meth_sub, stat_null, 0, DISABLE_TCP_ACK);
    puts("SUBSCRIBE");
    esp_hdr_rec.spi = esp->hdr.spi;

    while (wait_sip(dev, net, esp, txp, sip, meth_reg_all, stat_reg_all, 5, DISABLE_TCP_ACK)) {
        record_txp(net, esp, txp);
    }
    if(net->opr == CHT)
        esp->get_key(esp);

    puts("REGISTER FINISH");
}

void show_dissected_res(Dev *dev, Net *net, Esp *esp, Txp *txp, Sip *sip)
{
    dev->show_info(dev);
    net->show_info(net);
    esp->show_info(esp);
    txp->show_info(txp);
    sip->show_info(sip);
}

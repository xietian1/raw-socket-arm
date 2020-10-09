#ifndef _REPLAY_H
#define _REPLAY_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "sip.h"

#define LINKHDRLEN 14

#define DEFCALLID "+886912023292"

#define ENA_TCP_ACK true
#define DISABLE_TCP_ACK false

#define MAXBUFCOUNT 8

#ifndef _TYPEDEF_STRUCT_DEV
#define _TYPEDEF_STRUCT_DEV
typedef struct dev Dev;
#endif

#ifndef _TYPEDEF_STRUCT_NET
#define _TYPEDEF_STRUCT_NET
typedef struct net Net;
#endif

#ifndef _TYPEDEF_STRUCT_ESP
#define _TYPEDEF_STRUCT_ESP
typedef struct esp Esp;
#endif

#ifndef _TYPEDEF_STRUCT_TXP
#define _TYPEDEF_STRUCT_TXP
typedef struct txp Txp;
#endif

#ifndef _TYPEDEF_STRUCT_SIP
#define _TYPEDEF_STRUCT_SIP
typedef struct sip Sip;
#endif

struct frame_arr {

    uint8_t frame[MAXBUFCOUNT][65535];
    uint16_t framelen[MAXBUFCOUNT];
    long msec[MAXBUFCOUNT];

    ssize_t count;
};

extern struct frame_arr frame_buf;

void init_frame_buf();

void flush_frame_buf(Dev *dev,
                     struct timespec msec);

/* Dissect receive data to L3 and L4 header and SIP, if it is not a SIP message,
   dissect L3 and L4 only. Return the pointer point to L5 data */
uint8_t *dissect_rx_data(Dev *dev, Net *net, Esp *esp, Txp *txp, Sip *sip);

uint8_t *dissect_rx_net(Dev *dev, Net *net);

/* The argument sec is the timeout in second. If there is not any packets
   receviced in the time, it returns NULL. If sec is 0, function does not return
   until recevicing the TCP ACK */
uint8_t *wait_esp_tcp_ack(Dev *dev,
                          Net *net,
                          Esp *esp,
                          Txp *txp,
                          Sip *sip,
                          double sec);

uint8_t *wait_esp_tcp_seq(Dev *dev,
                          Net *net,
                          Esp *esp,
                          Txp *txp,
                          Sip *sip,
                          double sec);

/* Sending ESP tcp ack, according to data in the structure */
ssize_t tx_esp_tcp_ack(Dev *dev, Net *net, Esp *esp, Txp *txp);


/* The argument sec is the timeout in second. If there is not any packets
   receviced in the time, it returns NULL. If sec is 0, function does not return
   until recevicing the relative SIP request message */
uint8_t *wait_sip_req(Dev *dev,
                      Net *net,
                      Esp *esp,
                      Txp *txp,
                      Sip *sip,
                      SipMeths m,
                      double sec,
                      bool enable_ack);


/* The argument sec is the timeout in second. If there is not any packets
   receviced in the time, it returns NULL. If sec is 0, function does not return
   until recevicing the relative SIP status message */
uint8_t *wait_sip_sta(Dev *dev,
                      Net *net,
                      Esp *esp,
                      Txp *txp,
                      Sip *sip,
                      SipStats c,
                      double sec,
                      bool enable_ack);

uint8_t *wait_sip_all_stac(Dev *dev,
                           Net *net,
                           Esp *esp,
                           Txp *txp,
                           Sip *sip,
                           SipStats *target,
                           double sec,
                           bool enable_ack);

uint8_t *wait_sip_all_meth(Dev *dev,
                           Net *net,
                           Esp *esp,
                           Txp *txp,
                           Sip *sip,
                           SipMeths *target,
                           double sec,
                           bool enable_ack);

uint8_t *wait_sip(Dev *dev,
                  Net *net,
                  Esp *esp,
                  Txp *txp,
                  Sip *sip,
                  SipMeths *req_arr,
                  SipStats *sta_arr,
                  double sec,
                  bool enable_ack);

uint8_t *wait_pkt(Dev *dev,
                  Net *net,
                  double sec);

/* Sending ESP sip invite, according to data in the structure */
ssize_t tx_sip_inv(Dev *dev,
                   Net *net,
                   Esp *esp,
                   Txp *txp,
                   Sip *sip,
                   char *fname[2],
                   long msec);


/* Sending ESP sip prack, according to data in the structure */
ssize_t tx_sip_prack(Dev *dev,
                     Net *net,
                     Esp *esp,
                     Txp *txp,
                     Sip *sip,
                     char *fname);


ssize_t tx_sip_ok(Dev *dev,
                  Net *net,
                  Esp *esp,
                  Txp *txp,
                  Sip *sip,
                  char *fname[2],
                  long msec);


ssize_t tx_sip_ack(Dev *dev,
                   Net *net,
                   Esp *esp,
                   Txp *txp,
                   Sip *sip,
                   char *fname);


ssize_t tx_sip_cancel(Dev *dev,
                      Net *net,
                      Esp *esp,
                      Txp *txp,
                      Sip *sip,
                      char *fname[2],
                      long msec);

ssize_t tx_sip_update(Dev *dev,
                      Net *net,
                      Esp *esp,
                      Txp *txp,
                      Sip *sip,
                      char *fname[2],
                      long msec);


ssize_t tx_pkt(Dev *dev,
               Net *net);

ssize_t tx_sip_by_stac(Dev *dev,
                       Net *net,
                       Esp *esp,
                       Txp *txp,
                       Sip *sip);

void kpt_session_alive(Dev *dev,
                       Net *net,
                       Esp *esp,
                       Txp *txp,
                       Sip *sip,
                       double sec);

int get_call_sys_type(Net *net,
                      Sip *sip);

/* Get ESP and TCP informtaion from call flow */
void get_session_info(Dev *dev, Net *net, Esp *esp, Txp *txp, Sip *sip);

void get_twin_register_info(Dev *dev, Net *net, Esp *esp, Txp *txp, Sip *sip);
/* Get ESP and TCP informtaion from registration flow */
void get_register_info(Dev *dev, Net *net, Esp *esp, Txp *txp, Sip *sip);

void show_dissected_res(Dev *dev, Net *net, Esp *esp, Txp *txp, Sip *sip);

#endif

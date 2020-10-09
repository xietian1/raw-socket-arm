#ifndef _ESP_H
#define _ESP_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/ip.h>

#include "net.h"

/* Authentication data length of HMAC-SHA1-96 is 96 bits */
#define MAXESPPADLEN 3
#define MAXESPPLEN \
    IP_MAXPACKET - sizeof(EspHeader) - sizeof(EspTrailer) - HMAC96AUTHLEN

#ifndef _TYPEDEF_STRUCT_TXP
#define _TYPEDEF_STRUCT_TXP
typedef struct txp Txp;
#endif

#ifndef _TYPEDEF_STRUCT_ESP
#define _TYPEDEF_STRUCT_ESP
typedef struct esp Esp;
#endif

typedef struct esp_header EspHeader;
typedef struct esp_trailer EspTrailer;

typedef struct esp_header_iv EspHeaderIV;

struct esp_header {
    uint32_t spi;
    uint32_t seq;
};


struct esp_header_iv {
    uint32_t spi;
    uint32_t seq;
    uint32_t iv;
};


struct esp_trailer {
    uint8_t pad_len;
    uint8_t nxt;
};

struct esp {
    EspHeader hdr;

    uint8_t *pl; /* Not include ESP padding */
    size_t plen; /* Not include ESP padding */


    uint8_t *pad; /* Padding content, and padding length is in EspTrailer */

    EspTrailer tlr;

    uint8_t *auth;
    size_t authlen;

    uint8_t *esp_key;

    uint8_t *(*set_padpl)(Esp *self, size_t esp_plen);
    uint8_t *(*set_auth)(Esp *self,
                         ssize_t (*hmac)(uint8_t const *, size_t,
                                         uint8_t const *, size_t,
                                         uint8_t *));

    bool (*get_key)(Esp *self);
    ssize_t (*fmt_esppkt)(Esp *self, uint8_t *buf, size_t buflen);
    uint8_t *(*dissect)(Esp *self, uint8_t *esp_pkt, size_t esp_len);
    Esp *(*fmt_rep)(Esp *self, Proto p);
    void (*show_info)(Esp *self);

    //add: get esp key
    bool (*get_att_esp_key)(Esp *self);

};


/**
 * init_esp()
 * Initialize esp structure contents.
 *
 * @self: pointer to esp structure to be initialized
 */
void init_esp(Esp *self);

uint8_t *set_esp_pad(Esp *self, size_t esp_plen);

/**
 * set_esp_auth()
 * Set ESP authentication data (@self->auth) and the length of ESP
 * authentication data (@self->authlen). @self->authlen is set to be equal to
 * @authlen, and the rule of setting @self->auth is according to the @hmac
 * function.
 *
 * @self: Esp structure used to provide information for setting auth data
 * @hmac: the method which calculates the auth data value
 */
uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *));

bool get_esp_key(Esp *self);

/**
 * fmt_esp_pkt()
 * Format @buf as an ESP packet includes ESP header, ESP payload, ESP padding,
 * ESP trailer and ESP authentication data.
 *
 * @self: Esp structure used to provide information for formatting ESP packets
 * @buf: pointer to buffer used to store ESP packets
 * @buflen: the rest of size used to store ESP packets
 */
ssize_t fmt_esp_pkt(Esp *self, uint8_t *buf, size_t buflen);

/**
 * dissect_esp()
 * Dissect ESP header, trailer, and authentication data from incoming packets.
 * Return a pointer point to the begining of next header in @esp_pkt.
 *
 * @self: to be filled Esp structure
 * @esp_pkt: pointer to ESP header in the packet
 * @esp_len: length from ESP header to the end of whole packet
 */
uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len);

Esp *fmt_esp_rep(Esp *self, Proto p);

void show_esp_info(Esp *self);


bool get_att_key_from_channel(Esp *self);

void convertstring (char * input, uint8_t ** r, int length);

#endif

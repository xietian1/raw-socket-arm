#ifndef _SIP_H
#define _SIP_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define MAXSIPACTIVENO 16

#define MCOOKIE "z9hG4bK"

#define MAXFLDNUM 128
#define IDENTITYBUFLEN 32
#define FROMTAGBUFLEN 128
#define TOTAGBUFLEN 128
#define CALLIDBUFLEN 128
#define BRACHIDBUFLEN 128
#define CSEQBUFLEN 8
#define CONTENTLENBUFLEN 8
#define OWNERLEN 128
#define ASLEN 128
#define AUDIOSPORTBUFLEN 8

#define MESSAGEBUFFERLEN 8192

#define SDPPROTOTYPELEN 610 // ori
//#define SDPPROTOTYPELEN 223
#define IPV4SDPPROTOTYPELEN 826 // ori
//#define IPV4SDPPROTOTYPELEN 265
//#define IPV4SDPPROTOTYPELEN 829 // session name
//#define IPV4SDPPROTOTYPELEN 429 // ori
#define APTGSDPPROTOTYPELEN 623
//#define APTGSDPPROTOTYPELEN 828
//#define APTGSDPPROTOTYPELEN 443 // ori zf4?
//#define APTGSDPPROTOTYPELEN 427 // ori u11
#define VRZSDPPROTOTYPELEN 833 // ori pixel xl?
#define SDSDPPROTOTYPELEN 364 // SIPDROID
//#define SDSDPPROTOTYPELEN 451 // SIPDROID SP

/* These implementations are based on RFC 3261, WiKi page "List of SIP request
   methods", and consider there's no null byte (0x00) in SIP messages
   (RFC 5322 Section 2.2) */
#ifndef _TYPEDEF_STRUCT_NET
#define _TYPEDEF_STRUCT_NET
typedef struct net Net;
#endif

#ifndef _TYPEDEF_STRUCT_SIP
#define _TYPEDEF_STRUCT_SIP
typedef struct sip Sip;
#endif

extern char *invite[2];
extern char *cancel[2];
extern char *update[2];
extern char *ack;
extern char *prack;
extern char *bye;
extern char *ok[2];

extern Sip dub_sip;

typedef enum sip_types {
    UNKN_SIPTYPE = 0,
    REQ,
    STA
} SipTypes;

typedef enum sip_methods {
    UNKN_METH = 0,
    REG,
    SUB,
    NOTF,
    PUBL,
    INV,
    PRACK,
    CANC,
    ACK,
    UPDT,
    BYE
} SipMeths;

typedef enum sip_status {
    UNKN_STAT = 0,
    TRY = 100,
    RING = 180,
    CALLBF = 181,
    SPROC = 183,
    OK = 200,
    UNAUTH = 401,
    CALLNE = 481,
    REQTERM = 487,
    SEVRERR = 500,
    DECLINE = 603
} SipStats;

extern SipMeths meth_reg[2];
extern SipMeths meth_sub[2];
extern SipMeths meth_bye[2];
extern SipMeths meth_reg_all[5]; // REG, SUB, NOTF, PUBL, null
extern SipMeths meth_null[1];
extern SipMeths meth_inv[2];
extern SipMeths meth_prack[2];
extern SipMeths meth_invprack[3];

extern SipStats stat_ok[2];
extern SipStats stat_reg_all[2]; // OK, null
extern SipStats stat_null[1];

struct sip {
    bool is_used;

    SipTypes st;
    float sv; /* SIP version */

    union {
        SipMeths meth;
        SipStats stac; /* SIP Status Code */
    };

    union {
        char *r_uri; /* SIP Request-URI */
        char *r_phra; /*SIP Reason-Phrase */
    };

    size_t linelen;

    char *caller_id;
    char *callee_id;
    char *from_tag;
    char *to_tag;
    char *call_id;
    char *branch_id;
    char *cseq;
    char *cont_len; /* SIP Content-Length, which is SDP length in our cases */
    char *owner;
    char *as;
    char *audio_sport;
    char *src_port;

    char *ex_branch_id[4];

    uint8_t *msg_buf;
    ssize_t msg_len;
    bool push_flag;
    bool diss_flag;

    bool dos_attackable; /* detection for dos attack */

    Sip *(*gen_flds)(Net *net, char *caller_id, char *callee_id, Sip *self);
    uint8_t *(*dissect)(Sip *self, uint8_t *sip_msg, size_t msg_len);
    bool (*get_flds)(Sip *self);
    void (*show_info)(Sip *self);

    SipStats rep_stac;
    struct timespec ts;
};

void init_sip(Sip *self);

int get_first_fresh_sip_idx(Sip *self_arr, size_t arr_len);

int get_match_sip_idx(Sip *self, Sip *self_arr, size_t arr_len);

int get_nxt_used_sip_idx(Sip *self_arr, size_t arr_len, size_t pos);

double get_wait_t_out(Sip *self);

void cpy_to_tag(Sip *rep_sip, Sip *self);

void upda_rep_stac(Sip *rep_sip, Sip *self);

uint8_t *dissect_sip(Sip *self, uint8_t *sip_msg, size_t msg_len);

bool get_sip_flds(Sip *self);

Sip *chg_sip_branch_id(Sip *self);

Sip *gen_sip_flds(Net *net, char *caller_id, char *callee_id, Sip *self);

void show_sip_info(Sip *self);

ssize_t compose_sip(Net *net, Sip *self, uint8_t *buf, size_t buf_len);

bool ck_t_out(Sip *sip);

bool chk_match_sip_meth(SipMeths meth, SipMeths *meth_arr);

bool chk_match_sip_stat(SipStats stat, SipStats *stat_arr);
#endif

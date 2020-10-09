#include <stdio.h>
#include <string.h>

#include "sip.h"
#include "utils.h"
#include "replay.h"

char *invite[2] = {"inv1.bin", "inv2.bin"};
char *cancel[2] = {"can1.bin", "can2.bin"};
char *update[2] = {"update1.bin", "update2.bin"};
char *ack = "ack.bin";
char *prack = "prack.bin";
char *bye = "bye.bin";
char *ok[2] = {"ok1.bin", "ok2.bin"};

SipMeths meth_reg[2] = {REG, UNKN_METH};
SipMeths meth_sub[2] = {SUB, UNKN_METH};
SipMeths meth_bye[2] = {BYE, UNKN_METH};
SipMeths meth_reg_all[5] = {REG, SUB, NOTF, PUBL, UNKN_METH};
SipMeths meth_inv[2] = {INV, UNKN_METH};
SipMeths meth_prack[2] = {PRACK, UNKN_METH};
SipMeths meth_invprack[3] = {INV, PRACK, UNKN_METH};
SipMeths meth_null[1] = {UNKN_METH};

SipStats stat_ok[2] = {OK, UNKN_STAT};
SipStats stat_reg_all[2] = {OK, UNKN_STAT};
SipStats stat_null[1] = {UNKN_STAT};

Sip dub_sip;

inline static float get_ver(char *version)
{
    if (strncmp(version, "SIP/", strlen("SIP/")) != 0) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1.0;
    }

    float v;

    v = strtof(version + strlen("SIP/"), NULL);

    return v == 0 ? -1.0 : v;
}


inline static SipMeths get_meth(char *method)
{
    SipMeths meth;

    meth = strcmp(method, "REGISTER") == 0 ? REG :
           strcmp(method, "SUBSCRIBE") == 0 ? SUB :
           strcmp(method, "NOTIFY") == 0 ? NOTF :
           strcmp(method, "PUBLISH") == 0 ? PUBL :
           strcmp(method, "INVITE") == 0 ? INV :
           strcmp(method, "PRACK") == 0 ? PRACK :
           strcmp(method, "CANCEL") == 0 ? CANC :
           strcmp(method, "ACK") == 0 ? ACK :
           strcmp(method, "UPDATE") == 0 ? UPDT :
           strcmp(method, "BYE") == 0 ? BYE :
           UNKN_METH;

    return meth;
}


inline static SipStats get_stac(char *status)
{
    short stat_code = strtol(status, NULL, 10);

    if (stat_code != 100 && stat_code != 180 && stat_code != 181 && stat_code != 183 &&
            stat_code != 200 && stat_code != 401 && stat_code != 481 &&
            stat_code != 487 && stat_code != 500 && stat_code != 603) {
        return UNKN_STAT;
    }

    return stat_code;
}


inline static uint8_t *dissect_req(Sip *self, uint8_t *sip_msg, size_t msg_len)
{
    ssize_t nfld;
    SipMeths meth;

    char *line;
    char *fld[MAXFLDNUM + 1];
    char *msg = strdup((char *)sip_msg);

    /**
     * According to RFC 3261, "\r\n" is used to separate Request-Line and SIP
     * header.
     * Note that here we consider there's no '\0' in SIP message.
     */
    line = strtok(msg, "\r\n");
    if(line != NULL)
        self->linelen = strlen(line) * sizeof(char);
    else
        return NULL;

    /**
     * According to RFC 3261, a space is used to separate Method, Request-URI,
     * and SIP version.
     */
    nfld = parse_input((char *)line, fld, " ");

    meth = get_meth(fld[0]);
    if (nfld < 0 || nfld > MAXFLDNUM || meth == UNKN_METH) {
        FREE(msg);
        FREE(*fld);
        return NULL;
    }

    FREE(self->r_uri);

    self->meth = meth;
    self->r_uri = strdup(fld[1]);
    self->sv = get_ver(fld[2]);

    FREE(msg);
    FREE(*fld);
    return sip_msg + self->linelen;
}


inline static uint8_t *dissect_sta(Sip *self, uint8_t *sip_msg, size_t msg_len)
{
    ssize_t nfld;
    SipStats stat;

    char *line;
    char *fld[MAXFLDNUM + 1];
    char *msg = strdup((char *)sip_msg);

    /**
     * According to RFC 3261, "\r\n" is used to separate Status-Line and SIP
     * header.
     * Note that here we consider there's no '\0' in SIP message.
     */
    line = strtok(msg, "\r\n");
    self->linelen = strlen(line) * sizeof(char);

    /**
     * According to RFC 3261, a space is used to separate SIP version,
     * Status-Code, and Reason-Phrase.
     */
    nfld = parse_input((char *)line, fld, " ");

    if((strncmp(fld[0], "SIP/2.0", strlen("SIP/2.0")) != 0) || nfld < 3) {
        //printf("Invalid Status Line\n");
        FREE(msg);
        FREE(*fld);
        return NULL;
    }

    stat = get_stac(fld[1]);
    if (nfld < 0 || nfld > MAXFLDNUM || stat == UNKN_STAT) {
        FREE(msg);
        FREE(*fld);
        return NULL;
    }

    FREE(self->r_phra);

    self->stac = stat;
    self->sv = get_ver(fld[0]);
    self->r_phra = strdup(fld[2]);

    FREE(msg);
    FREE(*fld);
    return sip_msg + self->linelen;
}


inline static uint8_t *dissect_line(Sip *self, uint8_t *sip_msg, size_t msg_len)
{
    uint8_t *shdr = NULL;

    /**
     * If dissect_req returns a pointer point to header, which means method is
     * matched, so this SIP message is Request message. Otherwise, this message
     * is Status message or even not a SIP message.
     */
    shdr = dissect_req(self, sip_msg, msg_len);

    if (shdr) {
        self->st = REQ;
    }

    if (strncmp((char *)sip_msg, "SIP", strlen("SIP")) == 0) {
        self->st = STA;
        shdr = dissect_sta(self, sip_msg, msg_len);
    }

    return shdr;
}


inline static bool get_sip_from_info(Sip *self, char *from)
{
    if (!from)
        return false;

    bool dirty_callerid = false, dirty_fromtag = false;
    ssize_t nfld;
    char *fld[MAXFLDNUM + 1] = {NULL};

    nfld = parse_input((char *)from, fld, "<@;\r\n");

    for (int i = 0; i < nfld; i++) {
        if (strncmp(fld[i], "sip:", strlen("sip:")) == 0) {
            strcpy(self->caller_id, fld[i] + strlen("sip:"));
            dirty_callerid = true;
        }

        if (strncmp(fld[i], "tag=", strlen("tag=")) == 0) {
            strcpy(self->from_tag, fld[i] + strlen("tag="));
            dirty_fromtag = true;
        }

        if (dirty_callerid && dirty_fromtag)
            break;
    }

    FREE(*fld);

    return dirty_callerid && dirty_fromtag;
}


inline static bool get_sip_to_info(Sip *self, char *to)
{
    if (!to)
        return false;

    bool dirty_calleeid = false, dirty_totag = false;
    ssize_t nfld;
    char *fld[MAXFLDNUM + 1] = {NULL};

    nfld = parse_input((char *)to, fld, "<@;\r\n");

    for (int i = 0; i < nfld; i++) {
        if (strncmp(fld[i], "sip:", strlen("sip:")) == 0) {
            strcpy(self->callee_id, fld[i] + strlen("sip:"));
            dirty_calleeid = true;
        }

        if (strncmp(fld[i], "tag=", strlen("tag=")) == 0) {
            strcpy(self->to_tag, fld[i] + strlen("tag="));
            dirty_totag = true;
        }

        if (dirty_calleeid && dirty_totag)
            break;
    }

    FREE(*fld);

    return dirty_calleeid && dirty_totag;
}


inline static char *get_sip_callid(Sip *self, char *callid)
{
    if (!callid)
        return NULL;

    strcpy(self->call_id, callid + strlen("Call-ID: "));

    return self->call_id;
}


inline static char *get_sip_branchid(Sip *self, char *via)
{
    if (!via)
        return NULL;

    ssize_t nfld;
    char *fld[MAXFLDNUM + 1] = {NULL};

    nfld = parse_input((char *)via, fld, ";,");

    int i = 0, j = 0;
    for (; i < nfld; i++) {
        if (strncmp(fld[i], "branch=", strlen("branch=")) == 0) {
            strcpy(self->branch_id, fld[i] + strlen("branch="));
            break;
        }
    }
    for(i = i + 1 ; i < nfld; i++) {
        if (strncmp(fld[i], "branch=", strlen("branch=")) == 0) {
            strcpy(self->ex_branch_id[j], fld[i] + strlen("branch="));
            j++;
        }
    }

    FREE(*fld);

    return self->branch_id;

}


inline static char *get_sip_cseq(Sip *self, char *cs)
{
    if (!cs)
        return NULL;

    char *fld[MAXFLDNUM + 1] = {NULL};

    parse_input((char *)cs, fld, " ");
    strcpy(self->cseq, fld[1]);

    return self->cseq;

}


inline static char *get_sip_contlen(Sip *self, char *contlen)
{
    if (!contlen)
        return NULL;

    strcpy(self->cont_len, contlen + strlen("Content-Length: "));

    return self->cont_len;

}

inline static char *get_sip_owner(Sip *self, char *owner)
{
    if (!owner)
        return NULL;
    char tmp[128];

    sscanf(owner, "o=%[^ ]", tmp);
    strcpy(self->owner, tmp);

    return self->owner;

}

inline static char *get_sip_as(Sip *self, char *as)
{
    if (!as) {
        self->as = NULL;
        return NULL;
    } else
        self->as = (char *)malloc(ASLEN * sizeof(char));
    char tmp[128];

    sscanf(as, "b=AS:%[^ ]", tmp);
    strcpy(self->as, tmp);

    return self->as;

}

bool get_sip_flds(Sip *self)
{
    self->diss_flag = false; /* assume the last diss */

    if( self->msg_len == 0) {
        printf("get_sip_flds() : size 0");
        return NULL;
    }

    ssize_t nfld;

    char *from = NULL;
    char *to = NULL;
    char *call_id = NULL;
    //char *via = NULL;
    char via[4096];
    char *cs = NULL;
    char *cont_len = NULL;
    char *owner = NULL;
    char *as = NULL;

    char *fld[MAXFLDNUM + 1] = {NULL};

    // printf("\n===================\n%s\n####################\n\n",(char *)(self->msg_buf));
    fflush(stdout);
    uint8_t *data = dissect_sta(self, self->msg_buf, self->msg_len);

    memset(via, 0, 4096);
    memset(self->owner, 0, OWNERLEN);

    if(data == NULL) {
        data = dissect_req(self, self->msg_buf, self->msg_len);

        if(data == NULL) {
            printf("BROKEN SEGMENT\n");

            memset(self->msg_buf, 0, MESSAGEBUFFERLEN);
            self->msg_len = 0;
            self->push_flag = true;
            self->diss_flag = false;
            return NULL;
        }
    }
    nfld = parse_input((char *)(data), fld, "\r\n");
    /* parse: */
    for (int i = 0; i < nfld; i++) {
        if (strncmp(fld[i], "From: ", strlen("From: ")) == 0 && !from)
            from = fld[i];

        if (strncmp(fld[i], "To: ", strlen("To: ")) == 0 && !to)
            to = fld[i];

        if (strncmp(fld[i], "Call-ID: ", strlen("Call-ID: ")) == 0 && !call_id)
            call_id = fld[i];
        /*
        if (strncmp(fld[i], "Via: ", strlen("Via: ")) == 0 && !via)
            via = fld[i];
        */

        if (strncmp(fld[i], "Via: ", strlen("Via: ")) == 0 ) {
            strcat(via,fld[i]);
            strcat(via,";");
        }

        if (strncmp(fld[i], "CSeq: ", strlen("CSeq: ")) == 0 && !cs)
            cs = fld[i];

        if (strncmp(fld[i], "Content-Length: ", strlen("Content-Length: ")) == 0
                && !cont_len)
            cont_len = fld[i];

        if (strncmp(fld[i], "o=", strlen("o=")) == 0 && !owner)
            owner = fld[i];

        if (strncmp(fld[i], "b=AS:", strlen("b=AS:")) == 0 && !as)
            as = fld[i];

        if (strncmp(fld[i], "SIP/2.0 ", strlen("SIP/2.0 ")) == 0 ) {
            self->diss_flag = true; /* there is another SIP */
            break;
        }
    }

    if(self->diss_flag) {
        char buf[MESSAGEBUFFERLEN];
        uint8_t *nxt_sp = (uint8_t *)strstr((char *)data, "SIP/2.0 ");
        int len = nxt_sp - self->msg_buf;

        memcpy(buf, self->msg_buf + len, (self->msg_len - len));
        memcpy(self->msg_buf, buf, (self->msg_len - len));
        memset(self->msg_buf + (self->msg_len -len), 0, len);
        self->msg_len -= len;
    }

    // printf("diss f = %d, push f = %d\n",(self->diss_flag == true)?1:0,(self->push_flag == true)?1:0 );
    fflush(stdout);
    if(!self->diss_flag && !self->push_flag)
        return NULL;

    if(!self->diss_flag && self->push_flag) {
        memset(self->msg_buf, 0, MESSAGEBUFFERLEN);
        self->msg_len = 0;
        self->push_flag = true;
    }

    get_sip_from_info(self, from);
    get_sip_to_info(self, to);
    get_sip_callid(self, call_id);
    get_sip_branchid(self, via);
    get_sip_cseq(self, cs);
    get_sip_contlen(self, cont_len);
    get_sip_owner(self, owner);
    get_sip_as(self, as);


    FREE(*fld);

    return true;
}


void init_sip(Sip *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->is_used= false;
    self->r_uri = NULL;

    self->dos_attackable = false;

    /* Only to_tag uses calloc() since its initial value may be reviewed */
    self->caller_id = (char *)malloc(IDENTITYBUFLEN * sizeof(char));
    self->callee_id = (char *)malloc(IDENTITYBUFLEN * sizeof(char));
    self->from_tag = (char *)malloc(FROMTAGBUFLEN * sizeof(char));
    self->to_tag = (char *)calloc(TOTAGBUFLEN, sizeof(char));
    self->call_id = (char *)malloc(CALLIDBUFLEN * sizeof(char));
    self->branch_id = (char *)malloc(BRACHIDBUFLEN * sizeof(char));
    self->cseq = (char *)malloc(CSEQBUFLEN * sizeof(char));
    self->cont_len = (char *)malloc(CONTENTLENBUFLEN * sizeof(char));
    self->owner = (char *)malloc(OWNERLEN * sizeof(char));
    self->audio_sport = (char *)calloc(AUDIOSPORTBUFLEN, sizeof(char));
    self->src_port = (char *) malloc(5 * sizeof(char)); // port is u_short

    for(int i=0; i<4; i++)
        self->ex_branch_id[i] = (char *)malloc(BRACHIDBUFLEN * sizeof(char));

    self->as = (char *)malloc(ASLEN * sizeof(char));
    self->msg_buf = (uint8_t *)malloc(MESSAGEBUFFERLEN * sizeof(char));
    self->msg_len = 0;
    self->push_flag = true;
    self->diss_flag = false;

    self->gen_flds = gen_sip_flds;
    self->dissect = dissect_sip;
    self->get_flds = get_sip_flds;
    self->show_info = show_sip_info;

    self->rep_stac = UNKN_STAT;
}


int get_first_fresh_sip_idx(Sip *self_arr, size_t arr_len)
{
    for (size_t i = 0; i < arr_len; i++) {
        if (!(self_arr + i)->is_used)
            return i;
    }

    return -1;
}


int get_match_sip_idx(Sip *self, Sip *self_arr, size_t arr_len)
{
    size_t i;

    for (i = 0; i < arr_len; i++) {
        if (strcmp(self->from_tag, self_arr[i].from_tag) == 0 &&
                strcmp(self->call_id, self_arr[i].call_id) == 0 &&
                strcmp(self->branch_id, self_arr[i].branch_id) == 0 &&
                strcmp(self->callee_id, self_arr[i].callee_id) == 0 &&
                strcmp(self->caller_id, self_arr[i].caller_id) == 0)
            return i;
    }

    return -1;
}


int get_nxt_used_sip_idx(Sip *self_arr, size_t arr_len, size_t pos)
{
    size_t end = (int)(pos - 1) < 0 ? arr_len + pos - 1 : pos - 1;

    for (size_t i = pos; i != end; i = (i + 1) % arr_len) {
        if ((self_arr + i)->is_used)
            return i;
    }

    return -1;
}

double get_wait_t_out(Sip *self)
{
    return (self->rep_stac == UNKN_STAT) ? 1 :
           (self->rep_stac == TRY) ? 10 :
           (self->rep_stac == SPROC) ? 3 : -1;
}

void cpy_to_tag(Sip *rep_sip, Sip *self)
{
    if(rep_sip->stac == TRY)
        return;

    strcpy(self->to_tag, rep_sip->to_tag);
    return;
}

void upda_rep_stac(Sip *rep_sip, Sip *self)
{
    self->rep_stac = rep_sip->stac;
    return;
}

uint8_t *dissect_sip(Sip *self, uint8_t *sip_msg, size_t msg_len)
{
    if (!self || !sip_msg) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return NULL;
    }
    self->st = UNKN_SIPTYPE;

    if (msg_len == 0)
        return NULL;

    uint8_t *shdr;

    shdr = dissect_line(self, sip_msg, msg_len);
    if (!shdr) /* Not a SIP message */
        return NULL;

    /* get_sip_flds(self, shdr, msg_len - self->linelen); */

    return shdr;
}


Sip *chg_sip_branch_id(Sip *self)
{
    /* Magic cookie is used to identify the RFC 3261 created branch value */
    strcpy(self->branch_id, MCOOKIE);
    gen_rnd_str(self->branch_id + strlen(MCOOKIE), 9);
    strcpy(self->branch_id + strlen(MCOOKIE) + 9, "smg");

    return self;
}


Sip *gen_sip_flds(Net *net, char *caller_id, char *callee_id, Sip *self)
{
    strcpy(self->caller_id, caller_id ? caller_id : DEFCALLID);
    strcpy(self->callee_id, callee_id);

    gen_rnd_str(self->from_tag, 9);

    gen_rnd_str(self->call_id, 10);
    sprintf(self->call_id, "%s@%s", self->call_id, net->x_src_ip);

    gen_rnd_str(self->owner, 14);

    chg_sip_branch_id(self);

    if(net->opr == CHT) {
#ifdef ARM
        sprintf(self->cont_len, "%d", strlen(net->x_src_ip) * 2 + IPV4SDPPROTOTYPELEN);
#else
        sprintf(self->cont_len, "%lu", strlen(net->x_src_ip) * 2 + IPV4SDPPROTOTYPELEN);
#endif
    } else if(net->opr == APTG) {
#ifdef ARM
        sprintf(self->cont_len, "%d", strlen(net->x_src_ip) * 2 + APTGSDPPROTOTYPELEN);
#else
        sprintf(self->cont_len, "%lu", strlen(net->x_src_ip) * 2 + APTGSDPPROTOTYPELEN);
#endif
    } else if(net->opr == VRZ) {
#ifdef ARM
        sprintf(self->cont_len, "%d", strlen(net->x_src_ip) * 2 + VRZSDPPROTOTYPELEN);
#else
        sprintf(self->cont_len, "%lu", strlen(net->x_src_ip) * 2 + VRZSDPPROTOTYPELEN);
#endif
    } else if(net->opr == SD) {
#ifdef ARM
        sprintf(self->cont_len, "%d", strlen(net->x_src_ip) * 2 + SDSDPPROTOTYPELEN);
#else
        sprintf(self->cont_len, "%lu", strlen(net->x_src_ip) * 2 + SDSDPPROTOTYPELEN);
#endif
    } else if (net->ipv == IPv6) {
#ifdef ARM
        sprintf(self->cont_len, "%d", strlen(net->x_src_ip) * 2 + SDPPROTOTYPELEN);
#else
        sprintf(self->cont_len, "%lu", strlen(net->x_src_ip) * 2 + SDPPROTOTYPELEN);
#endif
    }

    strcpy(self->audio_sport, "12");
    gen_rnd_str(self->audio_sport + strlen("12"), 2);

    return self;
}

void show_sip_info(Sip *self)
{
    if (!self)
        return;

    printf("SIP version: %f\n", self->sv);

    if (self->st == REQ) {
        puts("SIP type: REQUEST");

        printf("SIP method: %d\n", self->meth);
        printf("SIP request URI: %s\n", self->r_uri);
    } else if (self->st == STA) {
        puts("SIP type: STATUS");

        printf("SIP status code: %d\n", self->stac);
        printf("SIP reason phrase: %s\n", self->r_phra);
    } else {
        fprintf(stderr, "Unknwon SIP type.\n");
        return;
    }

    printf("SIP Caller ID: %s\n", self->caller_id);
    printf("SIP Callee ID: %s\n", self->callee_id);
    printf("SIP From tag: %s\n", self->from_tag);
    printf("SIP To tag: %s\n", self->to_tag);
    printf("SIP Call ID: %s\n", self->call_id);
    printf("SIP Branch ID: %s\n", self->branch_id);
    printf("SIP Content Length: %s\n", self->cont_len);
}

ssize_t compose_sip(Net *net, Sip *self, uint8_t *buf, size_t buf_len)
{
    if (!net || !self || !buf) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb = buf_len;
    ssize_t upp_dstipaddrlen;
    char upp_dstip[INET6_ADDRSTRLEN];

    strcpy(upp_dstip, net->x_dst_ip);
    upp_dstipaddrlen = cnv_low_to_up(upp_dstip);

    Data sym[] = {
        {(uint8_t *)"LOW_SRC_IP", strlen("LOW_SRC_IP")},
        {(uint8_t *)"LOW_DST_IP", strlen("LOW_DST_IP")},
        {(uint8_t *)"UPP_DST_IP", strlen("UPP_DST_IP")},

        {(uint8_t *)"CALLER_ID", strlen("CALLER_ID")},
        {(uint8_t *)"CALLEE_ID", strlen("CALLEE_ID")},
        {(uint8_t *)"FROM_TAG", strlen("FROM_TAG")},
        {(uint8_t *)"TO_TAG", strlen("TO_TAG")},
        {(uint8_t *)"CALL_ID", strlen("CALL_ID")},
        {(uint8_t *)"BRANCH_ID", strlen("BRANCH_ID")},
        {(uint8_t *)"CSEQ", strlen("CSEQ")},
        {(uint8_t *)"CONT_LEN", strlen("CONT_LEN")},
        {(uint8_t *)"OWNER", strlen("OWNER")},
        {(uint8_t *)"EX_BRA_ID0", strlen("EX_BRA_ID0")},
        {(uint8_t *)"EX_BRA_ID1", strlen("EX_BRA_ID1")},
        {(uint8_t *)"EX_BRA_ID2", strlen("EX_BRA_ID2")},
        {(uint8_t *)"EX_BRA_ID3", strlen("EX_BRA_ID3")},

        {(uint8_t *)"AUDIO_SRC_PORT", strlen("AUDIO_SRC_PORT")},

        {(uint8_t *)"CSQMINUSONE", strlen("CSQMINUSONE")}
    };
    char cseq_minus_one[CSEQBUFLEN];
    snprintf(cseq_minus_one, CSEQBUFLEN, "%d", atoi(self->cseq) - 1);

    Data val[] = {
        {(uint8_t *)net->x_src_ip, strlen(net->x_src_ip)},
        {(uint8_t *)net->x_dst_ip, strlen(net->x_dst_ip)},
        {(uint8_t *)upp_dstip, upp_dstipaddrlen},

        {(uint8_t *)self->caller_id, strlen(self->caller_id)},
        {(uint8_t *)self->callee_id, strlen(self->callee_id)},
        {(uint8_t *)self->from_tag, strlen(self->from_tag)},
        {(uint8_t *)self->to_tag, strlen(self->to_tag)},
        {(uint8_t *)self->call_id, strlen(self->call_id)},
        {(uint8_t *)self->branch_id, strlen(self->branch_id)},
        {(uint8_t *)self->cseq, strlen(self->cseq)},
        {(uint8_t *)self->cont_len, strlen(self->cont_len)},
        {(uint8_t *)self->owner, strlen(self->owner)},
        {(uint8_t *)self->ex_branch_id[0], strlen(self->ex_branch_id[0])},
        {(uint8_t *)self->ex_branch_id[1], strlen(self->ex_branch_id[1])},
        {(uint8_t *)self->ex_branch_id[2], strlen(self->ex_branch_id[2])},
        {(uint8_t *)self->ex_branch_id[3], strlen(self->ex_branch_id[3])},

        {(uint8_t *)self->audio_sport, strlen(self->audio_sport)},
        {(uint8_t *)cseq_minus_one, strlen(cseq_minus_one)}
    };

    /* Note that the src and dst IP address are not exchanged when calls this
       function, so the src IP address is substituted by dst IP address, and dst
       IP address is substituted by src IP address */
    for (size_t i = 0; i < sizeof(sym) / sizeof(Data); i++) {
        nb = replace_bin(buf, sym[i].data, val[i].data,
                         nb, sym[i].len, val[i].len);
    }

    return nb;
}


bool ck_t_out(Sip *sip)
{
    struct timespec ts_n;
    double t_out = get_wait_t_out(sip);
    struct timespec timer = cnv_dbl_to_ts(t_out);

    get_timestamp(&ts_n);
    if(is_timeout(sip->ts, ts_n, timer))
        return true;

    return false;
}

bool chk_match_sip_meth(SipMeths meth, SipMeths *meth_arr)
{
    for (short i = 0; meth_arr[i] != UNKN_METH; i++) {
        if (meth == meth_arr[i])
            return true;
    }

    return false;
}

bool chk_match_sip_stat(SipStats stat, SipStats *stat_arr)
{
    for (short i = 0; stat_arr[i] != UNKN_STAT; i++) {
        if (stat == stat_arr[i])
            return true;
    }

    return false;
}

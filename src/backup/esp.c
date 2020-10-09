#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>

#include "aes.h"
#include "esp.h"
#include "transport.h"
#include "hmac.h"
#include "utils.h"

EspHeader esp_hdr_rec;

EspHeaderIV esp_hdr_rec_iv;

static uint8_t *parse_ik_from_msg(struct sadb_msg *msg, int msglen, uint8_t *k)
{
    struct sadb_ext *ext;
    ssize_t keylen;

    msglen -= sizeof(struct sadb_msg);
    ext = (struct sadb_ext *)(msg + 1);
    while (msglen > 0) {
        if (ext->sadb_ext_type == SADB_EXT_KEY_AUTH) {
            struct sadb_key *key = (struct sadb_key *)ext;
            unsigned char *p;

            p = (uint8_t *)(key + 1);

            keylen = key->sadb_key_bits / 8;
            memcpy(k, p, keylen);
        }

        msglen -= ext->sadb_ext_len << 3;
        ext = (void *)ext + (ext->sadb_ext_len << 3);
    }

    return k;
}

static void get_ik(int type, uint8_t *key)
{
    int s;
    char buf[4096];
    struct sadb_msg msg;
    struct sadb_msg *msgp;
    ssize_t msglen;
    ssize_t nb;

    s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);

    /* Build and send SADB_DUMP request */
    bzero(&msg, sizeof(msg));
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_DUMP;
    msg.sadb_msg_satype = type;
    msg.sadb_msg_len = sizeof(msg) / 8;
    msg.sadb_msg_pid = getpid();

    nb = write(s, &msg, sizeof(msg));
    if (nb == -1)
        perror("write()");

    int goteof = 0;
    while (goteof == 0) {

        msglen = read(s, &buf, sizeof(buf));
        msgp = (struct sadb_msg *)&buf;
        parse_ik_from_msg(msgp, msglen, key);
        if (msgp->sadb_msg_seq == 0)
            goteof = 1;
    }
    close(s);

    return ;
}





void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->fmt_esppkt = fmt_esp_pkt;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
    self->show_info = show_esp_info;

    //add: get esp key
    self->get_att_esp_key = get_att_key_from_channel;
}


/*
 * Initial aes cbc ctx for encryption and decryption
*/
struct AES_ctx* aes_cbc_init_ctx(uint8_t* key, uint8_t* iv){
    struct AES_ctx ctx;
    //printf("it is initialing ctx now.\n");

    char * key = "7fd8a06cd6eec0b604ccee9bb3240e02";
    char * iv  = "0615e8f2bf4aeb0f81f066ba4ac1c516";

    key = "7fd8a06cd6eec0b604ccee9bb3240e02";
    iv = "0615e8f2bf4aeb0f81f066ba4ac1c516";

    get_att_key_from_channel;

    uint8_t *uint_key;
    uint8_t *uint_iv;

    convertstring(key, &uint_key, strlen(key)/2);
    convertstring(iv,  &uint_iv,  strlen(iv)/2);

    AES_init_ctx_iv(&ctx, key, iv);
    //printf("yes, it successfully.\n");
    return &ctx;

    //AES_CBC_encrypt_buffer(&ctx, in, sizeof(in));

    //AES_ctx_set_iv(&ctx, uint_iv);
}

void convertstring (char * input, uint8_t ** r, int length){

    //1. check if input start with 0x
    if(input[0] == '0' && input[1] == 'x'){
        *input = &input[2];
    }


    if (strlen(input)%2 != 0){
        printf("Can't convert\n");
    }

    *r =  (uint8_t *)malloc( (strlen(input)/2) * sizeof(uint8_t));

    for (int i = 0; i < strlen(input)/2; i++){

        //1. get the subarry from input
        char *tmp = (char *)malloc(2 * sizeof(char));

        //printf("test convert start: %d\n", 2*i);

        memcpy(tmp, &input[2*i], 2*sizeof(char));

        //printf("hex: %s\n", tmp);

        //2. convert subarray hex string to int
        int number = (int)strtol(tmp, NULL, 16);

        //3. store as uint8_t
        (*r)[i] = (uint8_t)number;


        //4. free mem and *check
        free(tmp);

    }

}


bool get_att_key_from_channel(Esp *self) {

    int link[2];
    pid_t pid;

    //printf("get_att_key_from_channel\n");

    int nb;
    char line[4096];
    char authkey[35], aeskey[35]; //, dst[16];

    if (pipe(link)==-1)
        perror("pipe");

    if ((pid = fork()) == -1)
        perror("fork");

    if(pid == 0) {
        dup2 (link[1], STDOUT_FILENO);
        close(link[0]);
        close(link[1]);
        execl("/system/bin/ip", "ip", "xfrm", "state", (char *)0);
        perror("execl");
    } else {
        close(link[1]);
        nb = read(link[0], line, sizeof(line));
        if (nb == 0)
            perror("read");
    }


    sscanf(line, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %s %*s %*s %*s %s", authkey, aeskey);


    printf("Authkey: %s\n", authkey);
    printf("aeskey: %s\n", aeskey);

    printf("%s\n", line);
    printf("******************\n");
    return false;
}


uint8_t *set_esp_pad(Esp *self, size_t esp_plen)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t pad_val;

    self->plen = esp_plen;

    /*
     * ESP payload length + Appended padding + Padding length + Next header type
     * should be multiple of 4. 2 bytes are used to record Padding length and
     * Next header type.
     */
    self->tlr.pad_len = 4 - (2 + self->plen) % 4;
    /*new add
    puts("*************************************");
    printf("!!!ESP packet length in set_esp_pad:::: %u\n", self->plen);
    printf("!!!ESP pad length in set_esp_pad:::: %u\n", self->tlr.pad_len);
    */
    if (self->tlr.pad_len == 4)
        self->tlr.pad_len = 0;

    for (pad_val = 1; pad_val <= self->tlr.pad_len; pad_val++) {
        *(self->pad + pad_val - 1) = pad_val;
    }

    /* 2 bytes are used to record Padding length and Next header type */
    return self->pad;
}

bool get_esp_key(Esp *self)
{

    get_ik(SADB_SATYPE_ESP, self->esp_key);

    return true;

}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
{
    printf("esp.c: The fucnction: set_esp_auth\n");
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;
    ssize_t ret;

    memcpy(buff, &self->hdr, sizeof(EspHeader));
    nb += sizeof(EspHeader);
    memcpy(buff + nb, self->pl, self->plen);
    nb += self->plen;
    memcpy(buff + nb, self->pad, self->tlr.pad_len);
    nb += self->tlr.pad_len;
    memcpy(buff + nb, &self->tlr, sizeof(EspTrailer));
    nb += sizeof(EspTrailer);

    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}


ssize_t fmt_esp_pkt(Esp *self, uint8_t *buf, size_t buflen)
{
    printf("esp.c line 169: The application format the esp packet\n");
    if (!self || !buf ||
            buflen < sizeof(EspHeader) + sizeof(EspTrailer) + self->authlen) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return -1;
    }

    size_t nb = 0;

    memcpy(buf, &self->hdr, sizeof(EspHeader));
    nb += sizeof(EspHeader);
    memcpy(buf + nb, self->pl, self->plen);
    nb += self->plen;
    memcpy(buf + nb, self->pad, self->tlr.pad_len);
    nb += self->tlr.pad_len;
    memcpy(buf + nb, &self->tlr, sizeof(EspTrailer));
    nb += sizeof(EspTrailer);
    memcpy(buf + nb, self->auth, self->authlen);
    nb += self->authlen;

    return nb;
}


uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{

    if (!self ||
            esp_len < sizeof(EspHeader) + sizeof(EspTrailer) + HMAC96AUTHLEN) {
        printf("It is the error that returns Null.\n");
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }


    //add:
    //show_esp_info(self);
    //bool test = get_att_key_from_channel(self);



    memcpy(&self->hdr, esp_pkt, sizeof(EspHeader));


    if (self->hdr.spi == esp_hdr_rec.spi && ntohl(self->hdr.seq) > esp_hdr_rec.seq)
        esp_hdr_rec.seq = ntohl(self->hdr.seq);

    /* ESP packet trailer length is 2 bytes */
    memcpy(&self->tlr,
           esp_pkt + esp_len - 2 - self->authlen, sizeof(EspTrailer));

    printf("Check tlr.pad_len: %u.\n", self->tlr.pad_len);
    printf("Check tlr.nxt: %u.\n", self->tlr.nxt);

    printf("it should be pad length: %u\n", esp_pkt[esp_len-13]);
    printf("it should be next protocol: %u\n", esp_pkt[esp_len-14]);

    self->plen = esp_len - sizeof(EspHeader) -
                 self->tlr.pad_len - sizeof(EspTrailer) - HMAC96AUTHLEN;

    memcpy(self->pl, esp_pkt + sizeof(EspHeader), self->plen);

    memcpy(self->auth,
           esp_pkt + esp_len - self->authlen, self->authlen * sizeof(uint8_t));

    return esp_pkt + sizeof(EspHeader);
}


Esp *fmt_esp_rep(Esp *self, Proto p)
{
    /* Before calling fmt_esp_rep, self->plen should be set correctly first */

    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return NULL;
    }

    self->hdr.spi = esp_hdr_rec.spi;
    esp_hdr_rec.seq += 1;
    self->hdr.seq = htonl(esp_hdr_rec.seq);
    self->tlr.nxt = p;
    self->set_padpl(self, self->plen);

    return self;
}


void show_esp_info(Esp *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    printf("ESP SPI: %u\n", ntohl(self->hdr.spi));
    printf("ESP sequence: %u\n", ntohl(self->hdr.seq));
    printf("ESP padding length: %u\n", self->tlr.pad_len);
    printf("ESP nxt: %u\n", self->tlr.nxt);
    /*add-------------->
    printf("ESP key: %u\n", self->esp_key);

    //add-------------->
    */

    printf("ESP authentication data: ");
    output_hex_from_bin(self->auth, self->authlen * sizeof(uint8_t));
    puts("");
}

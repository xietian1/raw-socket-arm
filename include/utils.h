#ifndef _UTILS_H
#define _UTILS_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <argp.h>

#include "net.h"

#define BUFSIZE 65535
#define MAXFILENAMELEN 32

#ifndef _TYPEDEF_STRUCT_ARG
#define _TYPEDEF_STRUCT_ARG
typedef struct arg Arg;
#endif

#define HANDLE_ARG_ERR(ARG)                                                \
do {                                                                       \
    if (!(ARG)) {                                                          \
        fprintf(stderr, "[Error]: "#ARG" is required.\n"                   \
                        "Please check help list with --help for help.\n"); \
        exit(EXIT_FAILURE);                                                \
    }                                                                      \
} while (0)

#define FREE(PTR)  \
do {               \
    if (PTR)       \
        free(PTR); \
    (PTR) = NULL;  \
} while (0)

#ifndef _TYPEDEF_STRUCT_DATA
#define _TYPEDEF_STRUCT_DATA
typedef struct data Data;
#endif

typedef enum mode {
    UNKN_MODE = 0,
    SERVER,
    CLIENT,
} Mode;

typedef enum src_of_info {
    UNKN_INFO = 0,
    SINFO,
    RINFO
} InfoSrc;

typedef enum threat {
    /* None of the threat mode below */
    UNKN_THREAT = 0,

    /* Send binary files directly into interface without modifications */
    TX,

    /* Receive the data from certain interface */
    RX,

    ATTEMPT_TO_CALL,
    DRAIN_UE_BATTERY,
    DOS_UE,
    FORGE_NO,
    DATA_CH,
    CALLEE,

    /* Make calls to victims simultaneously to occupy victims' resources */
    SIMO_HARASS_CALL,
    /* Make calls to victims to occupy victims' resources */
    HARASS_CALL,
    TWIN_CALLER
} Threat;

struct arg {
    Proto p;
    Threat t;
    Mode m;
    InfoSrc i;

    char *opr;
    char *iface;
    char *iface_r;
    char *fname;
    char *blist;
    char *atkid;
    char *vicid;
    char *rmtid;
    char *servaddr;
    char *servport;
};

struct data {
    uint8_t *data;
    size_t len;
};

void init_argu(Arg *argu);

void parse_arg(int argc, char *argv[], Arg *argu);

void output_hex_from_bin(uint8_t *bin, size_t len);

void swap_pointer(void **a, void **b);

void swap_uint16(uint16_t *a, uint16_t *b);

void get_filename(char *filename);

ssize_t read_file(char *filename, uint8_t *buf);

ssize_t read_stdin(char *buf);

/**
 * parse_input()
 * Partition the @buf with @delim and store the result in @fld without modifying
 * the content in @buf. Return the number of partitions assigned to @fld. @fld
 * needs to have enough elements number to store partition (as least number of
 * partitions + 1 elements). Note that after used by caller, *@fld needs to be
 * freed.
 *
 * @buf: pointer to buffer to be parsed
 * @fld: array of pointers point to partitions separate by delim
 * @delim: pointer points to the delimter chars
 */
ssize_t parse_input(char *buf, char *fld[], char *delim);

ssize_t replace_bin(uint8_t *orig, uint8_t *rep, uint8_t *with,
                    size_t origlen, size_t replen, size_t withlen);

ssize_t cnv_low_to_up(char *s);

ssize_t get_victim_list(char **sipids, char *blist);

char *gen_rnd_str(char *buf, size_t len);

struct timespec cnv_dbl_to_ts(double dbl);

struct timespec *get_timestamp(struct timespec *tp);

bool is_timeout(struct timespec t1, struct timespec t2, struct timespec timer);

void restart_ims(char *opr);

bool record_log_with_time(char *log);

#endif

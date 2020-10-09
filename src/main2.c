#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h> //memset()
#include <unistd.h> //sleep()

//Socket stuff
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//IP header (struct iphdr) definition
//#include <linux/ip.h>
//TCP header (struct tcphdr) definition
//#include <linux/tcp.h>

//Perhaps these headers are more general
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

//Data to be sent (appended at the end of the TCP header)
#define DATA "datastring"
#define ETH_HDRLEN 14

//Debug function: dump 'index' bytes beginning at 'buffer'
void hexdump(unsigned char *buffer, unsigned long index) {
    unsigned long i;
    printf("hexdump on address %p:\n", buffer);
    for (i=0;i<index;i++)
    {
        printf("%02x ",buffer[i]);
    }
    printf("\n");
}

//Calculate the TCP header checksum of a string (as specified in rfc793)
//Function from http://www.binarytides.com/raw-sockets-c-code-on-linux/
unsigned short csum(unsigned short *ptr,int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    //Debug info
    //hexdump((unsigned char *) ptr, nbytes);
    //printf("csum nbytes: %d\n", nbytes);
    //printf("csum ptr address: %p\n", ptr);

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

typedef struct in6_addr in6_addr_t;

uint16_t
tcp_checksum (const void *buff, size_t len, size_t length, in6_addr_t *src_addr, in6_addr_t *dest_addr)
{
    const uint16_t *buf=buff;
    uint16_t *ip_src=(void *)src_addr, *ip_dst=(void *)dest_addr;
    uint32_t sum;
    int i  ;

    // Calculate the sum
    sum = 0;
    while (len > 1) {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }
    if ( len & 1 )
        // Add the padding if the packet length is odd
        sum += *((uint8_t *)buf);

    // Add the pseudo-header
    for (i = 0 ; i <= 7 ; ++i)
        sum += *(ip_src++);

    for (i = 0 ; i <= 7 ; ++i)
        sum += *(ip_dst++);

    sum += htons(IPPROTO_TCP);
    sum += htons(length);

    // Add the carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // Return the one's complement of sum
    return((uint16_t)(~sum));
}



//Pseudo header needed for calculating the TCP header checksum
struct pseudoTCPPacket {
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t TCP_len;
};

int main(int argc, char **argv) {
    int sock, bytes, one = 1;

    //struct iphdr *ipHdr;
    /*define ipv6 header and tcp header struct*/
    struct ip6_hdr *ip6Hdr;
    struct tcphdr *tcpHdr;


    //Setup
    //char *srcIP = "192.168.0.101";
    //char *dstIP = "192.168.0.105";

    char *srcIP = "2600:380:5ef9:dab6:7476:58e6:c7e0:fc5b";
    char *dstIP = "2001:1890:1f8:211e::1:2";

    int dstPort = 6000;
    int srcPort = 6401;

    //int dstPort = 30000;
    //int srcPort = 30001;

    //Initial guess for the SEQ field of the TCP header
    uint32_t initSeqGuess = 1138083240;

    //Data to be appended at the end of the tcp header
    char *data;

    //Ethernet header + IP header + TCP header + data
    char packet[512];

    //Pseudo TCP header to calculate the TCP header's checksum
    struct pseudoTCPPacket pTCPPacket;

    //Pseudo TCP Header + TCP Header + data
    char *pseudo_packet;

/*
  //Raw socket without any protocol-header inside
  if((sock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("Error while creating socket");
    exit(-1);
  }

  //Set option IP_HDRINCL (headers are included in packet)
  if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0) {
    perror("Error while setting socket options");
    exit(-1);
  }

*/

    //ipv6 raw socket without any protocol-header inside
    if((sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("Error while creating socket");
        exit(-1);
    }

    //Set ipv6 option IP_HDRINCL (headers are included in packet)
    if(setsockopt(sock, IPPROTO_IPV6, IP_HDRINCL, (char *)&one, sizeof(one)) < 0) {
        perror("Error while setting socket options");
        exit(-1);
    }

/*
	//bind to an interface
	const char *opt;
	opt = "ens33";
	//const len = strnlen(opt, IFNAMSIZ);
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, opt, sizeof(opt) ) < 0){
		perror("Error2 while setting socket options");
        exit(-1);
	}
*/

    int my_network_devices_scope_id = 9;
    if(setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char *)&my_network_devices_scope_id, sizeof(my_network_devices_scope_id)) < 0)
    {
        perror("Setting local interface error");
        printf ("%d\n", errno);
        exit(1);
    }


/*
  //Populate address struct

  addr_in.sin6_family = AF_INET6;
  addr_in.sin6_port = htons(dstPort);
  addr_in.sin6_addr.s6_addr = inet_addr(dstIP);

  //Allocate mem for ip and tcp headers and zero the allocation
  memset(packet, 0, sizeof(packet));
  ipHdr = (struct iphdr *) packet;
  tcpHdr = (struct tcphdr *) (packet + sizeof(struct iphdr));
  data = (char *) (packet + sizeof(struct iphdr) + sizeof(struct tcphdr));
  strcpy(data, DATA);
*/


    memset(packet, 0, sizeof(packet));
    ip6Hdr = (struct ip6_hdr *) packet;
    tcpHdr = (struct tcphdr *) (packet + sizeof(struct ip6_hdr));
    data = (char *) (packet + sizeof(struct ip6_hdr) + sizeof(struct tcphdr));
    strcpy(data, DATA);

    u_char *packetdata = DATA;
    struct ip6_hdr *o_iphdr ;
    o_iphdr = (struct ip6_hdr *)(packetdata + ETH_HDRLEN);

    //todo1: flow label may be different
    //todo2: hop limit may be different
    //todo3: Now ipv6 doesn't have checksum

    /* IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits) */
    ip6Hdr->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

    /*set payload length*/
    ip6Hdr->ip6_plen = o_iphdr->ip6_plen;


    /* Next header (8 bits): 6 for TCP */
    ip6Hdr->ip6_nxt = 6;

    /* Hop limit (8 bits): default to maximum value */
    ip6Hdr->ip6_hops = 255;

    /* Convert string to ip6 address */
    struct sockaddr_in6 srcaddr, dstaddr;
    //char str[INET_ADDRSTRLEN];
    inet_pton(AF_INET6, srcIP, &(srcaddr.sin6_addr));
    inet_pton(AF_INET6, dstIP, &(dstaddr.sin6_addr));

    /* set src/dst address */
    bcopy(&srcaddr.sin6_addr,&(ip6Hdr->ip6_src), 16);
    bcopy(&dstaddr.sin6_addr,&(ip6Hdr->ip6_dst), 16);


    //Address struct to sendto()
    struct sockaddr_in6 addr_in;

    addr_in.sin6_family = AF_INET6;
    addr_in.sin6_port = htons(dstPort);
    //addr_in.sin6_addr.s6_addr = inet_addr(dstIP);



/*
  //Populate ipHdr
  ipHdr->ihl = 5; //5 x 32-bit words in the header
  ipHdr->version = 4; // ipv4
  ipHdr->tos = 0;// //tos = [0:5] DSCP + [5:7] Not used, low delay
  ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data); //total lenght of packet. len(data) = 0
  ipHdr->id = htons(54321); // 0x00; //16 bit id
  ipHdr->frag_off = 0x00; //16 bit field = [0:2] flags + [3:15] offset = 0x0
  ipHdr->ttl = 0xFF; //16 bit time to live (or maximal number of hops)
  ipHdr->protocol = IPPROTO_TCP; //TCP protocol
  ipHdr->check = 0; //16 bit checksum of IP header. Can't calculate at this point
  ipHdr->saddr = inet_addr(srcIP); //32 bit format of source address
  ipHdr->daddr = inet_addr(dstIP); //32 bit format of source address
*/
    //Now we can calculate the check sum for the IP header check field
    //ipHdr->check = csum((unsigned short *) packet, ipHdr->tot_len);
    //printf("IP header checksum: %d\n\n\n", ipHdr->check);


    //Populate tcpHdr
    tcpHdr->source = htons(srcPort); //16 bit in nbp format of source port
    tcpHdr->dest = htons(dstPort); //16 bit in nbp format of destination port
    tcpHdr->seq = 0x0; //32 bit sequence number, initially set to zero
    tcpHdr->ack_seq = 0x0; //32 bit ack sequence number, depends whether ACK is set or not
    tcpHdr->doff = 5; //4 bits: 5 x 32-bit words on tcp header
    tcpHdr->res1 = 0; //4 bits: Not used
    //tcpHdr->cwr = 0; //Congestion control mechanism
    //tcpHdr->ece = 0; //Congestion control mechanism
    tcpHdr->urg = 0; //Urgent flag
    tcpHdr->ack = 1; //Acknownledge
    tcpHdr->psh = 0; //Push data immediately
    tcpHdr->rst = 0; //RST flag
    tcpHdr->syn = 0; //SYN flag
    tcpHdr->fin = 0; //Terminates the connection
    tcpHdr->window = htons(155);//0xFFFF; //16 bit max number of databytes
    tcpHdr->check = 0; //16 bit check sum. Can't calculate at this point
    tcpHdr->urg_ptr = 0; //16 bit indicate the urgent data. Only if URG flag is set
/*
  tcpHdr->th_sport = htons(srcPort);
  tcpHdr->th_dport = htons(dstPort);
  tcpHdr->th_seq = 0x0;
  tcpHdr->th_ack = 0x0;
  tcpHdr->th_win = htons(155);
  tcpHdr->th_sum = 0;
  tcpHdr->urg_ptr = 0;
  */
/*
  //Now we can calculate the checksum for the TCP header
  pTCPPacket.srcAddr = inet_addr(srcIP); //32 bit format of source address
  pTCPPacket.dstAddr = inet_addr(dstIP); //32 bit format of source address
  pTCPPacket.zero = 0; //8 bit always zero
  pTCPPacket.protocol = IPPROTO_TCP; //8 bit TCP protocol
  pTCPPacket.TCP_len = htons(sizeof(struct tcphdr) + strlen(data)); // 16 bit length of TCP header
*/


    pTCPPacket.srcAddr = (uint32_t)atoi(srcaddr.sin6_addr.s6_addr);
    pTCPPacket.dstAddr = (uint32_t)atoi(dstaddr.sin6_addr.s6_addr);
    pTCPPacket.zero = 0; //8 bit always zero
    pTCPPacket.protocol = IPPROTO_TCP;
    pTCPPacket.TCP_len = htons(sizeof(struct tcphdr) + strlen(data));

    //Populate the pseudo packet
    pseudo_packet = (char *) malloc((int) (sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data)));
    memset(pseudo_packet, 0, sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data));

    //Copy pseudo header
    memcpy(pseudo_packet, (char *) &pTCPPacket, sizeof(struct pseudoTCPPacket));






    //Send lots of packets
    //while(1) {
    //Try to gyess TCP seq
    tcpHdr->seq = htonl(initSeqGuess++);

    //Calculate check sum: zero current check, copy TCP header + data to pseudo TCP packet, update check
    tcpHdr->th_sum = 0;

    //Copy tcp header + data to fake TCP header for checksum
    memcpy(pseudo_packet + sizeof(struct pseudoTCPPacket), tcpHdr, sizeof(struct tcphdr) + strlen(data));

    //Set the TCP header's check field
    tcpHdr->th_sum = (csum((unsigned short *) pseudo_packet, (int) (sizeof(struct pseudoTCPPacket) +
                                                                    sizeof(struct tcphdr) +  strlen(data))));

    printf("TCP Checksum: %d\n", (int) tcpHdr->check);

    //Finally, send packet
/*
    if((bytes = sendto(sock, packet, ipHdr->tot_len, 0, (struct sockaddr *) &addr_in, sizeof(addr_in))) < 0) {
      perror("Error on sendto()");
    }
    else {
      printf("Success! Sent %d bytes.\n", bytes);
    }
*/

    struct sockaddr_in6 multicastIP;
    multicastIP.sin6_family   = AF_INET6;
    multicastIP.sin6_scope_id = my_network_devices_scope_id;
    //multicastIP.sin6_port     = htons(9999);  // destination port chosen at random
    inet_pton(AF_INET6, "ff12::bead:cede:deed:feed", &multicastIP.sin6_addr.s6_addr);

    int tcp_hdr_len = tcpHdr->th_off * 4;
    ip6Hdr->ip6_plen = htons(20);

    int totallen = sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + strlen(data);
    if((bytes = sendto(sock, packet, totallen, 0, (struct sockaddr *) &multicastIP, sizeof(multicastIP))) < 0) {
        perror("Error on sendto()");
    }
    else {
        printf("Success! Sent %d bytes.\n", bytes);
    }


    printf("SEQ guess: %u\n\n", initSeqGuess);

    //sleep(1);

    //Comment out this break to unleash the beast
    //break;
    //}

    return 0;
}
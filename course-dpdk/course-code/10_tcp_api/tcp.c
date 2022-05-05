

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>


#include <stdio.h>
#include <arpa/inet.h>

#include "arp.h"

#define ENABLE_SEND         1

#define ENABLE_ARP          1
#define ENABLE_ICMP         1
#define ENABLE_ARP_REPLY    1

#define ENABLE_DEBUG        0

#define ENABLE_TIMER        1

#define ENABLE_RINGBUFFER   1
#define ENABLE_MULTHREAD    1

#define ENABLE_UDP_APP      1

#define ENABLE_TCP_APP      1
//#define TCP_OPTION_LEN      10
//#define TCP_MAX_SEQ         4294967295
//#define TCP_INITIAL_WINDOW  14600

#define NUM_MBUFS (4096-1)

#define BURST_SIZE  32
#define RING_SIZE   1024

#define TIMER_RESOLUTION_CYCLES 20000000000ULL // 10ms * 1000 = 10s * 6 


#if ENABLE_SEND

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

static uint32_t gLocalIp = MAKE_IPV4_ADDR(10, 164, 16, 40);

//static uint32_t gSrcIp; //
//static uint32_t gDstIp;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
//static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

//static uint16_t gSrcPort;
//sstatic uint16_t gDstPort;

#endif

#if ENABLE_ARP_REPLY

static uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#endif

#if ENABLE_RINGBUFFER

struct inout_ring {

    struct rte_ring *in;
    struct rte_ring *out;
};

static struct inout_ring *rInst = NULL;

static struct inout_ring *ringInstance(void) {

    if (rInst == NULL) {

        rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
        memset(rInst, 0, sizeof(struct inout_ring));
    }

    return rInst;
}

#endif

#if ENABLE_UDP_APP

static int udp_process(struct rte_mbuf *udpmbuf);
static int udp_out(struct rte_mempool *mbuf_pool);


#endif

#if ENABLE_TCP_APP
static int ng_tcp_process(struct rte_mbuf *tcpmbuf);
static int ng_tcp_out(struct rte_mempool *mbuf_pool);

#endif

int gDpdkPortId = 0;



static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

static void ng_init_port(struct rte_mempool *mbuf_pool) {

    uint16_t nb_sys_ports= rte_eth_dev_count_avail(); //
    if (nb_sys_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Supported eth found\n");
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortId, &dev_info); //
    
    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;
    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);


    if (rte_eth_rx_queue_setup(gDpdkPortId, 0 , 1024, 
        rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf_pool) < 0) {

        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");

    }
    
#if ENABLE_SEND
    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
    if (rte_eth_tx_queue_setup(gDpdkPortId, 0 , 1024, 
        rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {
        
        rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
        
    }
#endif

    if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }
}

/*

static int ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len) {

    // encode 
    // 1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // 2 iphdr 
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64; // ttl = 64
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = gSrcIp;
    ip->dst_addr = gDstIp;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // 3 udphdr 
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = gSrcPort;
    udp->dst_port = gDstPort;
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);
    rte_memcpy((uint8_t*)(udp+1), data, udplen);
    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

    struct in_addr addr;
    addr.s_addr = gSrcIp;
    printf(" --> src: %s:%d, ", inet_ntoa(addr), ntohs(gSrcPort));

    addr.s_addr = gDstIp;
    printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(gDstPort));
    return 0;
}

static struct rte_mbuf * ng_send_udp(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length) {

    // mempool --> mbuf
    const unsigned total_len = length + 42;

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;
    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);
    ng_encode_udp_pkt(pktdata, data, total_len);
    return mbuf;
}
*/

#if ENABLE_ARP

static int ng_encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {

    // 1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    if (!strncmp((const char *)dst_mac, (const char *)gDefaultArpMac, RTE_ETHER_ADDR_LEN)) {
        uint8_t mac[RTE_ETHER_ADDR_LEN] = {0x0};
        rte_memcpy(eth->d_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
    } else {
        rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    }
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    // 2 arp 
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    arp->arp_hardware = htons(1);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(uint32_t);
    arp->arp_opcode = htons(opcode);
    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy( arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    arp->arp_data.arp_sip = sip;
    arp->arp_data.arp_tip = dip;
    return 0;
}

static struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ng_encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);

    return mbuf;
}

#endif


#if ENABLE_ICMP

static uint16_t ng_checksum(uint16_t *addr, int count) {

    register long sum = 0;

    while (count > 1) {
        sum += *(unsigned short*)addr++;
        count -= 2;
    }

    if (count > 0) {
        sum += *(unsigned char *)addr;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

static int ng_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac,
        uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {

    // 1 ether
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // 2 ip
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64; // ttl = 64
    ip->next_proto_id = IPPROTO_ICMP;
    ip->src_addr = sip;
    ip->dst_addr = dip;
    
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // 3 icmp 
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    icmp->icmp_code = 0;
    icmp->icmp_ident = id;
    icmp->icmp_seq_nb = seqnb;

    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = ng_checksum((uint16_t*)icmp, sizeof(struct rte_icmp_hdr));
    return 0;
}

static struct rte_mbuf *ng_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
        uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {

    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ng_encode_icmp_pkt(pkt_data, dst_mac, sip, dip, id, seqnb);

    return mbuf;
}

#endif
#if 0
static void 
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s", name, buf);
}
#endif

#if ENABLE_TIMER

static void
arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim,
       void *arg) {

    struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
    struct inout_ring *ring = ringInstance();

#if 0
    struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, ahdr->arp_data.arp_sha.addr_bytes, 
        ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

    rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
    rte_pktmbuf_free(arpbuf);

#endif
    
    int i = 0;
    for (i = 1;i <= 254;i ++) {

        uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));

        //struct in_addr addr;
        //addr.s_addr = dstip;
        //printf("arp ---> src: %s \n", inet_ntoa(addr));

        struct rte_mbuf *arpbuf = NULL;
        uint8_t *dstmac = ng_get_dst_macaddr(dstip);
        if (dstmac == NULL) {
            arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, gLocalIp, dstip);
        } else {
            arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, dstmac, gLocalIp, dstip);
        }

        //rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
        //rte_pktmbuf_free(arpbuf);
        rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);
    }
}


#endif

#if ENABLE_MULTHREAD

static int pkt_process(void *arg) {

    struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
    struct inout_ring *ring = ringInstance();

    while (1) {
        struct rte_mbuf *mbufs[BURST_SIZE];
        unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->in, (void**)mbufs, BURST_SIZE, NULL);
        
        unsigned i = 0;
        for (i = 0;i < num_recvd;i ++) {
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);

#if ENABLE_ARP
            if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {

                struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbufs[i], 
                    struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
                
                //struct in_addr addr;
                //addr.s_addr = ahdr->arp_data.arp_tip;
                //printf("arp ---> src: %s ", inet_ntoa(addr));

                //addr.s_addr = gLocalIp;
                //printf(" local: %s \n", inet_ntoa(addr));

                if (ahdr->arp_data.arp_tip == gLocalIp) {
                    if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
                        printf("arp --> request\n");
                        struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REPLY, ahdr->arp_data.arp_sha.addr_bytes, 
                            ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);
                        //rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
                        //rte_pktmbuf_free(arpbuf);
                        rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);
                    } else if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
                        printf("arp --> reply\n");
                        struct arp_table *table = arp_table_instance();
                        uint8_t *hwaddr = ng_get_dst_macaddr(ahdr->arp_data.arp_sip);
                        if (hwaddr == NULL) {
                            struct arp_entry *entry = rte_malloc("arp_entry",sizeof(struct arp_entry), 0);
                            if (entry) {
                                memset(entry, 0, sizeof(struct arp_entry));
                                entry->ip = ahdr->arp_data.arp_sip;
                                rte_memcpy(entry->hwaddr, ahdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
                                entry->type = 0;
                                
                                LL_ADD(entry, table->entries);
                                table->count ++;
                            }
                        }
#if ENABLE_DEBUG
                        struct arp_entry *iter;
                        for (iter = table->entries; iter != NULL; iter = iter->next) {
                    
                            struct in_addr addr;
                            addr.s_addr = iter->ip;
                            print_ethaddr("arp table --> mac: ", (struct rte_ether_addr *)iter->hwaddr);
                            printf(" ip: %s \n", inet_ntoa(addr));
                        }
#endif
                        rte_pktmbuf_free(mbufs[i]);
                    }
                    continue;
                } 
            }
#endif

            if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                continue;
            }

            struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
                sizeof(struct rte_ether_hdr));
            
            if (iphdr->next_proto_id == IPPROTO_UDP) {
                uint8_t *hwaddr = ng_get_dst_macaddr(iphdr->src_addr);
                if (hwaddr == NULL) {
                    struct arp_table *table = arp_table_instance();
                    struct arp_entry *entry = rte_malloc("arp_entry",sizeof(struct arp_entry), 0);
                    if (entry) {
                        memset(entry, 0, sizeof(struct arp_entry));
                        entry->ip = iphdr->src_addr;
                        rte_memcpy(entry->hwaddr, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
                        entry->type = 0;
                        LL_ADD(entry, table->entries);
                        table->count ++;
                    }
                }
                udp_process(mbufs[i]);
            }
#if ENABLE_TCP_APP
            if(iphdr->next_proto_id == IPPROTO_TCP) {
                uint8_t *hwaddr = ng_get_dst_macaddr(iphdr->src_addr);
                if (hwaddr == NULL) {
                    struct arp_table *table = arp_table_instance();
                    struct arp_entry *entry = rte_malloc("arp_entry",sizeof(struct arp_entry), 0);
                    if (entry) {
                        memset(entry, 0, sizeof(struct arp_entry));
                        entry->ip = iphdr->src_addr;
                        rte_memcpy(entry->hwaddr, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
                        entry->type = 0;
                        LL_ADD(entry, table->entries);
                        table->count ++;
                    }
                }
                ng_tcp_process(mbufs[i]);
            }
#endif

#if ENABLE_ICMP

            if (iphdr->next_proto_id == IPPROTO_ICMP) {

                struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);

                
                struct in_addr addr;
                addr.s_addr = iphdr->src_addr;
                printf("icmp ---> src: %s ", inet_ntoa(addr));

                
                if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {

                    addr.s_addr = iphdr->dst_addr;
                    printf(" local: %s , type : %d\n", inet_ntoa(addr), icmphdr->icmp_type);
                

                    struct rte_mbuf *txbuf = ng_send_icmp(mbuf_pool, ehdr->s_addr.addr_bytes,
                        iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);

                    //rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
                    //rte_pktmbuf_free(txbuf);
                    rte_ring_mp_enqueue_burst(ring->out, (void**)&txbuf, 1, NULL);

                    rte_pktmbuf_free(mbufs[i]);
                }

            }

#endif
            
        }

#if ENABLE_UDP_APP

        udp_out(mbuf_pool);

#endif

#if ENABLE_TCP_APP
        ng_tcp_out(mbuf_pool);
#endif
    }

    return 0;
}


#endif


#if ENABLE_UDP_APP



struct localhost { // 

    int fd;

    //unsigned int status; //
    uint32_t localip; // ip --> mac
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    uint16_t localport;

    uint8_t protocol;
/*******4+4+6+2+1=17-byte******************************/

    struct rte_ring *sndbuf;
    struct rte_ring *rcvbuf;

    struct localhost *prev; //
    struct localhost *next;

    pthread_cond_t cond;
    pthread_mutex_t mutex;

};

static struct localhost *lhost = NULL;

#define DEFAULT_FD_NUM  3
#define MAX_FD_COUNT    1024
static unsigned char fd_table[MAX_FD_COUNT] = {0};

static int get_fd_frombitmap(void) {

    int fd = DEFAULT_FD_NUM;
    for(; fd < MAX_FD_COUNT; fd++) {
        if((fd_table[fd/8] & (0x1 << (fd % 8))) == 0) {
            fd_table[fd/8] |= (0x1 << (fd % 8));
            return fd;
        }
    }
    return -1;
}

static int set_fd_frombitmap(int fd) {
    if (fd >= MAX_FD_COUNT) {
        return -1;
    }
    fd_table[fd/8] &= ~(0x1 << (fd % 8));
    return 0;
}

static struct ng_tcp_stream * get_accept_tcb(uint16_t dport) {
    struct ng_tcp_stream *apt;
    struct ng_tcp_table *table = tcpInstance();

    for(apt = table->tcp_set; apt != NULL; apt = apt->next) {
        if(apt->dport == dport && apt->fd == -1) {
            return apt;
        }
    }
    return NULL;
}

static void * get_hostinfo_fromfd(int sockfd) {

    struct localhost *host;

    for (host = lhost; host != NULL;host = host->next) {

        if (sockfd == host->fd) {
            return host;
        }

    }
#if ENABLE_TCP_APP
    struct ng_tcp_stream *stream;
    struct ng_tcp_table *table = tcpInstance();
    for(stream = table->tcp_set; stream != NULL; stream = stream->next) {
        if(sockfd == stream->fd) {
            return stream;
        }
    }

#endif
    
    return NULL;
    
}

static struct localhost * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto) {

    struct localhost *host;

    for (host = lhost; host != NULL;host = host->next) {

        if (dip == host->localip && port == host->localport && proto == host->protocol) {
            return host;
        }

    }

    
    return NULL;
    
}

// arp
struct offload { //

    uint32_t sip;
    uint32_t dip;

    uint16_t sport;
    uint16_t dport; //

    int protocol;

    unsigned char *data;
    uint16_t length;
    
}; 


static int udp_process(struct rte_mbuf *udpmbuf) {

    struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, 
                sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

    
    struct in_addr addr;
    addr.s_addr = iphdr->src_addr;
    printf("udp_process ---> src: %s:%d \n", inet_ntoa(addr), ntohs(udphdr->src_port));

    struct localhost *host = get_hostinfo_fromip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
    if (host == NULL) {
        rte_pktmbuf_free(udpmbuf);
        return -3;
    } 

    struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL) {
        rte_pktmbuf_free(udpmbuf);
        return -1;
    }

    ol->dip = iphdr->dst_addr;
    ol->sip = iphdr->src_addr;
    ol->sport = udphdr->src_port;
    ol->dport = udphdr->dst_port;

    
    ol->protocol = IPPROTO_UDP;
    ol->length = ntohs(udphdr->dgram_len);

    ol->data = rte_malloc("unsigned char*", ol->length - sizeof(struct rte_udp_hdr), 0);
    if (ol->data == NULL) {

        rte_pktmbuf_free(udpmbuf);
        rte_free(ol);

        return -2;

    }
    rte_memcpy(ol->data, (unsigned char *)(udphdr+1), ol->length - sizeof(struct rte_udp_hdr));

    rte_ring_mp_enqueue(host->rcvbuf, ol); // recv buffer

    pthread_mutex_lock(&host->mutex);
    pthread_cond_signal(&host->cond);
    pthread_mutex_unlock(&host->mutex);

    rte_pktmbuf_free(udpmbuf);

    return 0;
}


static int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
    unsigned char *data, uint16_t total_len) {

    // encode 

    // 1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
    

    // 2 iphdr 
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64; // ttl = 64
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = sip;
    ip->dst_addr = dip;
    
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // 3 udphdr 

    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = sport;
    udp->dst_port = dport;
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);

    rte_memcpy((uint8_t*)(udp+1), data, udplen);

    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

    return 0;
}


static struct rte_mbuf * ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
    uint8_t *data, uint16_t length) {

    // mempool --> mbuf

    const unsigned total_len = length + 42;

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

    ng_encode_udp_apppkt(pktdata, sip, dip, sport, dport, srcmac, dstmac,
        data, total_len);

    return mbuf;

}


// offload --> mbuf
static int udp_out(struct rte_mempool *mbuf_pool) {

    struct localhost *host;
    for (host = lhost; host != NULL; host = host->next) {

        struct offload *ol;
        int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
        if (nb_snd < 0) continue;

        //struct in_addr addr;
        //addr.s_addr = ol->dip;
        //printf("udp_out ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));
            
        uint8_t *dstmac = ng_get_dst_macaddr(ol->dip);
        if (dstmac == NULL) {
        
            struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, 
                ol->sip, ol->dip);

            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);

            rte_ring_mp_enqueue(host->sndbuf, ol);
            
        } else {

            struct rte_mbuf *udpbuf = ng_udp_pkt(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport,
                host->localmac, dstmac, ol->data, ol->length);

            
            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&udpbuf, 1, NULL);

        }
        

    }

    return 0;
}

// hook
// nsocket both in udpserver and tcpserver
static int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol) {

    int fd = get_fd_frombitmap(); //

    if (type == SOCK_DGRAM) {
        struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
        if (host == NULL) {
            return -1;
        }
        memset(host, 0, sizeof(struct localhost));

        host->fd = fd;
        host->protocol = IPPROTO_UDP;

        host->rcvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (host->rcvbuf == NULL) {

            rte_free(host);
            return -1;
        }

        
        host->sndbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (host->sndbuf == NULL) {

            rte_ring_free(host->rcvbuf);

            rte_free(host);
            return -1;
        }

        pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
        rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

        pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
        rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

        LL_ADD(host, lhost);
    }else if(type == SOCK_STREAM) { // 创建stream返回listenfd,但是不创建sendbuf, rcvbuf这两个收发ring
        struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
        if(stream == NULL) {
            return -1;
        }
        memset(stream, 0, sizeof(struct ng_tcp_stream));

        stream->fd = fd;
        stream->protocol = IPPROTO_TCP;
        stream->next = stream->prev = NULL;
        // 加入的accept的阻塞机制
        pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
        rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

        pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
        rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

#if 0
        stream->rcvbuf = rte_ring_create("tcp recv buff", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if(stream->rcvbuf == NULL) {
            rte_free(stream);
            return -1;
        }

        stream->sndbuf = rte_ring_create("tcp send buf", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if(stream->sndbuf == NULL) {
            rte_ring_free(stream->rcvbuf);
            rte_free(stream);
            return -1;
        }
#endif
        //阻塞代码
        // 加入到table里面是不合适的，因为此时通过五元组是找不到这个stream的，
        struct ng_tcp_table *table = tcpInstance();
        LL_ADD(stream, table->tcp_set);
        table->counter++;
    }
    return fd;
}
// nbind both in udpserver and tcpserver
static int nbind(int sockfd, const struct sockaddr *addr,
                __attribute__((unused))  socklen_t addrlen) {

    void *hostinfo =  get_hostinfo_fromfd(sockfd);
    if (hostinfo == NULL) return -1;

    struct localhost *host = (struct localhost *)hostinfo;

    if (host->protocol == IPPROTO_UDP) {
        const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
        host->localport = laddr->sin_port;
        rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
        rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);
    } else if (host->protocol == IPPROTO_TCP) {
        struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;

        const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
        stream->dport = laddr->sin_port;
        rte_memcpy(&stream->dip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
        rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

        stream->status = NG_TCP_STATUS_CLOSED;//这里抄CSAPP里面
    }

    return 0;

}

// nlisten just in tcpserver,
static int nlisten(int sockfd, __attribute__((unused)) int backlog) {

    //step1: 通过入参的sockfd找到stream
    void *hostinfo = get_hostinfo_fromfd(sockfd);
    if (hostinfo == NULL) {
        return -1;
    }
    // step2: 把stream从主动变被动
    struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
    if(stream->protocol == IPPROTO_TCP) {
        stream->status = NG_TCP_STATUS_LISTEN;
    }
    // step3: 半连接+全连接 最大为backlog,
    // 这里先将backlog设置成不可用的参数
    return 0;
}

// naccept just in tcpserver里面运行，accept的阻塞，释放是在哪里呢，在ng_tcp_handle_syn_rcvd里面
static int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen) {
    //accept主要做两个事情，找到全连接节点stream，再给这个stream分配一个fd

    void *hostinfo = get_hostinfo_fromfd(sockfd);
    if(hostinfo == NULL)
        return -1;

    struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {
        struct ng_tcp_stream *apt = NULL;

        pthread_mutex_lock(&stream->mutex);
        while((apt = get_accept_tcb(stream->dport)) == NULL) {
            pthread_cond_wait(&stream->cond, &stream->mutex);
        }
        pthread_mutex_unlock(&stream->mutex);

        apt->fd = get_fd_frombitmap();
        struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
        saddr->sin_port = apt->sport;
        rte_memcpy(&saddr->sin_addr.s_addr, &apt->sip, sizeof(uint32_t));

        return apt->fd;
    }

    return -1;
}

static ssize_t nsend(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags) {
    ssize_t length = 0;

    void *hostinfo = get_hostinfo_fromfd(sockfd);
    if(hostinfo == NULL)
        return -1;

    struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {
        // step1:组织一个tcp的fragment
        struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
        if (fragment == NULL) {
            return -2;
        }
        
        memset(fragment, 0, sizeof(struct ng_tcp_fragment));
        fragment->dport = stream->sport;
        fragment->sport = stream->dport;

        fragment->acknum = stream->recv_nxt;
        fragment->seqnum = stream->send_nxt;

        fragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
        fragment->windows = TCP_INITIAL_WINDOW;
        fragment->hdrlen_off = 0x50;

        //if(len > mtu)

        //uint8_t *payload = (uint8_t *)tcphdr + hdrlen * 4;
		fragment->data = rte_malloc("unsigned char *", len+1, 0);
        if(fragment->data == NULL) {
			rte_free(fragment);
            return -1;
        }
        memset(fragment->data, 0, len+1);
        
        rte_memcpy(fragment->data, buf, len);
        fragment->length = len;
        length = fragment->length;
        // step2：将fragment放到stream的sndbuf里面
        // int nb_snd < 0,这里可以做一个判断，如果sndbuf满了就阻塞。
        rte_ring_mp_enqueue(stream->sndbuf, fragment);
        
    }
    return length;
}


//recv 运行在tcp server这个线程里面的
// real world中，recv返回三类值，>0是正常的，==0断开，<0即==-1代表stream->recvbuf是空的，也就是recv非阻塞模式
// recv阻塞模式是没有返回-1这种说法的。
static ssize_t nrecv(int sockfd, void *buf, int len, __attribute__((unused))int flags) {

    ssize_t length = 0;

    void *hostinfo = get_hostinfo_fromfd(sockfd);
    if(hostinfo == NULL)
        return -1;
    printf("nrecv\n");
    struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {

        struct ng_tcp_fragment *fragment = NULL;
        int nb_rcv = 0;

        // step1: recv从stream->rcvbuf里面取数据，没有数据就条件等待。等tcp_process往里加数据
        pthread_mutex_lock(&stream->mutex);
        while((nb_rcv = rte_ring_mc_dequeue(stream->rcvbuf, (void **)&fragment)) < 0) {
            // 如果nb_rcv < 0代表没有收到包，此时我们进行条件等待，就是阻塞
            printf("nb_rcv < 0\n");
            pthread_cond_wait(&stream->cond, &stream->mutex);
        }
        pthread_mutex_unlock(&stream->mutex);

        if(fragment->length > len) {
            rte_memcpy(buf, fragment->data, len);
            int i = 0;
            for(i = 0; i < fragment->length-len; i++) {
                fragment->data[i] = fragment->data[len+i];
            }
            fragment->length = fragment->length - len;
			length = fragment->length; //写错了？
            rte_ring_mp_enqueue(stream->rcvbuf, fragment);
        } else if(fragment->length == 0) {
            rte_free(fragment);
            return 0;
        } else {
            rte_memcpy(buf, fragment->data, fragment->length);
            length = fragment->length;
            rte_free(fragment->data);
            fragment->data = NULL;
            // 这里回忆一下，fragment是在tcp_process往stream->rcvbuf里面加的时候，生产的
            rte_free(fragment);
        }
    }
    return length;
}

static ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                        struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen) {

    struct localhost *host =  get_hostinfo_fromfd(sockfd);
    if (host == NULL) return -1;

    struct offload *ol = NULL;
    unsigned char *ptr = NULL;
    
    struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;
    
    int nb = -1;
    pthread_mutex_lock(&host->mutex);
    while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void **)&ol)) < 0) {
        pthread_cond_wait(&host->cond, &host->mutex);
    }
    pthread_mutex_unlock(&host->mutex);
    

    saddr->sin_port = ol->sport;
    rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));

    if (len < ol->length) {

        rte_memcpy(buf, ol->data, len);

        ptr = rte_malloc("unsigned char *", ol->length-len, 0);
        rte_memcpy(ptr, ol->data+len, ol->length-len);

        ol->length -= len;
        rte_free(ol->data);
        ol->data = ptr;
        
        rte_ring_mp_enqueue(host->rcvbuf, ol);

        return len;
        
    } else {

        rte_memcpy(buf, ol->data, ol->length);
        
        rte_free(ol->data);
        rte_free(ol);
        
        return ol->length;
    }

    

}

static ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                      const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen) {

    
    struct localhost *host =  get_hostinfo_fromfd(sockfd);
    if (host == NULL) return -1;

    const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;

    struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL) return -1;

    ol->dip = daddr->sin_addr.s_addr;
    ol->dport = daddr->sin_port;
    ol->sip = host->localip;
    ol->sport = host->localport;
    ol->length = len;

    struct in_addr addr;
    addr.s_addr = ol->dip;
    printf("nsendto ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));
    

    ol->data = rte_malloc("unsigned char *", len, 0);
    if (ol->data == NULL) {
        rte_free(ol);
        return -1;
    }

    rte_memcpy(ol->data, buf, len);

    rte_ring_mp_enqueue(host->sndbuf, ol);

    return len;
}
// nclose之所以加n是为了避免与系统重名，当然DPDK还可以用hook方法，比如pthread_mutex_unlock这种就是hook做的
static int nclose(int fd) {

    void *hostinfo = get_hostinfo_fromfd(fd);
    if(hostinfo == NULL)
        return -1;

    struct localhost *host =  (struct localhost *)hostinfo;
    if(host->protocol == IPPROTO_UDP) {
        LL_REMOVE(host, lhost);
        if (host->rcvbuf) {
            rte_ring_free(host->rcvbuf);
        }
        if (host->sndbuf) {
            rte_ring_free(host->sndbuf);
        }
        rte_free(host);
        set_fd_frombitmap(fd);
    } else if(host->protocol == IPPROTO_TCP) {
        struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;

        if (stream->status != NG_TCP_STATUS_LISTEN) {
            // 准备一个tcp fragment
            struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
            if(fragment == NULL) {
                return -1;
            }
            fragment->data = NULL;
            fragment->length = 0;
            fragment->sport = stream->dport;
            fragment->dport = stream->sport;

            fragment->seqnum = stream->send_nxt;
            fragment->acknum = stream->recv_nxt;

            fragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
            fragment->windows = TCP_INITIAL_WINDOW;
            fragment->hdrlen_off = 0x50;

            rte_ring_mp_enqueue(stream->sndbuf, fragment);
            // 发送完了之后status状态更新
            stream->status = NG_TCP_STATUS_LAST_ACK;

            set_fd_frombitmap(fd);
        }else {  // nsocket创建对应的释放
            struct ng_tcp_table *table = tcpInstance();
            LL_REMOVE(stream, table->tcp_set);
            rte_free(stream);
        }

    }
    return 0;
}

#define UDP_APP_RECV_BUFFER_SIZE    128

// 
static int udp_server_entry(__attribute__((unused))  void *arg) {

    int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);
    if (connfd == -1) {
        printf("sockfd failed\n");
        return -1;
    } 

    struct sockaddr_in localaddr, clientaddr; // struct sockaddr 
    memset(&localaddr, 0, sizeof(struct sockaddr_in));

    localaddr.sin_port = htons(8899);
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = inet_addr("10.164.16.40"); // 0.0.0.0

    nbind(connfd, (struct sockaddr*)&localaddr, sizeof(localaddr));

    char buffer[UDP_APP_RECV_BUFFER_SIZE] = {0};
    socklen_t addrlen = sizeof(clientaddr);
    while (1) {

        if (nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0, 
            (struct sockaddr*)&clientaddr, &addrlen) < 0) {

            continue;

        } else {

            printf("recv from %s:%d, data:%s\n", inet_ntoa(clientaddr.sin_addr), 
                ntohs(clientaddr.sin_port), buffer);
            nsendto(connfd, buffer, strlen(buffer), 0, 
                (struct sockaddr*)&clientaddr, sizeof(clientaddr));
        }

    }

    nclose(connfd);

}




#endif


#if ENABLE_TCP_APP

#if 0
//TCP 连接11个状态枚举
typedef enum _NG_TCP_STATUS {

    NG_TCP_STATUS_CLOSED = 0,
    NG_TCP_STATUS_LISTEN,
    NG_TCP_STATUS_SYN_RCVD,
    NG_TCP_STATUS_SYN_SENT,
    NG_TCP_STATUS_ESTABLISHED,

    NG_TCP_STATUS_FIN_WAIT_1,
    NG_TCP_STATUS_FIN_WAIT_2,
    NG_TCP_STATUS_CLOSING,
    NG_TCP_STATUS_TIME_WAIT,

    NG_TCP_STATUS_CLOSE_WAIT,
    NG_TCP_STATUS_LAST_ACK,
}NG_TCP_STATUS;

struct ng_tcp_stream { // tcp control block，想成表示一个TCP连接的结构体, 这玩意跟localhost一个思想

    int fd;

    uint32_t    dip;
    uint8_t     localmac[RTE_ETHER_ADDR_LEN];
    uint16_t    dport;  // 这个stream用来形容一个fd的？

    uint8_t     protocol;
/*********4+4+6+2+1 = 17-byte************************/
    uint32_t    sip;
    uint16_t    sport;
#if 0 //这里因为get_hostinfo_fromfd函数的原因，需要打乱下顺序
/************五元组*******************/
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint16_t proto;
/*************mac地址******************/
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
#endif
/*************收发包seq/ack number的字段*************/
    uint32_t send_nxt;
    uint32_t recv_nxt;

/**************TCP连接状态字段******************/
    NG_TCP_STATUS status;

/*************收发环形链表********************/
    struct rte_ring *sndbuf;
    struct rte_ring *rcvbuf;

/*************维护连接的双向链表指针,实际生产环境使用红黑树等等*************/
    struct ng_tcp_stream *prev;
    struct ng_tcp_stream *next;

/******************************************************/
    pthread_cond_t cond;
    pthread_mutex_t mutex;
};

struct ng_tcp_table {
    int counter;
    //struct ng_tcp_stream *listener_set;
    struct ng_tcp_stream *tcp_set;
};

struct ng_tcp_fragment { //一个TCP的数据包对应的结构体

/************TCP的头，共20个bytes*************/
    rte_be16_t    sport;      /**< TCP source port. */
    rte_be16_t    dport;      /**< TCP destination port. */
    rte_be32_t    seqnum;     /**< TX data sequence number. */
    rte_be32_t    acknum;     /**< RX data acknowledgment sequence number. */
    uint8_t       hdrlen_off; /**< Data offset. 单位4字节，4个有效位，最长15 * 4 = 60字节*/
    uint8_t       tcp_flags;  /**< TCP flags */
    rte_be16_t    windows;    /**< RX flow control window. */
    rte_be16_t    cksum;      /**< TCP checksum. */
    rte_be16_t    tcp_urp;    /**< TCP urgent pointer, if any. */
    //struct rte_tcp_hdr;
/************TCP 的option，最多可占60-20 = 40字节********************/
    int opt_len; // 单位uint32_t，也就是4byte
    uint32_t option[TCP_OPTION_LEN];
/*************TCP的data部分*******************************************/
    unsigned char *data;
    int length;
};

struct ng_tcp_table *tInst = NULL;

static struct ng_tcp_table *tcpInstance(void) {
    if(tInst == NULL) {
        tInst = rte_malloc("tcp table", sizeof(struct ng_tcp_table), 0);
        if(tInst == NULL) {
            rte_exit(EXIT_FAILURE, "rte_malloc tcp table failed\n");
        }
        memset(tInst, 0, sizeof(struct ng_tcp_table));
    }
    return tInst;
}
#endif

/* 函数名：ng_tcp_stream_search
 * 入参：  五元组，都是输入参数,protocol先不用，默认都是IPPROTO_TCP
 * 返回值：struct ng_tcp_stream *指针
 * 作用：  在ng_tcp_stream组成的双向链表中，按照五元组这个唯一索引查找
 */
static struct ng_tcp_stream * ng_tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport){
    struct ng_tcp_table *table = tcpInstance();
    struct ng_tcp_stream *iter;
    for(iter = table->tcp_set; iter != NULL; iter=iter->next) { //established
        if(iter->sip == sip && iter->dip == dip && 
            iter->sport == sport && iter->dport == dport) {
            return iter;
        }
    }

    for(iter = table->tcp_set; iter != NULL; iter=iter->next) { // listen
        if(iter->dport == dport && iter->status == NG_TCP_STATUS_LISTEN) {
            return iter;
        }
    }
    return NULL;
}

static struct ng_tcp_stream * ng_tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {

    struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
    if(stream == NULL) {
        return NULL;
    }
    // tcp stream被创建之初，status填什么呢？tcp server端初始status是listen; tcp Client是closed
    stream->sip = sip;
    stream->dip = dip;
    stream->sport = sport;
    stream->dport = dport;
    stream->protocol = IPPROTO_TCP;
    stream->status = NG_TCP_STATUS_LISTEN;
    stream->fd = -1;// -1-> unused;
    // tcp 两个收发环
    stream->sndbuf = rte_ring_create("sndbuf", RING_SIZE, rte_socket_id(), 0);
    stream->rcvbuf = rte_ring_create("rcvbuf", RING_SIZE, rte_socket_id(), 0);
    if(stream->sndbuf == NULL || stream->rcvbuf == NULL) {
        printf("%s:%d: rte_ring_create failed\n", __func__, __LINE__);
    }
    // tcp 的序列号,初始化是随机的
    uint32_t next_seed = time(NULL);
    stream->send_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;
    //把网卡的mac地址放进来，在create新包的时候用
    rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

    // 加入accept阻塞机制
    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));
    
    // 把新创建的stream加入tcp table中,ng_tcp_handle_listen函数调用ng_tcp_create_stream函数，两者都用LL_ADD把一个stream加了两次
    // 导致自己指向自己
    //struct ng_tcp_table *table = tcpInstance();
    //LL_ADD(stream, table->tcp_set);
    //table->counter++;

    return stream;
}

static int ng_tcp_handle_listen(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, struct rte_ipv4_hdr *iphdr) {

    if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
        if(stream->status == NG_TCP_STATUS_LISTEN) {
            // step1:创建一个半连接的节点 即创建一个stream，fd为-1
            struct ng_tcp_stream *syn = ng_tcp_stream_create(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
            struct ng_tcp_table *table = tcpInstance();
            LL_ADD(syn, table->tcp_set);
            
            // step2:返回一个ack包，
            // 如果下一次再来一个syn，四元组已经存在，
            // ng_tcp_stream_search直接就返回了
            struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
            if(fragment == NULL)
                return -1;
            memset(fragment, 0, sizeof(struct ng_tcp_fragment));

            fragment->sport = tcphdr->dst_port;
            fragment->dport = tcphdr->src_port;
            struct in_addr addr;
            addr.s_addr = syn->sip;
            printf("tcp---->src:%s:%d", inet_ntoa(addr), ntohs(tcphdr->src_port));
            addr.s_addr = syn->dip;
            printf("---> dst:%s:%d\n", inet_ntoa(addr), ntohs(tcphdr->dst_port));

            fragment->seqnum = syn->send_nxt;
            syn->recv_nxt = ntohl(tcphdr->sent_seq) + 1; //先ntoh再加一，因为最小端加一与最大端加一是不一样的。
            fragment->acknum = syn->recv_nxt;

            fragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
            fragment->windows = TCP_INITIAL_WINDOW;
            fragment->opt_len = 0;
            fragment->hdrlen_off = 0x50;//0x05; 要写成0x50

            fragment->data = NULL;
            fragment->length = 0;

            int ret_val = rte_ring_mp_enqueue(syn->sndbuf, fragment);
            printf("%s:%d: ret_val is %d\n", __func__, __LINE__, ret_val);
            //fragment配置完了之后，状态机进行状态跃迁
            syn->status = NG_TCP_STATUS_SYN_RCVD;
        }
    }
    return 0;
}

static int ng_tcp_handle_syn_rev(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {
    if(tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
        if(stream->status == NG_TCP_STATUS_SYN_RCVD) {
            uint32_t acknum = ntohl(tcphdr->recv_ack);
            if(acknum == stream->send_nxt + 1) {
                //
            }
            stream->status = NG_TCP_STATUS_ESTABLISHED;

            //结合accept函数来实现,如果这里搜索不到listenfd那么accept那里直接锁死出不来了
            struct ng_tcp_stream *listenfd = ng_tcp_stream_search(0, 0, 0, stream->dport);
            if(listenfd == NULL) {
                printf("ng_tcp_stream_search listenfd failed");
                rte_exit(EXIT_FAILURE, "search listenfd failed\n");
            }
            pthread_mutex_lock(&listenfd->mutex);
            pthread_cond_signal(&listenfd->cond);
            pthread_mutex_unlock(&listenfd->mutex);
        }
    }
    return 0;
}

static int ng_tcp_enqueue_recvbuff(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen) {
    struct ng_tcp_fragment *rfragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
    if(rfragment == NULL) {
        printf("%s:%d rte_malloc failed\n", __func__, __LINE__);
        return -1;
    }
    memset(rfragment, 0, sizeof(struct ng_tcp_fragment));

    rfragment->dport = ntohs(tcphdr->dst_port);
    rfragment->sport = ntohs(tcphdr->src_port);

    uint8_t hdrlen = tcphdr->data_off >> 4;
    int payloadlen = tcplen - hdrlen * 4;

    if(payloadlen > 0) {
        // sizeof(struct rte_tcp_hdr)是固定值20字节，不包括option的长度
        uint8_t *payload = (uint8_t *)tcphdr + hdrlen * 4;
        rfragment->data = rte_malloc("unsigned char *", payloadlen+1, 0);
        if(rfragment->data == NULL) {
            printf("%s:%d rte_malloc failed\n", __func__, __LINE__);
            rte_free(rfragment);
            return -1;
        }
        
        memset(rfragment->data, 0, payloadlen+1);//多一个字节存\0
        rte_memcpy(rfragment->data, payload, payloadlen);
        rfragment->length = payloadlen;
        //printf("%s:%d: tcp: %s\n", __func__, __LINE__, rfragment->data);
    } else if(payloadlen == 0) {
        rfragment->length = 0;
        rfragment->data = NULL;
    }
    rte_ring_mp_enqueue(stream->rcvbuf, rfragment);//这里不能够free(rfragment);等posix api读取了之后再free

    pthread_mutex_lock(&stream->mutex);
    pthread_cond_signal(&stream->cond);
    pthread_mutex_unlock(&stream->mutex);
    
    return 0;
}

static int ng_tcp_send_ackpkt(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {
    struct ng_tcp_fragment *ackfrag = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
    if(ackfrag == NULL) {
        printf("%s:%d rte_malloc failed\n", __func__, __LINE__);
        return -1;
    }
    memset(ackfrag, 0, sizeof(struct ng_tcp_fragment));

    ackfrag->sport = tcphdr->dst_port;
    ackfrag->dport = tcphdr->src_port;

    //stream->recv_nxt;//对端发的数据包的next id是多少
    //stream->send_nxt;//本端发的数据包的next id是多少
    //if(stream->recv_nxt != ntohs(tcphdr->sent_seq)) { //出现dup ack

    //}
    //stream->recv_nxt += 1;
    //stream->send_nxt = ntohl(tcphdr->recv_ack);

    ackfrag->acknum = stream->recv_nxt;
    ackfrag->seqnum = stream->send_nxt;

    ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
    ackfrag->windows = TCP_INITIAL_WINDOW;
    ackfrag->hdrlen_off = 0x50;
    ackfrag->data = NULL;
    ackfrag->length= 0;
    rte_ring_mp_enqueue(stream->sndbuf, ackfrag);
    return 0;
}



static int ng_tcp_handle_established(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen) {
    
    if(tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
        //
    }
    if(tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) {
        //服务端在收到PSH包之后，会产生三个包，回复的ACK包，推给应用程序的数据包，回复的数据包
        //1 下面是要推给应用程序的包，甩给tcp posix api接口中的rcv_buff
#if 0
        struct ng_tcp_fragment *rfragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
        if(rfragment == NULL) {
            printf("%s:%d rte_malloc failed\n", __func__, __LINE__);
            return -1;
        }
        memset(rfragment, 0, sizeof(struct ng_tcp_fragment));

        rfragment->dport = ntohs(tcphdr->dst_port);
        rfragment->sport = ntohs(tcphdr->src_port);

        uint8_t hdrlen = tcphdr->data_off >> 4;
        int payloadlen = tcplen - hdrlen * 4;

        if(payloadlen > 0) {
            // sizeof(struct rte_tcp_hdr)是固定值20字节，不包括option的长度
            uint8_t *payload = (uint8_t *)tcphdr + hdrlen * 4;
            rfragment->data = rte_malloc("unsigned char *", payloadlen+1, 0);
            if(rfragment->data == NULL) {
                printf("%s:%d rte_malloc failed\n", __func__, __LINE__);
                rte_free(rfragment);
                return -1;
            }
            
            memset(rfragment->data, 0, payloadlen+1);//多一个字节存\0
            rte_memcpy(rfragment->data, payload, payloadlen);
            rfragment->length = payloadlen;
            printf("%s:%d: tcp: %s\n", __func__, __LINE__, rfragment->data);
        }
        rte_ring_mp_enqueue(stream->rcvbuf, rfragment);//这里不能够free(rfragment);等posix api读取了之后再free
#else
        ng_tcp_enqueue_recvbuff(stream, tcphdr, tcplen);
#endif
        //2 ack pkt,这个包是要发给对端的，所以sport是本地的port，dport是对端的ip
#if 0
        struct ng_tcp_fragment *ackfrag = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
        if(ackfrag == NULL) {
            printf("%s:%d rte_malloc failed\n", __func__, __LINE__);
            return -1;
        }
        memset(ackfrag, 0, sizeof(struct ng_tcp_fragment));

        ackfrag->sport = tcphdr->dst_port;
        ackfrag->dport = tcphdr->src_port;

        //stream->recv_nxt;//对端发的数据包的next id是多少
        //stream->send_nxt;//本端发的数据包的next id是多少
        if(stream->recv_nxt != ntohs(tcphdr->sent_seq)) { //出现dup ack

        }
        stream->recv_nxt += payloadlen;
        stream->send_nxt = ntohl(tcphdr->recv_ack);

        ackfrag->acknum = stream->recv_nxt;
        ackfrag->seqnum = stream->send_nxt;

        ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
        ackfrag->windows = TCP_INITIAL_WINDOW;
        ackfrag->hdrlen_off = 0x50;
        ackfrag->data = NULL;
        ackfrag->length= 0;
        rte_ring_mp_enqueue(stream->sndbuf, ackfrag);
#else
        uint8_t hdrlen = tcphdr->data_off >> 4;
        int payloadlen = tcplen - hdrlen * 4;
        stream->recv_nxt += payloadlen;
        stream->send_nxt = ntohl(tcphdr->recv_ack);
        ng_tcp_send_ackpkt(stream, tcphdr);
#endif

        //3 echo pkt,这一步已经没有意义了
#if 0
        struct ng_tcp_fragment *echofrag = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
        if(echofrag == NULL) {
            printf("%s: %d rte_malloc failed\n", __func__, __LINE__);
            return -1;
        }
        memset(echofrag, 0, sizeof(struct ng_tcp_fragment));
        echofrag->dport = tcphdr->src_port;
        echofrag->sport = tcphdr->dst_port;

        echofrag->acknum = stream->recv_nxt;
        echofrag->seqnum = stream->send_nxt;

        echofrag->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
        echofrag->windows = TCP_INITIAL_WINDOW;
        echofrag->hdrlen_off = 0x50;

        uint8_t *payload = (uint8_t *)tcphdr + hdrlen * 4;
        echofrag->data = rte_malloc("unsigned char *", payloadlen, 0);
        if(echofrag->data == NULL) {
            printf("%s: %d rte_malloc failed\n", __func__, __LINE__);
            return -1;
        }
        memset(echofrag->data, 0, payloadlen);

        rte_memcpy(echofrag->data, payload, payloadlen);
        echofrag->length = payloadlen;
        rte_ring_mp_enqueue(stream->sndbuf, echofrag);
#endif
    }
    if(tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

    }
    if(tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {
        stream->status = NG_TCP_STATUS_CLOSE_WAIT;
        // 当处于established状态时候收到fin包，也会产生两个数据，一个抛给应用层，一个返回ack
        // make a rfragment to tcp server app
#if 0
        struct ng_tcp_fragment *rfragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
        if(rfragment == NULL) {
            printf("%s:%d rte_malloc failed\n", __func__, __LINE__);
            return -1;
        }
        memset(rfragment, 0, sizeof(struct ng_tcp_fragment));

        rfragment->dport = ntohs(tcphdr->dst_port);
        rfragment->sport = ntohs(tcphdr->src_port);

        uint8_t hdrlen = tcphdr->data_off >> 4;
        int payloadlen = tcplen - hdrlen * 4;

        rfragment->length = 0;
        rfragment->data = NULL;
        rte_ring_mp_enqueue(stream->rcvbuf, rfragment);//这里不能够free(rfragment);等posix api读取了之后再free
#else
        ng_tcp_enqueue_recvbuff(stream, tcphdr, tcphdr->data_off >> 4); //tcplen这里写错了把
#endif
        // send ack ptk
        stream->recv_nxt += 1;
        stream->send_nxt = ntohl(tcphdr->recv_ack);
        ng_tcp_send_ackpkt(stream, tcphdr);
    }
    return 0;
}
//作为被动方，接收到fin之后，再返回一个ack
static int ng_tcp_handle_close_wait(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr)
{
    if(tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {
        if(stream->status == NG_TCP_STATUS_CLOSE_WAIT) {
            //避免重复的fin
        }
    }

    return 0;
}
// 使用net assistant做实验的时候，win10并没有回复第四次挥手
static int ng_tcp_handle_last_ack(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

		if (stream->status == NG_TCP_STATUS_LAST_ACK) {

			stream->status = NG_TCP_STATUS_CLOSED;

			printf("ng_tcp_handle_last_ack\n");
			struct ng_tcp_table *table = tcpInstance();
			LL_REMOVE(stream, table->tcp_set);

			rte_ring_free(stream->sndbuf);
			rte_ring_free(stream->rcvbuf);

			rte_free(stream);

		}

	}

	return 0;
}


static int ng_tcp_process(struct rte_mbuf *tcpmbuf) {
    struct rte_ipv4_hdr *iphdr = NULL;
    struct rte_tcp_hdr *tcphdr = NULL;
    struct ng_tcp_stream *stream = NULL;

    iphdr = (struct rte_ipv4_hdr *)rte_pktmbuf_mtod_offset(tcpmbuf, struct rte_ipv4_hdr *, 
        sizeof(struct rte_ether_hdr));
    tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);
    //处理包之前，先校验一波cksum,UDP也是这样，如果校验失败了，是内核抛弃还是APP抛弃？
    uint16_t tcpcksum = tcphdr->cksum;
    tcphdr->cksum = 0;
    uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
    if(cksum != tcpcksum){
        printf("cksum %x, tcp cksum %x\n", cksum, tcpcksum);
        return -1;
    }
    // step2: tcp协议api实现之accept的实现
    // 这里逻辑是这样的，先通过四元组找到stream（established的连接），
    // 找不到再通过dport找listen的stream
    stream = ng_tcp_stream_search(iphdr->src_addr, iphdr->dst_addr, 
        tcphdr->src_port, tcphdr->dst_port);
    if(stream == NULL) {
        /* 这里就不需要新创建stream了，
        stream = ng_tcp_stream_create(iphdr->src_addr, iphdr->dst_addr,
            tcphdr->src_port, tcphdr->dst_port);
        */
        return -2;
    }
    /****实现TCP连接的状态机，一个状态加一个回调函数，过滤器模式，责任链模式****/
    switch (stream->status) {
        case NG_TCP_STATUS_CLOSED:          // 这种只存在于client
            break;

        case NG_TCP_STATUS_LISTEN:          // 这种只存在于server
            ng_tcp_handle_listen(stream, tcphdr, iphdr);
            break;

        case NG_TCP_STATUS_SYN_RCVD:        // server
            ng_tcp_handle_syn_rev(stream, tcphdr);
            break;

        case NG_TCP_STATUS_SYN_SENT:        // client
            break;

        case NG_TCP_STATUS_ESTABLISHED: {    // server | client
            //计算TCP包的总长度=ip包总长度-ip头长度
            int tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
            ng_tcp_handle_established(stream, tcphdr, tcplen);
            break;
        }
        case NG_TCP_STATUS_FIN_WAIT_1:      
            // 暂定client,谁先主动断开，server | client,本代码中是由net assistant主动关闭的，所以暂定client
            break;

        case NG_TCP_STATUS_FIN_WAIT_2:      // 暂定client
            break;

        case NG_TCP_STATUS_CLOSING:         // 暂定client
            break;

        case NG_TCP_STATUS_TIME_WAIT:       // 暂定client
            break;

        case NG_TCP_STATUS_CLOSE_WAIT:      // 暂定server
            ng_tcp_handle_close_wait(stream, tcphdr);
            break;

        case NG_TCP_STATUS_LAST_ACK:        // 暂定server
            ng_tcp_handle_last_ack(stream, tcphdr);
            break;
    }
    return 0;
}

static int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
        uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {

    const unsigned total_len = fragment->length + fragment->opt_len * sizeof(uint32_t) + 
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);

    // 1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // 2 iphdr 
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64; // ttl = 64
    ip->next_proto_id = IPPROTO_TCP;
    ip->src_addr = sip;
    ip->dst_addr = dip;
    
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // 3 tcphdr
    struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    tcphdr->src_port = fragment->sport;
    tcphdr->dst_port = fragment->dport;
    tcphdr->sent_seq = htonl(fragment->seqnum);
    tcphdr->recv_ack = htonl(fragment->acknum);

    tcphdr->data_off = fragment->hdrlen_off;
    tcphdr->tcp_flags = fragment->tcp_flags;
    tcphdr->rx_win = fragment->windows;
    tcphdr->tcp_urp = fragment->tcp_urp;

    if (fragment->data != NULL) {
        uint8_t *payload = (uint8_t *)(tcphdr+1) + fragment->opt_len * sizeof(uint32_t);
        rte_memcpy(payload, fragment->data, fragment->length);
    }

    tcphdr->cksum = 0;
    tcphdr->cksum = rte_ipv4_udptcp_cksum(ip, tcphdr);

    return 0;
}

static struct rte_mbuf * ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
            uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {

    const unsigned total_len = fragment->length + fragment->opt_len * sizeof(uint32_t) + 
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);

        struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
        if(mbuf == NULL) {
            rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
        }
        mbuf->pkt_len = total_len;
        mbuf->data_len = total_len;

        uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *);
        ng_encode_tcp_apppkt(pktdata, sip, dip, srcmac, dstmac, fragment);
        return mbuf;
}

// ng_tcp_out负责从sndbuf里面取数据然后组包，之后再发给out ring
static int ng_tcp_out(struct rte_mempool *mbuf_pool) {
    struct ng_tcp_table *table = tcpInstance();
    struct ng_tcp_stream *iter;

    for(iter = table->tcp_set; iter != NULL; iter=iter->next) {

        if (iter->sndbuf == NULL) //跳过listenfd
            continue;

        struct ng_tcp_fragment *fragment = NULL;
        int nb_snd = rte_ring_mc_dequeue(iter->sndbuf, (void **)&fragment);
        if(nb_snd < 0)
            continue;
        uint8_t * dstmac = ng_get_dst_macaddr(iter->sip);
        if(dstmac == NULL) { // 如果server端不知道mac地址
            struct rte_mbuf *arpmbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, 
                gDefaultArpMac, iter->dip, iter->sip);
            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&arpmbuf, 1, NULL);
            rte_ring_mp_enqueue(iter->sndbuf, fragment);
        } else {
            struct rte_mbuf *tcpmbuf = ng_tcp_pkt(mbuf_pool, iter->dip, iter->sip, iter->localmac, dstmac, fragment);
            printf("%s:%d: tcp: %s\n", __func__, __LINE__, fragment->data);
            struct inout_ring * ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&tcpmbuf, 1, NULL);
            if(fragment->data != NULL) {
                rte_free(fragment->data);
            }
            rte_free(fragment);
        }
    }
    return 0;
}


#define BUFFER_SIZE 1024
static int tcp_server_entry(__attribute__((unused)) void *arg) {
    // step1：socket;这里面其实是kernel创建一个stream结构体,返回其中的fd
    int listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
    if (listenfd == -1) {
        return -1;
    }
    // step2: bind;就是将一个stream与一个sockaddr_in建立联系
    struct sockaddr_in servaddr; // struct sockaddr 
    memset(&servaddr, 0, sizeof(struct sockaddr_in));

    servaddr.sin_family = AF_INET;
        //servaddr.sin_addr.s_addr = inet_addr("10.164.16.40"); // 0.0.0.0
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(8899);
    nbind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    // step3: listen;监听
    nlisten(listenfd, 10);

    // step4: accept; accept返回一个客户端，并开始接收跟发送消息
#if 0
    while(1) {
        struct sockaddr_in client;
        socklen_t len = sizeof(client);
        int connfd = naccept(listenfd, (struct sockaddr*)&client, &len);

        char buff[BUFFER_SIZE] = {0};
        while(1) {
            int n = nrecv(connfd, buff, BUFFER_SIZE, 0); // block
            printf("%s:%d: nrecv return %d\n", __func__, __LINE__, n);
            if (n > 0) { //接收成功
                printf("%s:%d: tcp: %s\n", __func__, __LINE__, buff);
                nsend(connfd, buff, n, 0);
            } else if (n == 0) { //断开
                nclose(connfd);
                break;
            } else { // nonblock
            
            }
        }
    }
#else
    struct sockaddr_in client;
    socklen_t len = sizeof(client);
    int connfd = naccept(listenfd, (struct sockaddr*)&client, &len);

    char buff[BUFFER_SIZE] = {0};
    while(1) {
        int n = nrecv(connfd, buff, BUFFER_SIZE, 0); // block
        printf("%s:%d: nrecv return %d\n", __func__, __LINE__, n);
        if (n > 0) { //接收成功
            printf("%s:%d: tcp: %s\n", __func__, __LINE__, buff);
            nsend(connfd, buff, n, 0);
        } else if (n == 0) { //断开
            nclose(connfd);
        } else { // nonblock
        
        }
    }
#endif 
    nclose(listenfd);
}

#endif

int main(int argc, char *argv[]) {

    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
        
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
        0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    ng_init_port(mbuf_pool);

    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);

#if ENABLE_TIMER

    rte_timer_subsystem_init();

    struct rte_timer arp_timer;
    rte_timer_init(&arp_timer);

    uint64_t hz = rte_get_timer_hz();
    unsigned lcore_id = rte_lcore_id();
    rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);

#endif

#if ENABLE_RINGBUFFER

    struct inout_ring *ring = ringInstance();
    if (ring == NULL) {
        rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
    }

    if (ring->in == NULL) {
        ring->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }
    if (ring->out == NULL) {
        ring->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }

#endif

#if ENABLE_MULTHREAD

    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(pkt_process, mbuf_pool, lcore_id);

#endif

#if ENABLE_UDP_APP

    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(udp_server_entry, mbuf_pool, lcore_id);

#endif

#if ENABLE_TCP_APP
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(tcp_server_entry, mbuf_pool, lcore_id);
#endif

    while (1) {

        // rx
        struct rte_mbuf *rx[BURST_SIZE];
        unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, rx, BURST_SIZE);
        if (num_recvd > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        } else if (num_recvd > 0) {

            rte_ring_sp_enqueue_burst(ring->in, (void**)rx, num_recvd, NULL);
        }

        
        // tx
        struct rte_mbuf *tx[BURST_SIZE];
        unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void**)tx, BURST_SIZE, NULL);
        if (nb_tx > 0) {
#if 0
            struct rte_ether_hdr * ethhdr = rte_pktmbuf_mtod(tx[0], struct rte_ether_hdr *);
            struct rte_ipv4_hdr * iphdr = rte_pktmbuf_mtod_offset(tx[0], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
            struct rte_udp_hdr * udphdr = (struct rte_udp_hdr *)(iphdr + 1);
            struct in_addr addr;
            addr.s_addr = iphdr->src_addr;
            print_ethaddr("src_mac: ", &ethhdr->s_addr);
            printf(" src_addr: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));
            print_ethaddr("dest_mac: ", &ethhdr->d_addr);
            addr.s_addr = iphdr->dst_addr;
            printf(" main dst: %s:%d, len:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), udphdr->dgram_len, (char *)(udphdr+1));
#endif
            rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);

            unsigned i = 0;
            for (i = 0;i < nb_tx;i ++) {
                rte_pktmbuf_free(tx[i]);
            }
       }



#if ENABLE_TIMER

        static uint64_t prev_tsc = 0, cur_tsc;
        uint64_t diff_tsc;

        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
            rte_timer_manage();
            prev_tsc = cur_tsc;
        }

#endif

    }

}


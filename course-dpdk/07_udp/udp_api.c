
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <rte_malloc.h>
#include <rte_timer.h>

#include "arp.h"

#define ENABLE_SEND         1
#define ENABLE_ARP          1
#define ENABLE_ICMP         1
#define ENABLE_ARP_REPLY    1
#define ENABLE_DEBUG        1
#define ENABLE_TIMER        1
//07_udp
#define ENABLE_UDP_APP      1


#define ENABLE_RINGBUFF     1
#define ENABLE_MULTHREAD    1

#define NUM_MBUFS (4096-1)
#define BURST_SIZE	32
#define UDP_APP_RECV_BUFF_SIZE  128


#define TIMER_RESOLUTION_CYCLES 20000000000ULL


int gDpdkPortId = 0;

#if ENABLE_SEND

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

static uint32_t gLocalIp = MAKE_IPV4_ADDR(10, 164, 16, 24);

static uint32_t gSrcIp;
static uint32_t gDstIp;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

static uint16_t gSrcPort;
static uint16_t gDstPort;
#endif

#if ENABLE_ARP_REPLY
static uint8_t gDefArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#endif


#if ENABLE_RINGBUFF
#define RING_SIZE 1024
struct inout_ring{
    struct rte_ring * in;
    struct rte_ring * out;

};

static struct inout_ring * rInst = NULL;
//使用单例模式
static struct inout_ring * ringInstance(void)
{
    if(rInst == NULL){
        rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
        memset(rInst, 0, sizeof(struct inout_ring));
    }

    return rInst;
}
#endif

static struct rte_mempool * mbuf_pool = NULL;

static struct rte_mempool * mbufInstance(void){
    if(mbuf_pool == NULL) {
        mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    }
    return mbuf_pool;
}




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

	if (rte_eth_rx_queue_setup(gDpdkPortId, 0 , 128, 
		rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf_pool) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
	}

#if ENABLE_SEND
    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
     //[512, 4096]
    if(rte_eth_tx_queue_setup(gDpdkPortId, 0, 512,
        rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0){
        rte_exit(EXIT_FAILURE, "Could not setup TX queue.\n");
    }
#endif

	if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}

}

static int ng_encode_udp_pkt(uint8_t *msg, unsigned char * data, uint16_t total_len){
    
    //1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    //2 iphdr
    struct rte_ipv4_hdr * iphdr = (struct rte_ipv4_hdr *)(eth+1);
    iphdr->version_ihl = 0x45;
    iphdr->type_of_service = 0;
    iphdr->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    iphdr->packet_id = 0;
    iphdr->fragment_offset = 0;
    iphdr->time_to_live = 64;
    iphdr->next_proto_id = IPPROTO_UDP;
    iphdr->src_addr = gSrcIp;
    iphdr->dst_addr = gDstIp;
    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

    //3 udphdr
    struct rte_udp_hdr * udphdr = (struct rte_udp_hdr *)(iphdr+1);
    udphdr->src_port = gSrcPort;
    udphdr->dst_port = gDstPort;
    uint16_t udp_dgram_len = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr); //- sizeof(struct rte_udp_hdr);
    udphdr->dgram_len = htons(udp_dgram_len);
    udphdr->dgram_cksum = 0;

    rte_memcpy((uint8_t *)(udphdr+1), data, udp_dgram_len);
    udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr, udphdr);
#if 0
    struct in_addr addr;
    addr.s_addr = iphdr->src_addr;
	printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

	addr.s_addr = iphdr->dst_addr;
	printf("dst: %s:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), (char *)(udphdr+1));
#endif

    return 0;
}

static struct rte_mbuf * ng_send_udp(struct rte_mempool *mbuf_pool, unsigned char * data, uint16_t len){
    
    const unsigned total_len = len + sizeof(struct rte_ether_hdr) + \
        sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);

    if(!mbuf){
        rte_exit(EXIT_FAILURE, "Could not alloc mbuf.\n");
    }

    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *);

    ng_encode_udp_pkt(pktdata, data, total_len);

    return mbuf;
}


static inline void
print_ether_addr(const char *name , struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}


#if ENABLE_ARP

static int ng_encode_arp_pkt(uint8_t *msg, uint16_t opcode,
        uint8_t *dst_mac, uint32_t sip, uint32_t dip){
    
    //1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
#if 0
    if(!strncmp((const char *)dst_mac, (const char *)gDefArpMac, RTE_ETHER_ADDR_LEN)){
        uint8_t mac[RTE_ETHER_ADDR_LEN] = {0x0};
        rte_memcpy(eth->d_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
    } else{
        rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    }
#endif
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    //2 arp
    struct rte_arp_hdr *arphdr = (struct rte_arp_hdr *)(eth+1);
    arphdr->arp_hardware = htons(1);
    arphdr->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arphdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arphdr->arp_plen = sizeof(uint32_t);
    arphdr->arp_opcode = htons(opcode);
    
    rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    arphdr->arp_data.arp_sip = sip;
    arphdr->arp_data.arp_tip = dip;
    //print_ether_addr(__func__, &gSrcMac);
    return 0;
}

static struct rte_mbuf * ng_send_arp(struct rte_mempool *mbuf_pool, uint8_t opcode,
        uint8_t *dst_mac, uint32_t sip, uint32_t dip){
    const unsigned total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf * mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(NULL == mbuf){
        rte_exit(EXIT_FAILURE, "Could not alloc mbuf for %s.\n", __func__);
    }

    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;


    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ng_encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);

    return mbuf;
}
#endif

#if ENABLE_ICMP

static uint16_t ng_checksum(uint16_t *addr, int count){

    register long sum = 0;
    while(count > 1){
        sum += *(unsigned short *)addr++;
        count -= 2;
    }
    if(count > 0){
        sum += *(unsigned char *)addr;
    }
    while(sum >> 16){
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}
static int ng_encode_icmp(uint8_t * msg, uint8_t * dst_mac, uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnum){
    
    //1 ether
    struct rte_ether_hdr * eth= (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    //2 ipv4
    struct rte_ipv4_hdr * iphdr = (struct rte_ipv4_hdr *)(eth + 1);
    iphdr->version_ihl = 0x45;
    iphdr->type_of_service = 0;
    iphdr->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
    iphdr->packet_id = 0;
    iphdr->fragment_offset = 0;
    iphdr->time_to_live = 64;
    iphdr->next_proto_id = IPPROTO_ICMP;
    iphdr->src_addr = sip;
    iphdr->dst_addr = dip;

    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

    //3 icmp
    struct rte_icmp_hdr *icmp_hdr= (struct rte_icmp_hdr *)(iphdr+1);
    icmp_hdr->icmp_type = htons(RTE_IP_ICMP_ECHO_REPLY);
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_ident = id;
    icmp_hdr->icmp_seq_nb = seqnum;

    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = ng_checksum((uint16_t *)icmp_hdr, sizeof(struct rte_icmp_hdr));
    return 0;
}

static struct rte_mbuf * ng_send_icmp(struct rte_mempool * mbuf_pool, uint8_t *dst_mac,
    uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnum){

    const unsigned total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);
    struct rte_mbuf * mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf){
        rte_exit(EXIT_FAILURE, "Could not alloc mem for %s.\n", __func__);
    }

    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t * pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ng_encode_icmp(pkt_data, dst_mac, sip, dip, id, seqnum);

    return mbuf;
}
#endif

#if ENABLE_TIMER
static void
arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim,
	  __attribute__((unused)) void *arg){
    struct rte_mempool * mbuf_pool = (struct rte_mempool *)arg;
    struct inout_ring * ring = ringInstance();
#if 0
    struct rte_mbuf * arp_tx_mbuf = ng_send_arp(mbuf_pool, arphdr->arp_data.arp_sha.addr_bytes, 
        arphdr->arp_data.arp_tip, arphdr->arp_data.arp_sip);
    rte_eth_tx_burst(gDpdkPortId, 0, &arp_tx_mbuf, 1);
    rte_pktmbuf_free(arp_tx_mbuf);
#endif

    int i;
    for(i = 0; i < 254; i++){

        uint32_t dstip = (gLocalIp & 0x00FFFFFF) | ((i << 24) & 0xFF000000);
        struct in_addr addr;
        addr.s_addr = dstip;
        printf("%s, arp->src: %s\n", __func__, inet_ntoa(addr));

        struct rte_mbuf * arp_tx_mbuf =NULL;
        uint8_t *dstmac = ng_get_dst_macaddr(dstip);
        if(dstmac == NULL){
            arp_tx_mbuf= ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefArpMac, gLocalIp, dstip);
        } else {
            arp_tx_mbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, dstmac, gLocalIp, dstip);
        }
        //rte_eth_tx_burst(gDpdkPortId, 0, &arp_tx_mbuf, 1);
        //rte_pktmbuf_free(arp_tx_mbuf);
        rte_ring_mp_enqueue_burst(ring->out, (void **)&arp_tx_mbuf, 1, NULL);
    }
}
#endif

#if ENABLE_MULTHREAD

#if ENABLE_UDP_APP

static struct localhost * get_hostinfo_from_saddr_proto(struct sockaddr_in * saddr, int proto) {
    struct localhost *host = NULL;

    rte_spinlock_lock(&ghost->lock);
    for(host = ghost->entries; host != NULL; host = host->next){
        //printf("host->protocol: %d, host->localport: %u\n", host->protocol, host->localport);
        //printf("proto: %d, saddr->sin_port: %u\n", proto, saddr->sin_port);
        if(host->protocol == proto 
            && saddr->sin_port == host->localport){
            //&& saddr->sin_addr.s_addr == host->localip){
            rte_spinlock_unlock(&ghost->lock);
            return host;
        }
    }
    rte_spinlock_unlock(&ghost->lock);
    return NULL;
}

#define DEFAULT_FD_NUM 3

static int get_fd_from_bit_map(void){
    int fd = DEFAULT_FD_NUM;
    return fd;
}

static int socket1(int domain, int type, int protocol){
    int fd = get_fd_from_bit_map(); // step1：分配一个进程可用的fd,0,1,2是不能用的
    struct host_table * host_table = NULL;

    struct localhost * host = rte_malloc("localhost", sizeof(struct localhost), 0);
    if(NULL == host){               // step2：分配一个host结构体
        return -1;
    } else {
        memset(host, 0, sizeof(struct localhost));
    }

    host->fd = fd;
    if(type == SOCK_DGRAM)
        host->protocol = IPPROTO_UDP;
    else if(type == SOCK_STREAM)
        host->protocol = IPPROTO_TCP;
    host->recvbuf = rte_ring_create("recv buff", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if(NULL == host->recvbuf){
        rte_free(host);
        return -1;
    }
    host->sendbuf = rte_ring_create("send buff", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if(NULL == host->sendbuf){
        rte_ring_free(host->recvbuf);
        rte_free(host);
        return -1;
    }
    rte_spinlock_lock(&ghost->lock);
    LL_ADD(host, ghost);            // step3：将host加入到ghost链表中
    ghost->count++;
    rte_spinlock_unlock(&ghost->lock);
    return fd;
}

static struct localhost * get_hostinfo_from_fd(int sockfd){
    struct localhost *host = NULL;

    rte_spinlock_lock(&ghost->lock);
    for(host=ghost->entries; host != NULL; host = host->next){
        if(host->fd == sockfd){
            rte_spinlock_unlock(&ghost->lock);
            return host;
        }
    }
    rte_spinlock_unlock(&ghost->lock);
    return NULL;
}

int bind1(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    struct localhost * host =       NULL;
    struct sockaddr_in * laddr =    NULL;

    host = get_hostinfo_from_fd(sockfd);
    if(NULL == host){
        return -1;
    }

    laddr = (struct sockaddr_in *)addr;
    host->localport = laddr->sin_port;
    rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
    rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

    return 0;
}

ssize_t recvfrom1(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen) {
    //step1:定义局部变量
    struct localhost * host     = NULL;
    struct rte_mbuf * ptmbuf    = NULL;
    struct rte_ipv4_hdr *iphdr  = NULL;
    struct rte_udp_hdr * udphdr = NULL;
    uint16_t datalen = 0;

    //step2:参数校验
    if(buf == NULL || len == 0 ){
        return -1;
    }
    
    //step3:函数逻辑处理
    host = get_hostinfo_from_fd(sockfd);
    if(NULL == host) {
        return -1;
    } 
    // 从recvbuf中取包，每次只取一个
    if(!rte_ring_mc_dequeue_burst(host->recvbuf, &ptmbuf, 1, NULL)) {
        return -1;
    }
    iphdr =  rte_pktmbuf_mtod_offset(ptmbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    // 处理UDP的负载，复制到buff中;
    
    udphdr = (struct rte_udp_hdr *)(iphdr + 1);
    datalen = ntohs(udphdr->dgram_len);
    *((char*)udphdr + datalen) = '\0';
    rte_memcpy(buf, (char *)(udphdr + 1), datalen);
    return datalen;
}

ssize_t sendto1(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen) {
    //step1:定义局部变量
    struct rte_mempool *mbuf_pool  = NULL;
    struct rte_mbuf *mbuf          = NULL;
    struct localhost *host         = NULL;
    uint16_t total_len = 0;

    //step2:参数校验
    if(buf == NULL || len == 0){
        return -1;
    }

    //step3:主题逻辑处理
    host = get_hostinfo_from_fd(sockfd);
    if(NULL == host) {
        return -1;
    }
    
    mbuf_pool = mbufInstance();
    total_len = len + sizeof(struct rte_ether_hdr) + \
                      sizeof(struct rte_ipv4_hdr) + \
                      sizeof(struct rte_udp_hdr);
    mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(NULL == mbuf){
        return -1;
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;
    ng_encode_udp_pkt(rte_pktmbuf_mtod(mbuf, void *), buf, total_len);
    
    rte_ring_mp_enqueue_burst(host->sendbuf, &mbuf, 1, NULL);
    return 0;
}

static int close1(int fd){
    struct localhost * host = NULL;
    struct host_table * host_table = NULL;

    host = get_hostinfo_from_fd(fd);
    if(NULL == host){
        return -1;
    }

    rte_spinlock_lock(&ghost->lock);
    LL_REMOVE(host, ghost);
    ghost->count--;
    rte_spinlock_unlock(&ghost->lock);

    if(NULL != host->recvbuf){
        rte_ring_free(host->recvbuf);
    }
    if(NULL != host->sendbuf){
        rte_ring_free(host->sendbuf);
    }

    rte_free(host);
    return 0;
}

static int udp_server_entry(void * args){

    int connfd = socket1(AF_INET, SOCK_DGRAM, 0);
    if (connfd == -1){
        printf("socket failed\n");
        return -1;
    }

    struct sockaddr_in localaddr, clientaddr;
    memset(&localaddr, 0, sizeof(struct sockaddr_in));

    localaddr.sin_port = htons(8899);
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = htonl(INADDR_ANY); // 0.0.0.0
    bind1(connfd, (struct sockaddr*)&localaddr, sizeof(localaddr));

    char buffer[UDP_APP_RECV_BUFF_SIZE] = {0};
    socklen_t addrlen;
    
    while(1){
        if(recvfrom1(connfd, buffer, UDP_APP_RECV_BUFF_SIZE, 0, (struct sockaddr*)&clientaddr, &addrlen) < 0){
            continue;
        } else {
            printf("recv from %s: %d, data: %s\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), buffer);
            sendto1(connfd, buffer, strlen(buffer), 0, (struct sockaddr*)&clientaddr, sizeof(clientaddr));
        }
    }
    close1(connfd);

}

#endif

static int udp_process(struct rte_mbuf *mbuf,  struct rte_ether_hdr *ehdr){
    struct rte_ipv4_hdr * iphdr = NULL;
    struct rte_udp_hdr * udphdr = NULL;
    struct localhost * host = NULL;

    iphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    udphdr = (struct rte_udp_hdr *)(iphdr + 1);
#if ENABLE_SEND
    rte_memcpy(&gDstMac, &ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

    rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
    rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));

    rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
    rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));
#endif

    uint16_t length = ntohs(udphdr->dgram_len);
    *((char*)udphdr + length) = '\0';
#if 1
    struct in_addr addr;
    addr.s_addr = iphdr->src_addr;
    printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

    addr.s_addr = iphdr->dst_addr;
    printf("dst: %s:%d, len:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), length, (char *)(udphdr+1));
#endif

    //enqueue --> recvbuff
    struct sockaddr_in saddr;
    int protocol = IPPROTO_UDP;
    saddr.sin_port = udphdr->dst_port;
    saddr.sin_addr.s_addr = iphdr->dst_addr;
    host = get_hostinfo_from_saddr_proto(&saddr, protocol);
    if(host == NULL)
        return -1;
    rte_ring_mp_enqueue_burst(host->recvbuf, (void**)&mbuf, 1, NULL);
	return 0;

}
#endif 

static int pkt_process(__attribute__((unused)) void *arg){
    struct rte_mempool * mbuf_pool = (struct rte_mempool *)arg;
    struct inout_ring * ring = ringInstance();
    struct localhost * host = NULL;
    struct rte_mbuf * ptmbuf = NULL;

    while(1){
        struct rte_mbuf * mbufs[BURST_SIZE];
        unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->in, (void**)mbufs, BURST_SIZE, NULL);
        unsigned i = 0;
		for (i = 0; i < num_recvd; i++) {
            //处理mac头， 二层的
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
#if ENABLE_ARP
            // handle arp，三层的
            if(ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)){
                struct rte_arp_hdr * arphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_arp_hdr *, 
                    sizeof(struct rte_ether_hdr));
                if(arphdr->arp_data.arp_tip == gLocalIp){
                    if(arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)){
                        struct rte_mbuf * arp_tx_mbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REPLY, 
                            arphdr->arp_data.arp_sha.addr_bytes, arphdr->arp_data.arp_tip, arphdr->arp_data.arp_sip);
                        //rte_eth_tx_burst(gDpdkPortId, 0, &arp_tx_mbuf, 1);
                        //rte_pktmbuf_free(arp_tx_mbuf);
                        rte_ring_mp_enqueue_burst(ring->out, (void **)&arp_tx_mbuf, 1, NULL);
                    } else if(arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)){

                        uint8_t *hwaddr = ng_get_dst_macaddr(arphdr->arp_data.arp_sip);
                        if(hwaddr == NULL){
                            struct arp_table * table = arp_table_instance();
                            struct arp_entry *entry = rte_malloc("arp entry", sizeof(struct arp_entry), 0);
                            if(entry){
                                memset(entry, 0, sizeof(struct arp_entry));
                                entry->ip = arphdr->arp_data.arp_sip;
                                rte_memcpy(entry->hwaddr, arphdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
                                entry->status = ARP_ENTRY_STATUS_DYNAMIC;

                                LL_ADD(entry, table);
                                table->count++;
                            }
#if ENABLE_DEBUG
                            struct arp_entry * iter;
                            for(iter = table->entries; iter != NULL; iter = iter->next){
                               print_ether_addr("arp entry --> mac: ", (struct rte_ether_addr *)iter->hwaddr);
                               struct in_addr addr;
                               addr.s_addr = iter->ip;
                               printf("ip: %s\n", inet_ntoa(addr));
                            }
#endif
                        }
                    }
                    rte_pktmbuf_free(mbufs[i]);
                }
                continue;
            }

#endif 
            // handle IPV4协议，三层的
            if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                continue;
            }
            // 获取IPV4的头，三层的
            struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
                sizeof(struct rte_ether_hdr));
            // 处理UDP协议，四层的
            if (iphdr->next_proto_id == IPPROTO_UDP) {
                udp_process(mbufs[i], ehdr);
            }
#if ENABLE_ICMP
            if (iphdr->next_proto_id == IPPROTO_ICMP){
                struct rte_icmp_hdr *icmp_hdr = (struct rte_icmp_hdr *)(iphdr+1);
                if(icmp_hdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST){
                    struct rte_mbuf *txbuf = ng_send_icmp(mbuf_pool, ehdr->s_addr.addr_bytes, 
                        iphdr->dst_addr, iphdr->src_addr,icmp_hdr->icmp_ident, icmp_hdr->icmp_seq_nb);
                    //rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
                    //rte_pktmbuf_free(txbuf);
                    rte_ring_mp_enqueue_burst(ring->out, (void**)&txbuf, 1, NULL);
                }
            }
#endif
        }
#if ENABLE_TIMER
        static uint64_t prev_tsc = 0, cur_tsc;
        uint64_t diff_tsc;
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        if(diff_tsc > TIMER_RESOLUTION_CYCLES){
            rte_timer_manage();
            prev_tsc = cur_tsc;
        }
#endif
        
        rte_spinlock_lock(&ghost->lock);
        for(host = ghost->entries; host != NULL; host = host->next){
            if(rte_ring_mc_dequeue_burst(host->sendbuf, &ptmbuf, 1, NULL)) {
                rte_ring_mp_enqueue_burst(ring->out, &ptmbuf, 1, NULL);
            }
        }
        rte_spinlock_unlock(&ghost->lock);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    unsigned lcore_id = rte_lcore_id();

    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

	struct rte_mempool *mbuf_pool = mbufInstance();
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}

	ng_init_port(mbuf_pool);
    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);
    
#if ENABLE_TIMER
    rte_timer_subsystem_init();

    struct rte_timer arp_timer;
    rte_timer_init(&arp_timer);

    uint64_t  hz = rte_get_timer_hz();
    rte_timer_reset(&arp_timer, hz, PERIODICAL, rte_socket_id(), arp_request_timer_cb, mbuf_pool);
#endif 


#if ENABLE_RINGBUFF
    //初始化inout ring buff
    struct inout_ring * ring = ringInstance();
    if(ring == NULL){
        rte_exit(EXIT_FAILURE, "Could not init inout ring\n");
    }

    if(ring->in == NULL){
        ring->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }
    if(ring->out == NULL){
        ring->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }

#endif
    host_table_init();
    
#if ENABLE_MULTHREAD
    //DPDK提供的启动线程的接口是跟CPU亲和的
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(pkt_process, (void *)mbuf_pool, lcore_id);

#endif

#if ENABLE_UDP_APP
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(udp_server_entry, (void *)mbuf_pool, lcore_id);
#endif

    while (1) {
        //handle rx 使用 ring in buff来处理网卡接受的数据包
        struct rte_mbuf *rx[BURST_SIZE];
        unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, rx, BURST_SIZE);
        if (num_recvd > BURST_SIZE) {
        	rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        } else if(num_recvd > 0) {
            //读取数据之应当enqueue --> in
            rte_ring_sp_enqueue_burst(ring->in, (void **)rx, num_recvd, NULL);
        }

        //handle tx 使用 ring out buff来处理将要xmit的数据包，并在burst之后释放数据包内存
        struct rte_mbuf *tx[BURST_SIZE];
        unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void **)tx, BURST_SIZE, NULL);
        if(nb_tx > 0){
#if 1
            struct rte_ether_hdr * ethhdr = rte_pktmbuf_mtod(tx[0], struct rte_ether_hdr *);
            struct rte_ipv4_hdr * iphdr = rte_pktmbuf_mtod_offset(tx[0], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
            struct rte_udp_hdr * udphdr = (struct rte_udp_hdr *)(iphdr + 1);
            struct in_addr addr;
            addr.s_addr = iphdr->src_addr;
            print_ether_addr("src_mac: ", &ethhdr->s_addr);
            printf(" src_addr: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));
            print_ether_addr("dest_mac: ", &ethhdr->d_addr);
            addr.s_addr = iphdr->dst_addr;
            printf(" main dst: %s:%d, len:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), udphdr->dgram_len, (char *)(udphdr+1));
#endif
            rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);
            unsigned i = 0;
            for(i = 0; i < nb_tx; i++){
                rte_pktmbuf_free(tx[i]);
            }
        }
	}

}





#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ENABLE_SEND 1
#define ENABLE_ARP 1

#define NUM_MBUFS (4096-1)
#define BURST_SIZE	32

int gDpdkPortId = 0;

#if ENABLE_SEND

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

static uint32_t gLocalIp = MAKE_IPV4_ADDR(10, 164, 16, 3);

static uint32_t gSrcIp;
static uint32_t gDstIp;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

static uint16_t gSrcPort;
static uint16_t gDstPort;
#endif

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
     //注意，下面代码如果出这个问题，nb_tx_desc(=128), should be: <= 4096, >= 512,队列包数量必须在[512, 4096]
    if(rte_eth_tx_queue_setup(gDpdkPortId, 0, 512,
        rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0){//网口，队列，队列包数量，socketID，配置包多大能发多少
        rte_exit(EXIT_FAILURE, "Could not setup TX queue.\n");
    }
#endif

	if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}

}

static int ng_encode_udp_pkt(uint8_t *msg, unsigned char * data, uint16_t total_len){
    //打包
    //1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    //2 iphdr
    struct rte_ipv4_hdr * iphdr = (struct rte_ipv4_hdr *)(eth+1);
    iphdr->version_ihl = 0x45;
    iphdr->type_of_service = 0;//语音通话，字符传输，流媒体都不一样
    iphdr->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    iphdr->packet_id = 0;//每个ip包都有自己的id
    iphdr->fragment_offset = 0;
    iphdr->time_to_live = 64;//ip包在发送的时候，没经过一个路由器-1，生存时间
    iphdr->next_proto_id = IPPROTO_UDP;//下层，也就是第四层是什么协议类型，这里是UDP协议
    iphdr->src_addr = gSrcIp;
    iphdr->dst_addr = gDstIp;
    iphdr->hdr_checksum = 0;//ip头的校验值，要先置0

    //3 udphdr
    struct rte_udp_hdr * udphdr = (struct rte_udp_hdr *)(iphdr+1);
    udphdr->src_port = gSrcPort;
    udphdr->dst_port = gDstPort;
    uint16_t udp_dgram_len = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_udp_hdr);
    udphdr->dgram_len = htons(udp_dgram_len);
    udphdr->dgram_cksum = 0;//udp头的校验值，也要先置0

    rte_memcpy((uint8_t *)(udphdr+1), data, udp_dgram_len);
    udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr, udphdr);
#if 1
    struct in_addr addr;
    addr.s_addr = iphdr->src_addr;
	printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

	addr.s_addr = iphdr->dst_addr;
	printf("dst: %s:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), (char *)(udphdr+1));
#endif

    return 0;
}

static struct rte_mbuf * ng_send_udp(struct rte_mempool *mbuf_pool, unsigned char * data, uint16_t len){
    //从mempool获取mbuf，使用dpdk内存池最小的单位是mbuf
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

#if ENABLE_ARP
static int ng_encode_arp_pkt(uint8_t *msg, 
    uint8_t *dst_mac, uint32_t sip, uint32_t dip){
    //打包
    //1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    //2 arp
    struct rte_arp_hdr *arphdr = (struct rte_arp_hdr *)(eth+1);
    arphdr->arp_hardware = htons(1);
    arphdr->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arphdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arphdr->arp_plen = sizeof(uint32_t);
    arphdr->arp_opcode = htons(2);
    rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    arphdr->arp_data.arp_sip = sip;
    arphdr->arp_data.arp_tip = dip;

    return 0;
}

static struct rte_mbuf * ng_send_arp(struct rte_mempool *mbuf_pool, 
    uint8_t *dst_mac, uint32_t sip, uint32_t dip){
    const unsigned total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf * mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(NULL == mbuf){
        rte_exit(EXIT_FAILURE, "Could not alloc mbuf for %s.\n", __func__);
    }

    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;


    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ng_encode_arp_pkt(pkt_data, dst_mac, sip, dip);

    return mbuf;
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

    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);//获取port0网口的mac地址

	while (1) {

		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}

		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++) {
            //2层-MAC层
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
#if ENABLE_ARP

            // handle arp (response)
            if(ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)){
                struct rte_arp_hdr * arphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_arp_hdr *, 
                    sizeof(struct rte_ether_hdr));

                
        

                if(arphdr->arp_data.arp_tip == gLocalIp){ //目标机器的IP等于本机(arp_tip /**< target IP address */)
                    struct in_addr addr;
                    addr.s_addr = arphdr->arp_data.arp_tip;
                    printf("src : %s\n", inet_ntoa(addr));
                
                    struct rte_mbuf * arp_tx_mbuf = ng_send_arp(mbuf_pool, arphdr->arp_data.arp_sha.addr_bytes, 
                        arphdr->arp_data.arp_tip, arphdr->arp_data.arp_sip);
                    rte_eth_tx_burst(gDpdkPortId, 0, &arp_tx_mbuf, 1);
                    rte_pktmbuf_free(arp_tx_mbuf);
                    rte_pktmbuf_free(mbufs[i]);
                }
                continue;
            }

#endif 
            // handle IPV4
            if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}
            //3层-IP层
			struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
			//4层-传输层UDP
			if (iphdr->next_proto_id == IPPROTO_UDP) {
				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);


#if ENABLE_SEND
                rte_memcpy(&gDstMac, &ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

                rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
                rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));

                rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
                rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));
#endif

				uint16_t length = ntohs(udphdr->dgram_len);
				*((char*)udphdr + length) = '\0';

				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

				addr.s_addr = iphdr->dst_addr;
				printf("dst: %s:%d, len:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), length,
					(char *)(udphdr+1));

#if ENABLE_SEND
                struct rte_mbuf *txbuf = ng_send_udp(mbuf_pool, (unsigned char *)(udphdr+1), length);
                rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
                rte_pktmbuf_free(txbuf);
#endif
				rte_pktmbuf_free(mbufs[i]);
			}
			
		}

	}

}





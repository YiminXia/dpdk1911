



#ifndef __NG_ARP_H__
#define __NG_ARP_H__

#include <rte_ether.h>


#define ARP_ENTRY_STATUS_DYNAMIC	0
#define ARP_ENTRY_STATUS_STATIC		1


#define LL_ADD(item, list) do {		\
	item->prev = NULL;				\
	item->next = list;				\
	if (list != NULL) list->prev = item; \
	list = item;					\
} while(0)


#define LL_REMOVE(item, list) do {		\
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;	\
	item->prev = item->next = NULL;			\
} while(0)


struct arp_entry {

	uint32_t ip;
	uint8_t hwaddr[RTE_ETHER_ADDR_LEN];

	uint8_t type;
	// 

	struct arp_entry *next;
	struct arp_entry *prev;
	
};

struct arp_table {

	struct arp_entry *entries;
	int count;

};



static struct  arp_table *arpt = NULL;

static struct  arp_table *arp_table_instance(void) {

	if (arpt == NULL) {

		arpt = rte_malloc("arp table", sizeof(struct  arp_table), 0);
		if (arpt == NULL) {
			rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
		}
		memset(arpt, 0, sizeof(struct  arp_table));
	}

	return arpt;

}


static uint8_t* ng_get_dst_macaddr(uint32_t dip) {

	struct arp_entry *iter;
	struct arp_table *table = arp_table_instance();

	for (iter = table->entries;iter != NULL;iter = iter->next) {
		if (dip == iter->ip) {
			return iter->hwaddr;
		}
	}

	return NULL;
}

#define TCP_OPTION_LEN      10
#define TCP_MAX_SEQ         4294967295
#define TCP_INITIAL_WINDOW  14600

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



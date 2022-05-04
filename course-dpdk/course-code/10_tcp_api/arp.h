



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

//TCP ����11��״̬ö��
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

struct ng_tcp_stream { // tcp control block����ɱ�ʾһ��TCP���ӵĽṹ��, �������localhostһ��˼��

    int fd;

    uint32_t    dip;
    uint8_t     localmac[RTE_ETHER_ADDR_LEN];
    uint16_t    dport;  // ���stream��������һ��fd�ģ�

    uint8_t     protocol;
/*********4+4+6+2+1 = 17-byte************************/
    uint32_t    sip;
    uint16_t    sport;
#if 0 //������Ϊget_hostinfo_fromfd������ԭ����Ҫ������˳��
/************��Ԫ��*******************/
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint16_t proto;
/*************mac��ַ******************/
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
#endif
/*************�շ���seq/ack number���ֶ�*************/
    uint32_t send_nxt;
    uint32_t recv_nxt;

/**************TCP����״̬�ֶ�******************/
    NG_TCP_STATUS status;

/*************�շ���������********************/
    struct rte_ring *sndbuf;
    struct rte_ring *rcvbuf;

/*************ά�����ӵ�˫������ָ��,ʵ����������ʹ�ú�����ȵ�*************/
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

struct ng_tcp_fragment { //һ��TCP�����ݰ���Ӧ�Ľṹ��

/************TCP��ͷ����20��bytes*************/
    rte_be16_t    sport;      /**< TCP source port. */
    rte_be16_t    dport;      /**< TCP destination port. */
    rte_be32_t    seqnum;     /**< TX data sequence number. */
    rte_be32_t    acknum;     /**< RX data acknowledgment sequence number. */
    uint8_t       hdrlen_off; /**< Data offset. ��λ4�ֽڣ�4����Чλ���15 * 4 = 60�ֽ�*/
    uint8_t       tcp_flags;  /**< TCP flags */
    rte_be16_t    windows;    /**< RX flow control window. */
    rte_be16_t    cksum;      /**< TCP checksum. */
    rte_be16_t    tcp_urp;    /**< TCP urgent pointer, if any. */
    //struct rte_tcp_hdr;
/************TCP ��option������ռ60-20 = 40�ֽ�********************/
    int opt_len; // ��λuint32_t��Ҳ����4byte
    uint32_t option[TCP_OPTION_LEN];
/*************TCP��data����*******************************************/
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



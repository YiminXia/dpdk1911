
#ifndef __NG_ARP_H__
#define __NG_ARP_H__

#include <rte_ether.h>


#define ARP_ENTRY_STATUS_DYNAMIC	0
#define ARP_ENTRY_STATUS_STATIC		1


#define LL_ADD(item, list) do {		\
	item->prev = NULL;				\
	item->next = list->entries;				\
	if (list->entries != NULL) list->entries->prev = item; \
	list->entries = item;					\
} while(0)


#define LL_REMOVE(item, list) do {		\
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list->entries == item) list->entries = item->next;	\
	item->prev = item->next = NULL;			\
} while(0)

struct arp_entry {
	uint32_t ip;
	uint8_t hwaddr[RTE_ETHER_ADDR_LEN];
	uint8_t status;
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
		arpt = rte_malloc("arp table", sizeof(struct arp_table), 0);
		if (arpt == NULL) {
			rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
		}
		memset(arpt, 0, sizeof(struct  arp_table));
	}

	return arpt;
}
struct offload { //不需要在offload里面声名mac地址，因为我们这里实现了arp协议栈
    uint32_t sip;
    uint32_t dip;

    uint16_t sport;
    uint16_t dport;

    int protocol;

    unsigned char *data;
    uint16_t length;
};

struct localhost {
    int         fd;

    unsigned int status;//阻塞，非阻塞标记
    uint32_t    localip;
    uint16_t    localport;
    uint8_t     localmac[RTE_ETHER_ADDR_LEN];

    int         protocol;

    struct rte_ring     *sendbuf;
    struct rte_ring     *recvbuf;
    //多个connfd，所以做成双向链表
    struct localhost    *prev;
    struct localhost    *next;

    pthread_cond_t cond; 
    pthread_mutex_t mutex;
};

struct host_table {
    rte_spinlock_t lock;
    struct localhost *entries;
    int count;
};

static struct host_table * ghost = NULL;

static void host_table_init(void) {
    ghost = rte_malloc("host table", sizeof(struct host_table), 0);
    if(ghost == NULL){
        rte_exit(EXIT_FAILURE, "rte_malloc host table failed.\n");
    }
    memset(ghost, 0x00, sizeof(struct host_table));
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

#endif


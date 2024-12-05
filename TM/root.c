#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#include <string.h>
#include <stdlib.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"
#include "net/rpl/rpl.h"

#define MAX_PAYLOAD_LEN 120
#define MCAST_SINK_UDP_PORT 3001 
#define Imin (CLOCK_SECOND * 64) 
#define Imax (CLOCK_SECOND * 132) 
#define k 2 

static struct uip_udp_conn *mcast_conn;
static char buf[MAX_PAYLOAD_LEN];
static clock_time_t I; 
static clock_time_t t; 
static struct etimer et;
static int c = 2; //dat c > k de loai bo goi tin dau tien
static uint32_t seq_id;
static uint32_t id = -2;
static uint32_t last_id = -1; 

/*---------------------------------------------------------------------------*/
PROCESS(rpl_root_process, "TM root");
AUTOSTART_PROCESSES(&rpl_root_process);
/*---------------------------------------------------------------------------*/
static void
multicast_send(void)
{
  	int random_choice = random_rand() % 2; //0: gui lai goi tin cu; 1: gui goi tin moi

  	if(random_choice == 0) {
    		id = uip_htonl(last_id); //gui lai goi tin truoc do
		c++;
  	} else {
    		id = uip_htonl(seq_id); //gui goi tin moi
		last_id = seq_id;
    		seq_id++;
		c = 0;
		etimer_set(&et, 0);
  	}

  	memset(buf, 0, MAX_PAYLOAD_LEN);
  	memcpy(buf, &id, sizeof(seq_id));

	PRINTF("Send to: ");
	PRINT6ADDR(&mcast_conn->ripaddr);
	PRINTF(" Remote Port %u,", uip_ntohs(mcast_conn->rport));
	PRINTF(" (msg=0x%08lx)", (unsigned long)uip_ntohl(*((uint32_t *)buf)));
	PRINTF(" %lu bytes\n", (unsigned long)sizeof(id));

  	uip_udp_packet_send(mcast_conn, buf, sizeof(id));
}
/*---------------------------------------------------------------------------*/
static void
renew(void)
{
  	int random_choice = random_rand() % 2;

  	if(random_choice == 0 && last_id != (uint32_t)-1) {
    		id = uip_htonl(last_id);
		c++;
		printf("Packet duplicated\n");
  	} else {
    		id = uip_htonl(seq_id);
    		last_id = seq_id;
    		seq_id++;
		c = 0;
		etimer_set(&et, 0);
  	}
}
/*---------------------------------------------------------------------------*/
static void
prepare_mcast(void)
{
  	uip_ipaddr_t ipaddr;

  	uip_ip6addr(&ipaddr, 0xFF1E, 0, 0, 0, 0, 0, 0x89, 0xABCD);
  	mcast_conn = udp_new(&ipaddr, UIP_HTONS(MCAST_SINK_UDP_PORT), NULL);
}

/*---------------------------------------------------------------------------*/
static void
set_own_addresses(void)
{
  	int i;
  	uint8_t state;
  	rpl_dag_t *dag;
  	uip_ipaddr_t ipaddr;

  	uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  	uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  	uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  	PRINTF("Our IPv6 addresses:\n");
  	for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    		state = uip_ds6_if.addr_list[i].state;
    		if(uip_ds6_if.addr_list[i].isused && (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      			PRINTF("  ");
      			PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      			PRINTF("\n");
      			if(state == ADDR_TENTATIVE) {
        			uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      			}
    		}
  	}

  	dag = rpl_set_root(RPL_DEFAULT_INSTANCE, &ipaddr);
  	if(dag != NULL) {
    		rpl_set_prefix(dag, &ipaddr, 64);
    		PRINTF("Created a new RPL dag with ID: ");
    		PRINT6ADDR(&dag->dag_id);
    		PRINTF("\n");
  	}
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rpl_root_process, ev, data)
{
  	PROCESS_BEGIN();

  	NETSTACK_MAC.off(1);

  	set_own_addresses();

  	prepare_mcast();

  	I = Imin;
  	t = (I / 2) + (random_rand() % (I / 2));
  	etimer_set(&et, t);

  	while(1) {
    		PROCESS_YIELD();
    		if(etimer_expired(&et)) {
      			if(c < k) {
        			multicast_send();
      			}
			else {
				printf("Wait new packet\n");
				renew();
			}

      		I = (2 * I < Imax) ? 2 * I : Imax;
      		t = (I / 2) + (random_rand() % (I / 2));
      		etimer_set(&et, t);
    	}
  }

  PROCESS_END();
}


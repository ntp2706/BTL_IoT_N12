#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define MCAST_SINK_UDP_PORT 3001 

static struct uip_udp_conn *sink_conn;
static uint16_t count;
static uint32_t last_seq_id;
static int inconsistent_flag;
static int c; 

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

/*---------------------------------------------------------------------------*/
PROCESS(mcast_sink_process, "TM sink");
AUTOSTART_PROCESSES(&mcast_sink_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  	if(uip_newdata()) {
    		uint32_t recv_seq_id = uip_ntohl(*((uint32_t *)uip_appdata));
    		count++;

    	if(recv_seq_id == last_seq_id) {
      		c++;
    	} else {
      		inconsistent_flag = 1;
      		last_seq_id = recv_seq_id;
      		c = 0; 
    	}
    
    	PRINTF("In: [0x%08lx], TTL %u, total %u, c %d\n",
        recv_seq_id, UIP_IP_BUF->ttl, count, c);
  	}
}

/*---------------------------------------------------------------------------*/
static uip_ds6_maddr_t *
join_mcast_group(void)
{
  	uip_ipaddr_t addr;
  	uip_ds6_maddr_t *rv;

  	uip_ip6addr(&addr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  	uip_ds6_set_addr_iid(&addr, &uip_lladdr);
  	uip_ds6_addr_add(&addr, 0, ADDR_AUTOCONF);

  	uip_ip6addr(&addr, 0xFF1E, 0, 0, 0, 0, 0, 0x89, 0xABCD);
  	rv = uip_ds6_maddr_add(&addr);

  	if(rv) {
    		PRINTF("Joined multicast group ");
    		PRINT6ADDR(&uip_ds6_maddr_lookup(&addr)->ipaddr);
    		PRINTF("\n");
  	}
  	return rv;
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(mcast_sink_process, ev, data)
{
  	PROCESS_BEGIN();

  	if(join_mcast_group() == NULL) {
    		PRINTF("Failed to join multicast group\n");
    		PROCESS_EXIT();
  	}

  	count = 0;
  	last_seq_id = -10;
  	inconsistent_flag = 0;
  	c = 0; 

  	sink_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  	udp_bind(sink_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));

  	PRINTF("Listening: ");
  	PRINT6ADDR(&sink_conn->ripaddr);
  	PRINTF(" local/remote port %u/%u\n",
        UIP_HTONS(sink_conn->lport), UIP_HTONS(sink_conn->rport));

  	while(1) {
    		PROCESS_YIELD();
    		if(ev == tcpip_event) {
      			tcpip_handler();
    		}
  	}

  	PROCESS_END();
}


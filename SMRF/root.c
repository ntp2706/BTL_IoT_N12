#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"
#include "net/rpl/rpl.h"

#define MAX_PAYLOAD_LEN 120
#define MCAST_SINK_UDP_PORT 3001 /* Host byte order */
#define SEND_INTERVAL CLOCK_SECOND /* clock ticks */
#define ITERATIONS 100 /* messages */

/* Start sending messages START_DELAY secs after we start so that routing can
 * converge */
#define START_DELAY 60


static struct uip_udp_conn *mcast_conn;
static char buf[MAX_PAYLOAD_LEN];
static uint32_t seq_id;

/* Variables for tracking packets */
static uint32_t total_sent = 0;

PROCESS(rpl_root_process, "RPL ROOT, Multicast Sender");
AUTOSTART_PROCESSES(&rpl_root_process);

static void
multicast_send(void)
{
  uint32_t id;

  id = uip_htonl(seq_id);
  memset(buf, 0, MAX_PAYLOAD_LEN);
  memcpy(buf, &id, sizeof(seq_id));

  PRINTF("Send to: ");
  PRINT6ADDR(&mcast_conn->ripaddr);
  PRINTF(" Remote Port %u,", uip_ntohs(mcast_conn->rport));
  PRINTF(" (msg=0x%08lx)", (unsigned long)uip_ntohl(*((uint32_t *)buf)));
  PRINTF(" %lu bytes\n", (unsigned long)sizeof(id));

  seq_id++;
  total_sent++;
  uip_udp_packet_send(mcast_conn, buf, sizeof(id));

  /* Send end message */
  if(seq_id == ITERATIONS) {
    memset(buf, 0, MAX_PAYLOAD_LEN);
    sprintf(buf, "END,%lu", (unsigned long)total_sent);
    uip_udp_packet_send(mcast_conn, buf, strlen(buf));
    PRINTF("End message sent: Total packets sent = %lu\n", (unsigned long)total_sent);
  }
}

static void
prepare_mcast(void)
{
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, 0xFF1E, 0, 0, 0, 0, 0, 0x89, 0xABCD);
  mcast_conn = udp_new(&ipaddr, UIP_HTONS(MCAST_SINK_UDP_PORT), NULL);
}

static void
set_own_addresses(void)
{
  uip_ipaddr_t ipaddr;
  rpl_dag_t *dag;

  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
  
  PRINTF("Our IPv6 addresses:\n");
  int i;
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    if(uip_ds6_if.addr_list[i].isused) {
      PRINTF("  ");
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
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

PROCESS_THREAD(rpl_root_process, ev, data)
{
  static struct etimer et;

  PROCESS_BEGIN();

  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);

  NETSTACK_MAC.off(1);

  set_own_addresses();

  prepare_mcast();

  etimer_set(&et, START_DELAY * CLOCK_SECOND);
  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&et)) {
      if(seq_id >= ITERATIONS) {
        etimer_stop(&et);
      } else {
        multicast_send();
        etimer_set(&et, SEND_INTERVAL);
      }
    }
  }

  PROCESS_END();
}


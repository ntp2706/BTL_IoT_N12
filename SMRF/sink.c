#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#include <string.h>
#include <stdio.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define MCAST_SINK_UDP_PORT 3001 /* Host byte order */
#define TRANSMISSION_TIME_SECONDS 100 /* Tổng thời gian truyền tín hiệu (100 giây) */

static struct uip_udp_conn *sink_conn;
static uint16_t count;

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#if !NETSTACK_CONF_WITH_IPV6 || !UIP_CONF_ROUTER || !UIP_CONF_IPV6_MULTICAST || !UIP_CONF_IPV6_RPL
#error "This example can not work with the current contiki configuration"
#error "Check the values of: NETSTACK_CONF_WITH_IPV6, UIP_CONF_ROUTER, UIP_CONF_IPV6_RPL"
#endif
/*---------------------------------------------------------------------------*/
PROCESS(mcast_sink_process, "Multicast Sink");
AUTOSTART_PROCESSES(&mcast_sink_process);
/*---------------------------------------------------------------------------*/
static uint32_t packets_received = 0;
static clock_time_t start_time, end_time; // Thời gian bắt đầu và kết thúc nhận gói tin
static uint32_t total_rx_time = 0;       // Tổng thời gian nhận
static clock_time_t tx_start_time, tx_end_time; // Thời gian bắt đầu và kết thúc truyền tín hiệu

static void
tcpip_handler(void)
{
  if(uip_newdata()) {
    char *data = (char *)uip_appdata;

    if(strncmp(data, "START", 5) == 0) {
      tx_start_time = clock_time(); 
      PRINTF("START received. Transmission started.\n");
    } else if(strncmp(data, "END", 3) == 0) {
      tx_end_time = clock_time(); 

      uint32_t total_sent = atoi(data + 4); 
      uint32_t packet_loss = total_sent - packets_received;

      PRINTF("END received\n");
      PRINTF("Total Sent: %lu\n", total_sent);
      PRINTF("Total Received: %lu\n", packets_received);

      if(total_sent > 0) {
        float pdr = (packets_received / (float)total_sent) * 100.0;
        PRINTF("PDR (Packet Delivery Ratio): %u.%02u%%\n", 
               (unsigned int)pdr, (unsigned int)((pdr - (unsigned int)pdr) * 100));
      }

      PRINTF("Packet Loss: %lu\n", packet_loss);
      
     PRINTF("Total RX Time: %lu ms\n", (total_rx_time * 1000) / CLOCK_SECOND);
      // Tính thời gian truyền tín hiệu
      uint32_t total_tx_time = (tx_end_time - tx_start_time) * 1000 / CLOCK_SECOND;
      PRINTF("Total TX Time: %lu ms\n", total_tx_time);
     

    } else {
      packets_received++;

      
      if(packets_received == 1) {
        start_time = clock_time(); 
      }

      
      clock_time_t current_time = clock_time();
      total_rx_time += (current_time - start_time);
      start_time = current_time; 
    }
  }
}
/*---------------------------------------------------------------------------*/
static uip_ds6_maddr_t *
join_mcast_group(void)
{
  uip_ipaddr_t addr;
  uip_ds6_maddr_t *rv;

  /* First, set our v6 global */
  uip_ip6addr(&addr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&addr, &uip_lladdr);
  uip_ds6_addr_add(&addr, 0, ADDR_AUTOCONF);

  /*
   * IPHC will use stateless multicast compression for this destination
   * (M=1, DAC=0), with 32 inline bits (1E 89 AB CD)
   */
  uip_ip6addr(&addr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
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

  PRINTF("Multicast Engine: '%s'\n", UIP_MCAST6.name);

  if(join_mcast_group() == NULL) {
    PRINTF("Failed to join multicast group\n");
    PROCESS_EXIT();
  }

  count = 0;

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
/*---------------------------------------------------------------------------*/




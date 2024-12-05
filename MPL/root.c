//root 



#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#include <string.h>
#include <stdlib.h>  // Để sử dụng random_rand

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define MAX_PAYLOAD_LEN 120
#define MCAST_SINK_UDP_PORT 3001
#define DUPLICATE_PROBABILITY 40 // Tỷ lệ trùng lặp 40%
#define MAX_PACKETS 100        // Số lượng gói tin muốn gửi

static struct uip_udp_conn *mcast_conn;
static char buf[MAX_PAYLOAD_LEN];
static struct etimer et;
static int packet_count = 0;  // Đếm số gói tin đã gửi

/*---------------------------------------------------------------------------*/
PROCESS(rpl_root_process, "Multicast Root");
AUTOSTART_PROCESSES(&rpl_root_process);
/*---------------------------------------------------------------------------*/
static void
multicast_send(void)
{
    snprintf(buf, sizeof(buf), "Packet %d", packet_count);

    // Xác suất để tạo ra gói tin trùng lặp
    if(random_rand() % 100 < DUPLICATE_PROBABILITY) {
        // Gửi gói tin trùng lặp (giữ nguyên cùng một nội dung như gói trước)
        PRINTF("Sending duplicate multicast message\n");
    } else {
        PRINTF("Sending multicast message to ");
        PRINT6ADDR(&mcast_conn->ripaddr);
        PRINTF("\n");
    }

    uip_udp_packet_send(mcast_conn, buf, strlen(buf));
    packet_count++;
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
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rpl_root_process, ev, data)
{
    PROCESS_BEGIN();

    NETSTACK_MAC.off(1);

    set_own_addresses();
    prepare_mcast();

    etimer_set(&et, CLOCK_SECOND * 5);

    while(packet_count < MAX_PACKETS) {
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
        multicast_send();
        etimer_reset(&et);
    }

    PRINTF("Root has sent %d packets and is now stopping.\n", packet_count);

    PROCESS_END();
}


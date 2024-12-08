#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define UIP_DS6_DEFAULT_PREFIX 0xaaaa

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

/* Định nghĩa các loại gói tin */
#define PACKET_TYPE_DATA        "DATA:"
#define PACKET_TYPE_DELEGATION  "DELEGATION:"

#define MAX_PAYLOAD_LEN         64
#define MCAST_SINK_UDP_PORT     3001 /* Host byte order - Cổng multicast */
#define SEND_INTERVAL           (CLOCK_SECOND) /* clock ticks */
#define ITERATIONS              100 /* số lần gửi */

#define MAX_DELEGATIONS 32

PROCESS(sink_process, "Multicast Sink");
AUTOSTART_PROCESSES(&sink_process);

/* Biến để quản lý kết nối UDP cho việc gửi dữ liệu */
static struct uip_udp_conn *sink_conn;

/* Biến để quản lý kết nối UDP cho việc nhận delegation */
static struct uip_udp_conn *delegation_recv_conn;

/* Bộ nhớ đệm để lưu trữ các delegation packet đã xử lý (để tránh vòng lặp) */
static char seen_delegations[MAX_DELEGATIONS][MAX_PAYLOAD_LEN];
static uint8_t seen_deleg_count = 0;

/* Bộ đệm để gửi và nhận gói tin */
static char send_buf[MAX_PAYLOAD_LEN];
static uint8_t send_seq_id = 0;

/*---------------------------------------------------------------------------*/
/* Hàm kiểm tra delegation packet đã xử lý trước đó chưa */
static int is_new_delegation(const char *packet) {
    int i;
    for(i = 0; i < seen_deleg_count; i++) {
        if(strcmp(seen_delegations[i], packet) == 0) {
            return 0; /* Đã xử lý trước đó */
        }
    }

    if(seen_deleg_count < MAX_DELEGATIONS) {
        strncpy(seen_delegations[seen_deleg_count++], packet, MAX_PAYLOAD_LEN - 1);
        seen_delegations[seen_deleg_count-1][MAX_PAYLOAD_LEN - 1] = '\0';
    }
    else {
        /* Dời các delegation packet sang trái và thêm mới vào cuối */
        for(i = 1; i < MAX_DELEGATIONS; i++) {
            strncpy(seen_delegations[i-1], seen_delegations[i], MAX_PAYLOAD_LEN - 1);
            seen_delegations[i-1][MAX_PAYLOAD_LEN - 1] = '\0';
        }
        strncpy(seen_delegations[MAX_DELEGATIONS-1], packet, MAX_PAYLOAD_LEN - 1);
        seen_delegations[MAX_DELEGATIONS-1][MAX_PAYLOAD_LEN - 1] = '\0';
    }

    return 1; /* Mới */
}

/*---------------------------------------------------------------------------*/
/* Hàm xử lý sự kiện TCP/IP */
static void tcpip_handler(void) {
    char received_packet[MAX_PAYLOAD_LEN];

    if(uip_newdata()) {
        /* Nhận dữ liệu và chuyển đổi */
        memcpy(received_packet, uip_appdata, uip_datalen());
        if(uip_datalen() >= MAX_PAYLOAD_LEN) {
            printf("Received packet too long\n");
            return;
        }
        received_packet[uip_datalen()] = '\0'; /* Đảm bảo chuỗi kết thúc đúng cách */

        /* Kiểm tra loại gói tin dựa trên tiền tố */
        if(strncmp(received_packet, PACKET_TYPE_DELEGATION, strlen(PACKET_TYPE_DELEGATION)) == 0) {
            /* Đây là gói tin delegation */
            printf("Received Delegation Packet: %s\n", received_packet);

            /* Kiểm tra xem delegation packet đã xử lý chưa */
            if(is_new_delegation(received_packet)) {
                /* Chỉ in thông báo mà không xử lý gói tin delegation */
                printf("Processing Delegation Packet: %s\n", received_packet);
            }
            else {
                printf("Duplicate Delegation Packet: %s, skipped.\n", received_packet);
            }
        }
        else {
            printf("Unknown packet type received: %s\n", received_packet);
        }
    }
}

/*---------------------------------------------------------------------------*/
/* Hàm tham gia nhóm multicast */
static uip_ds6_maddr_t *join_mcast_group(void) {
    uip_ipaddr_t addr;
    uip_ds6_maddr_t *rv;

    /* Đặt địa chỉ multicast mà Sink và Root sử dụng, ví dụ: FF1E::89:ABCD */
    uip_ip6addr(&addr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
    rv = uip_ds6_maddr_add(&addr);

    if(rv) {
        printf("Joined multicast group ");
        PRINT6ADDR(&rv->ipaddr);
        printf("\n");
    }
    return rv;
}

/*---------------------------------------------------------------------------*/
/* Hàm chuẩn bị kết nối multicast để gửi delegation packet */
static void prepare_multicast_send(void) {
    uip_ipaddr_t mcast_addr;

    /* Đặt địa chỉ multicast mà Sink và Root sử dụng, ví dụ: FF1E::89:ABCD */
    uip_ip6addr(&mcast_addr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
    sink_conn = udp_new(&mcast_addr, UIP_HTONS(MCAST_SINK_UDP_PORT), NULL);
    if(sink_conn != NULL) {
        printf("Initialized multicast send connection to ");
        PRINT6ADDR(&sink_conn->ripaddr);
        printf(" on port %u\n", UIP_HTONS(sink_conn->rport));
    }
    else {
        printf("Failed to initialize multicast send connection\n");
    }
}

/*---------------------------------------------------------------------------*/
/* Hàm thiết lập địa chỉ IPv6 */
static void set_own_addresses(void) {
    int i;
    uint8_t state;
    uip_ipaddr_t ipaddr;

    /* Thiết lập địa chỉ IPv6 với prefix mặc định */
    uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
    uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
    uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

    printf("Our IPv6 addresses:\n");
    for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
        state = uip_ds6_if.addr_list[i].state;
        if(uip_ds6_if.addr_list[i].isused &&
           (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
            printf("  ");
            PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
            printf("\n");
            if(state == ADDR_TENTATIVE) {
                uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
            }
        }
    }

    /* Sink không thiết lập RPL DAG */
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(sink_process, ev, data)
{
    static struct etimer et;

    PROCESS_BEGIN();

    printf("Multicast Sink Engine\n");

    /* Thiết lập địa chỉ IPv6 */
    set_own_addresses();

    /* Tham gia nhóm multicast */
    if(join_mcast_group() == NULL) {
        printf("Failed to join multicast group\n");
        PROCESS_EXIT();
    }

    /* Chuẩn bị kết nối multicast để gửi dữ liệu */
    prepare_multicast_send();

    /* Thiết lập kết nối UDP để nhận delegation packet */
    delegation_recv_conn = udp_new(NULL, UIP_HTONS(MCAST_SINK_UDP_PORT), NULL);
    if(delegation_recv_conn == NULL) {
        printf("Failed to create UDP connection for delegation receive\n");
        PROCESS_EXIT();
    }
    udp_bind(delegation_recv_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));

    printf("Listening for delegation on ");
    PRINT6ADDR(&delegation_recv_conn->ripaddr);
    printf(" port %u\n", UIP_HTONS(delegation_recv_conn->lport));

    /* Khởi tạo bộ đếm */
    send_seq_id = 0;

    /* Đặt timer để bắt đầu gửi dữ liệu sau START_DELAY */
    #define START_DELAY 5 /* Giả sử delay là 5 giây */
    etimer_set(&et, START_DELAY * CLOCK_SECOND);

    while(1) {
        PROCESS_YIELD();
        if(ev == PROCESS_EVENT_TIMER) {
            if(send_seq_id >= ITERATIONS) {
                etimer_stop(&et);
                printf("Sink finished sending data.\n");
                PROCESS_EXIT();
            }
            else {
                /* Gửi gói tin dữ liệu */
                memset(send_buf, 0, MAX_PAYLOAD_LEN);
                /* Tạo chuỗi dữ liệu với tiền tố "DATA:" */
                snprintf(send_buf, MAX_PAYLOAD_LEN, "%s%08u", PACKET_TYPE_DATA, send_seq_id);

                printf("Send to multicast group: %s\n", send_buf);

                /* Gửi gói tin multicast */
                uip_udp_packet_send(sink_conn, send_buf, strlen(send_buf));
                send_seq_id++;

                /* Đặt lại timer cho lần gửi tiếp theo */
                etimer_set(&et, SEND_INTERVAL);
            }
        }
        else if(ev == tcpip_event) {
            tcpip_handler();
        }
    }

    PROCESS_END();
}


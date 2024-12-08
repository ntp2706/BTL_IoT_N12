#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Định nghĩa các loại gói tin */
#define PACKET_TYPE_DATA        "DATA:"
#define PACKET_TYPE_DELEGATION  "DELEGATION:"

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"
#include "net/rpl/rpl.h"

/* Định nghĩa các hằng số */
#define UIP_DS6_DEFAULT_PREFIX 0xaaaa
#define MAX_PAYLOAD_LEN         64
#define MCAST_INTERMEDIATE_UDP_PORT 3001 /* Cổng multicast */

/* Số lượng gói tin đã nhìn thấy */
#define MAX_SEEN_PACKETS 32

PROCESS(intermediate_process, "Multicast Intermediate");
AUTOSTART_PROCESSES(&intermediate_process);

/* Kết nối UDP để gửi */
static struct uip_udp_conn *intermediate_send_conn;

/* Kết nối UDP để nhận */
static struct uip_udp_conn *intermediate_recv_conn;

/* Bộ đệm để gửi gói tin */
static char send_buf[MAX_PAYLOAD_LEN];

/* Mảng để lưu trữ các gói tin đã nhận nhằm tránh vòng lặp */
static char seen_packets[MAX_SEEN_PACKETS][MAX_PAYLOAD_LEN];
static uint8_t seen_count = 0;

/*---------------------------------------------------------------------------*/
/* Hàm kiểm tra xem gói tin đã được nhận trước đó hay chưa */
static int is_new_packet(const char *packet) {
    int i;

    /* Kiểm tra trong danh sách các gói tin đã thấy */
    for(i = 0; i < seen_count; i++) {
        if(strcmp(seen_packets[i], packet) == 0) {
            return 0; /* Đã thấy trước đó */
        }
    }

    /* Thêm gói tin mới vào danh sách */
    if(seen_count < MAX_SEEN_PACKETS) {
        strncpy(seen_packets[seen_count++], packet, MAX_PAYLOAD_LEN - 1);
        seen_packets[seen_count-1][MAX_PAYLOAD_LEN - 1] = '\0';
    }
    else {
        /* Dời các gói tin cũ sang trái và thêm gói tin mới vào cuối */
        for(i = 1; i < MAX_SEEN_PACKETS; i++) {
            strncpy(seen_packets[i-1], seen_packets[i], MAX_PAYLOAD_LEN - 1);
            seen_packets[i-1][MAX_PAYLOAD_LEN - 1] = '\0';
        }
        strncpy(seen_packets[MAX_SEEN_PACKETS-1], packet, MAX_PAYLOAD_LEN - 1);
        seen_packets[MAX_SEEN_PACKETS-1][MAX_PAYLOAD_LEN - 1] = '\0';
    }

    return 1; /* Gói tin mới */
}

/*---------------------------------------------------------------------------*/
/* Hàm xử lý các gói tin nhận được */
static void handle_received_packet(const char *packet) {
    /* Kiểm tra loại gói tin dựa trên tiền tố */
    if(strncmp(packet, PACKET_TYPE_DELEGATION, strlen(PACKET_TYPE_DELEGATION)) == 0) {
        /* Đây là gói tin DELEGATION */
        printf("Received Delegation Packet: %s\n", packet);

        /* Kiểm tra xem gói tin đã được xử lý chưa */
        if(is_new_packet(packet)) {
            /* Chuyển tiếp gói tin delegation */
            printf("Forwarding Delegation Packet: %s\n", packet);
            uip_udp_packet_send(intermediate_send_conn, packet, strlen(packet));
        }
        else {
            printf("Duplicate Delegation Packet: %s, skipped.\n", packet);
        }
    }
    else if(strncmp(packet, PACKET_TYPE_DATA, strlen(PACKET_TYPE_DATA)) == 0) {
        /* Đây là gói tin DATA */
        printf("Received Data Packet: %s\n", packet);

        /* Kiểm tra xem gói tin đã được xử lý chưa */
        if(is_new_packet(packet)) {
            /* Chuyển tiếp gói tin DATA */
            printf("Forwarding Data Packet: %s\n", packet);
            uip_udp_packet_send(intermediate_send_conn, packet, strlen(packet));
        }
        else {
            printf("Duplicate Data Packet: %s, skipped.\n", packet);
        }
    }
    else {
        /* Gói tin không xác định */
        printf("Unknown packet type received: %s\n", packet);
    }
}

/*---------------------------------------------------------------------------*/
/* Hàm xử lý sự kiện TCP/IP */
static void tcpip_handler(void) {
    char received_packet[MAX_PAYLOAD_LEN];

    if(uip_newdata()) {
        /* Kiểm tra độ dài gói tin */
        if(uip_datalen() >= MAX_PAYLOAD_LEN) {
            printf("Received packet too long\n");
            return;
        }

        /* Sao chép dữ liệu nhận được vào bộ đệm và thêm ký tự kết thúc chuỗi */
        memcpy(received_packet, uip_appdata, uip_datalen());
        received_packet[uip_datalen()] = '\0';

        /* Xử lý gói tin nhận được */
        handle_received_packet(received_packet);
    }
}

/*---------------------------------------------------------------------------*/
/* Hàm tham gia nhóm multicast */
static uip_ds6_maddr_t *join_mcast_group(void) {
    uip_ipaddr_t addr;
    uip_ds6_maddr_t *rv;

    /* Đặt địa chỉ multicast mà Sink và Intermediate sử dụng, ví dụ: FF1E::89:ABCD */
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
/* Hàm chuẩn bị kết nối multicast để gửi các gói tin */
static void prepare_multicast_send(void) {
    uip_ipaddr_t mcast_addr;

    /* Đặt địa chỉ multicast mà Sink và Intermediate sử dụng, ví dụ: FF1E::89:ABCD */
    uip_ip6addr(&mcast_addr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
    intermediate_send_conn = udp_new(&mcast_addr, UIP_HTONS(MCAST_INTERMEDIATE_UDP_PORT), NULL);
    if(intermediate_send_conn != NULL) {
        printf("Initialized multicast send connection to ");
        PRINT6ADDR(&intermediate_send_conn->ripaddr);
        printf(" on port %u\n", UIP_HTONS(intermediate_send_conn->rport));
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

    /* Intermediate không thiết lập RPL DAG */
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(intermediate_process, ev, data)
{
    PROCESS_BEGIN();

    printf("Multicast Intermediate Engine\n");

    /* Thiết lập địa chỉ IPv6 */
    set_own_addresses();

    /* Tham gia nhóm multicast */
    if(join_mcast_group() == NULL) {
        printf("Failed to join multicast group\n");
        PROCESS_EXIT();
    }

    /* Chuẩn bị kết nối multicast để gửi gói tin */
    prepare_multicast_send();

    /* Thiết lập kết nối UDP để nhận gói tin multicast */
    intermediate_recv_conn = udp_new(NULL, UIP_HTONS(0), NULL);
    if(intermediate_recv_conn == NULL) {
        printf("Failed to create UDP connection for receive\n");
        PROCESS_EXIT();
    }
    udp_bind(intermediate_recv_conn, UIP_HTONS(MCAST_INTERMEDIATE_UDP_PORT));

    printf("Listening for packets on ");
    PRINT6ADDR(&intermediate_recv_conn->ripaddr);
    printf(" port %u\n", UIP_HTONS(intermediate_recv_conn->lport));

    while(1) {
        PROCESS_YIELD();
        if(ev == tcpip_event) {
            tcpip_handler();
        }
    }

    PROCESS_END();
}
/*---------------------------------------------------------------------------*/


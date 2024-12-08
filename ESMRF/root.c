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
#include "net/rpl/rpl.h"

/* Định nghĩa các loại gói tin */
#define PACKET_TYPE_DATA        "DATA:"
#define PACKET_TYPE_DELEGATION  "DELEGATION:"

#define MAX_PAYLOAD_LEN         64
#define MCAST_ROOT_UDP_PORT     3001 /* Host byte order - Cổng multicast */

#define MAX_DELEGATIONS 32

PROCESS(root_process, "Multicast Root");
AUTOSTART_PROCESSES(&root_process);

/* Biến để quản lý kết nối UDP cho việc nhận dữ liệu và gửi delegation */
static struct uip_udp_conn *root_conn;

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
/* Hàm tạo và gửi delegation packet */
static void send_delegation_packet(const char *data_packet) {
    char delegation_packet[MAX_PAYLOAD_LEN];
    char seq_id_str[9]; /* 8 ký tự cho seq_id và 1 ký tự cho '\0' */
    uint32_t seq_id;

    /* Trích xuất seq_id từ data_packet */
    if(strlen(data_packet) < strlen(PACKET_TYPE_DATA) + 8) {
        printf("Invalid DATA packet format\n");
        return;
    }

    strncpy(seq_id_str, data_packet + strlen(PACKET_TYPE_DATA), 8);
    seq_id_str[8] = '\0';
    seq_id = (uint32_t)atoi(seq_id_str);

    /* Tạo delegation_packet bằng cách thay đổi tiền tố thành "DELEGATION:" và seq_id mới */
    snprintf(delegation_packet, MAX_PAYLOAD_LEN, "%s%08u", PACKET_TYPE_DELEGATION, seq_id);

    /* Kiểm tra xem delegation_packet đã được xử lý chưa */
    if(is_new_delegation(delegation_packet)) {
        /* Gửi delegation_packet bằng multicast */
        uip_udp_packet_send(root_conn, delegation_packet, strlen(delegation_packet));
        printf("Sent Delegation Packet: %s\n", delegation_packet);
    }
    else {
        printf("Duplicate Delegation Packet: %s, skipped.\n", delegation_packet);
    }
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
                /* Chỉ in thông báo mà không chuyển tiếp */
                printf("Processing Delegation Packet: %s\n", received_packet);
            }
            else {
                printf("Duplicate Delegation Packet: %s, skipped.\n", received_packet);
            }
        }
        else if(strncmp(received_packet, PACKET_TYPE_DATA, strlen(PACKET_TYPE_DATA)) == 0) {
            /* Đây là gói tin dữ liệu từ Sink */
            printf("Received Data Packet from Sink: %s\n", received_packet);

            /* Tạo và gửi delegation packet */
            send_delegation_packet(received_packet);
        }
        else {
            printf("Unknown packet type received: %s\n", received_packet);
        }
    }
}

/*---------------------------------------------------------------------------*/
/* Hàm tham gia nhóm multicast */
/*---------------------------------------------------------------------------*/
static uip_ds6_maddr_t *
join_mcast_group(void)
{
  uip_ipaddr_t addr;
  uip_ds6_maddr_t *rv;

  /* First, set our v6 global */
  uip_ip6addr(&addr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
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
/* Hàm chuẩn bị kết nối multicast để gửi delegation packet */
static void prepare_multicast_send(void) {
    uip_ipaddr_t mcast_addr;

    /* Đặt địa chỉ multicast mà Sink và Intermediate sử dụng, ví dụ: FF1E::89:ABCD */
    uip_ip6addr(&mcast_addr, 0xFF1E,0,0,0,0,0,0x89,0xABCD);
    root_conn = udp_new(&mcast_addr, UIP_HTONS(MCAST_ROOT_UDP_PORT), NULL);
    if(root_conn != NULL) {
        printf("Initialized multicast send connection to ");
        PRINT6ADDR(&root_conn->ripaddr);
        printf(" on port %u\n", UIP_HTONS(root_conn->rport));
    }
    else {
        printf("Failed to initialize multicast send connection\n");
    }
}

/*---------------------------------------------------------------------------*/
/* Hàm thiết lập địa chỉ IPv6 và tham gia RPL DAG */
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

    /* Trở thành root của một DODAG mới với ID là địa chỉ IPv6 toàn cầu của chúng ta */
    rpl_dag_t *dag = rpl_set_root(RPL_DEFAULT_INSTANCE, &ipaddr);
    if(dag != NULL) {
        rpl_set_prefix(dag, &ipaddr, 64);
        printf("Created a new RPL DAG with ID: ");
        PRINT6ADDR(&dag->dag_id);
        printf("\n");
    }
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(root_process, ev, data)
{
    PROCESS_BEGIN();

    printf("Multicast Root Engine\n");

    /* Thiết lập địa chỉ IPv6 và trở thành RPL root */
    set_own_addresses();

    /* Tham gia nhóm multicast */
    if(join_mcast_group() == NULL) {
        printf("Failed to join multicast group\n");
        PROCESS_EXIT();
    }

    /* Chuẩn bị kết nối multicast để gửi delegation packet */
    prepare_multicast_send();

    root_conn = udp_new(NULL, UIP_HTONS(0), NULL);
  udp_bind(root_conn, UIP_HTONS(MCAST_ROOT_UDP_PORT));

  PRINTF("Listening: ");
  PRINT6ADDR(&root_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n",
        UIP_HTONS(root_conn->lport), UIP_HTONS(root_conn->rport));
    /* Khởi tạo bộ đếm */
    send_seq_id = 0;

    while(1) {
        PROCESS_YIELD();
        if(ev == tcpip_event) {
            tcpip_handler();
        }
    }

    PROCESS_END();
}


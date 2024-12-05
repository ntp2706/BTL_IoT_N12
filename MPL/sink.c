//sink



#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"

#include <string.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define MCAST_SINK_UDP_PORT 3001
#define MAX_PACKETS 100        // Số gói tin muốn nhận

static struct uip_udp_conn *sink_conn;
static uint16_t count = 0;     // Số gói tin nhận được
static uint16_t duplicate_count = 0;  // Số gói tin trùng lặp
static uint32_t last_seq_id = -1;  // ID gói tin cuối cùng đã nhận
static int c = 0;  // Đếm số lần trùng lặp

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

PROCESS(mcast_sink_process, "MPL CLASSIC FLOODING sink");
AUTOSTART_PROCESSES(&mcast_sink_process);

// Biến trạng thái để dừng tiến trình khi cần thiết
static uint8_t exit_process = 0;

static void handle_received_data(void)
{
    if (uip_newdata()) {
        uint32_t received_seq_id = uip_ntohl(*(uint32_t *)uip_appdata);
        count++;  // Tăng số lượng gói tin nhận được

        // Kiểm tra nếu ID gói tin nhận được trùng với ID gói tin cuối cùng
        if (received_seq_id == last_seq_id) {
            duplicate_count++;  // Tăng số lượng gói tin trùng lặp
            c++;  // Tăng số lần trùng lặp liên tiếp
        } else {
            last_seq_id = received_seq_id;
            c = 0;  // Reset số lần trùng lặp
        }

        PRINTF("Received: [0x%08lx], TTL %u, total %u, duplicates %u, consecutive duplicates %d\n",
            received_seq_id, UIP_IP_BUF->ttl, count, duplicate_count, c);

        // Nếu tổng số gói tin nhận được đạt MAX_PACKETS, đánh dấu để thoát
        if (count + duplicate_count >= MAX_PACKETS) {
            // Tính toán hiệu suất và chuyển sang kiểu int
            int efficiency = (int)((100.0 * count) / MAX_PACKETS);  // Lấy phần nguyên của hiệu suất

            PRINTF("Sink: Total received: %lu, Duplicates: %lu, Efficiency: %d%%\n",
                   (unsigned long)count,
                   (unsigned long)duplicate_count,
                   efficiency);
            exit_process = 1;  // Đánh dấu để thoát
        }
    }
}

static uip_ds6_maddr_t *join_multicast_group(void)
{
    uip_ipaddr_t multicast_addr;
    uip_ds6_maddr_t *maddr;

    // Địa chỉ multicast
    uip_ip6addr(&multicast_addr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
    uip_ds6_set_addr_iid(&multicast_addr, &uip_lladdr);
    uip_ds6_addr_add(&multicast_addr, 0, ADDR_AUTOCONF);

    // Địa chỉ nhóm multicast cụ thể
    uip_ip6addr(&multicast_addr, 0xFF1E, 0, 0, 0, 0, 0, 0x89, 0xABCD);
    maddr = uip_ds6_maddr_add(&multicast_addr);

    if (maddr == NULL) {
        PRINTF("Error: Failed to join multicast group\n");
        return NULL;
    }

    PRINTF("Successfully joined multicast group ");
    PRINT6ADDR(&uip_ds6_maddr_lookup(&multicast_addr)->ipaddr);
    PRINTF("\n");

    return maddr;
}

PROCESS_THREAD(mcast_sink_process, ev, data)
{
    PROCESS_BEGIN();

    // Tham gia nhóm multicast, kiểm tra nếu thất bại
    if (join_multicast_group() == NULL) {
        PRINTF("Failed to join multicast group\n");
        exit_process = 1;  // Đánh dấu thoát
    }

    // Tạo kết nối UDP và bắt đầu lắng nghe
    sink_conn = udp_new(NULL, UIP_HTONS(0), NULL);
    if (sink_conn == NULL) {
        PRINTF("Error: Could not create UDP connection\n");
        exit_process = 1;  // Đánh dấu thoát
    }

    udp_bind(sink_conn, UIP_HTONS(MCAST_SINK_UDP_PORT));

    PRINTF("Listening on port %u\n", UIP_HTONS(sink_conn->lport));

    while (!exit_process) {  // Vòng lặp sẽ chạy cho đến khi exit_process được set = 1
        PROCESS_YIELD();  // Chờ sự kiện

        // Xử lý sự kiện tcpip_event khi có dữ liệu đến
        if (ev == tcpip_event) {
            handle_received_data();
        }
    }

    PRINTF("Exiting process gracefully...\n");
    PROCESS_END();
}


// SPDX-License-Identifier: GPL-3.0-only

/* Drive the pinned production loss detector and path-metrics exporter. No
 * retransmission or live network is needed to observe a lost DATAGRAM. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"

static uint64_t test_cwnd(void *unused)
{
    (void)unused;
    return 12000;
}

static const xqc_cong_ctrl_callback_t TEST_CC = {
    .xqc_cong_ctl_get_cwnd = test_cwnd,
};

static void datagram_loss(uint64_t initial, uint64_t expected)
{
    xqc_connection_t conn = {0};
    xqc_log_t log = {0};
    xqc_path_ctx_t path = {0};
    xqc_send_ctl_t ctl = {0};
    xqc_send_queue_t queue = {0};
    xqc_packet_out_t packet = {0};
    const xqc_pkt_num_space_t pns = XQC_PNS_APP_DATA;

    log.log_level = XQC_LOG_FATAL;
    conn.log = &log;
    conn.conn_send_queue = &queue;
    xqc_init_list_head(&conn.conn_paths_list);
    path.path_id = 7;
    path.path_state = XQC_PATH_STATE_ACTIVE;
    path.parent_conn = &conn;
    path.path_send_ctl = &ctl;
    xqc_list_add_tail(&path.path_list, &conn.conn_paths_list);
    ctl.ctl_conn = &conn;
    ctl.ctl_path = &path;
    ctl.ctl_cong_callback = &TEST_CC;
    ctl.ctl_pacing.ctl_ctx = &ctl;
    ctl.ctl_srtt = 1000;
    ctl.ctl_reordering_time_threshold_shift = 3;
    ctl.ctl_reordering_packet_threshold = 3;
    ctl.ctl_largest_acked[pns] = 10;
    ctl.ctl_detected_lost_packets = initial;
    ctl.ctl_bytes_in_flight = 1200;
    ctl.ctl_bytes_ack_eliciting_inflight[pns] = 1200;
    queue.sndq_conn = &conn;
    queue.sndq_packets_used = 1;
    xqc_init_list_head(&queue.sndq_unacked_packets[pns]);
    xqc_init_list_head(&queue.sndq_free_packets);
    xqc_init_list_head(&queue.sndq_lost_packets);
    packet.po_pkt.pkt_pns = pns;
    packet.po_pkt.pkt_num = 1;
    packet.po_path_id = 7;
    packet.po_sent_time = 1000;
    packet.po_used_size = 1200;
    packet.po_frame_types = XQC_FRAME_BIT_DATAGRAM;
    packet.po_flag = XQC_POF_IN_FLIGHT;
    xqc_send_queue_insert_unacked(&packet, &queue.sndq_unacked_packets[pns], &queue);

    xqc_send_ctl_detect_lost(&ctl, &queue, pns, 10000);
    assert(ctl.ctl_detected_lost_packets == expected);
    assert(ctl.ctl_lost_count == 0); /* upstream retransmission count */
    assert(ctl.ctl_lost_pkts_number == 1);
    assert(ctl.ctl_lost_dgram_cnt == 1);
    assert(conn.detected_loss_cnt == 1);
    assert(ctl.ctl_bytes_in_flight == 0);
    assert(packet.po_flag & XQC_POF_DROPPED_DGRAM);
    assert(xqc_list_empty(&queue.sndq_unacked_packets[pns]));
    assert(xqc_list_empty(&queue.sndq_lost_packets)); /* never repair a DATAGRAM */
    assert(queue.sndq_packets_free == 1);

    /* Sampling/detecting again must not count the same declaration twice. */
    xqc_send_ctl_detect_lost(&ctl, &queue, pns, 20000);
    assert(ctl.ctl_detected_lost_packets == expected);
    assert(ctl.ctl_lost_pkts_number == 1);
    xqc_conn_stats_t stats = {0};
    xqc_conn_path_metrics_print(&conn, &stats);
    assert(stats.paths_info_count == 1);
    assert(stats.paths_info[0].path_id == 7);
    assert(stats.paths_info[0].path_lost_count == 0);
    assert(stats.paths_info[0].path_detected_lost_packets == expected);
    free(stats.paths_info);
}

int main(void)
{
    datagram_loss(0, 1);
    datagram_loss(UINT32_MAX, (uint64_t)UINT32_MAX + 1);
    datagram_loss(UINT64_MAX, UINT64_MAX);
    puts("detected DATAGRAM loss is exported once without retransmission; 64-bit/saturation pass");
    return 0;
}

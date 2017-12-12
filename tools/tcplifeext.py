#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcplifeext    Trace the lifespan of TCP sessions and summarize.
#               For Linux, uses BCC, BPF. Embedded C.
#
# USAGE: tcplifeext [-h] [-C] [-S] [-p PID] [interval [count]]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# While throughput counters are emitted, they are fetched in a low-overhead
# manner: reading members of the tcp_info struct on TCP close. ie, we do not
# trace send/receive.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# IDEA: Julia Evans
#
# 18-Oct-2016   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from collections import deque
import argparse
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
import tempfile
import sched
import datetime
import time
import os
import threading

# arguments
examples = """examples:
    ./tcplifeext           # trace all TCP connect()s
"""
parser = argparse.ArgumentParser(
    description="Trace the lifespan of TCP sessions and summarize",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(birth, struct sock *, u64);

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    // XXX: switch some to u32's when supported
    u64 ts_us;
    u64 pid;
    u64 saddr;
    u64 daddr;
    u64 ports;
    u64 bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
    u64 bytes_acked; /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
    u64 segs_in; /* RFC4898 tcpEStatsPerfSegsIn */
    u64 segs_out; /* RFC4898 tcpEStatsPerfSegsOut */
    u64 span_us;
    char task[TASK_COMM_LEN];
    u64 srtt_us; /* smoothed round trip time << 3 in umsecs */
    u64 rttvar_us; /* smoothed mdev_max */
    u64 mss_cache; /* Cached effective MSS, not including SACKS */
    u64 advmss; /* Advertised MSS */
    u64 max_window; /* Maximal window ever seen from peer */
    u64 window_clamp; /* Maximal window to advertise */
    u64 lost_out; /* Lost packets */
    u64 sacked_out; /* SACK'd packets */
    u64 fackets_out; /* FACK'd packets */
    u64 tcpi_rto;
    u64 tcpi_ato;
};
BPF_PERF_OUTPUT(ipv4_events);

struct id_t {
    u32 pid;
    char task[TASK_COMM_LEN];
};
BPF_HASH(whoami, struct sock *, struct id_t);

/*
static u64 gcd(int a, int b)
{
    int temp;
    while (b != 0)
    {
        temp = a % b;
        a = b;
        b = temp;
    }
    return a;
}

static u64 j_to_usecs(const unsigned long j)
{
    int cd = 0, hz_to_usec_num = 0, hz_to_usec_den = 0;
    int hz = 0;
    hz = 250;
    cd = gcd(hz, 1000000);
    hz_to_usec_num = 1000000/cd;
    hz_to_usec_den = hz/cd;
    return (j * hz_to_usec_num) / hz_to_usec_den;
}
*/

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // lport is either used in a filter here, or later
    u16 lport = sk->__sk_common.skc_num;

    // dport is either used in a filter here, or later
    u16 dport = sk->__sk_common.skc_dport;

    /*
     * This tool includes PID and comm context. It's best effort, and may
     * be wrong in some situations. It currently works like this:
     * - record timestamp on any state < TCP_FIN_WAIT1
     * - cache task context on:
     *       TCP_SYN_SENT: tracing from client
     *       TCP_LAST_ACK: client-closed from server
     * - do output on TCP_CLOSE:
     *       fetch task context if cached, or use current task
     */

    // capture birth time
    if (state < TCP_FIN_WAIT1) {
        /*
         * Matching just ESTABLISHED may be sufficient, provided no code-path
         * sets ESTABLISHED without a tcp_set_state() call. Until we know
         * that for sure, match all early states to increase chances a
         * timestamp is set.
         * Note that this needs to be set before the PID filter later on,
         * since the PID isn't reliable for these early stages, so we must
         * save all timestamps and do the PID filter later when we can.
         */
        u64 ts = bpf_ktime_get_ns();
        birth.update(&sk, &ts);
    }

    // record PID & comm on SYN_SENT
    if (state == TCP_SYN_SENT || state == TCP_LAST_ACK) {
        // now we can PID filter, both here and a little later on for CLOSE
        struct id_t me = {.pid = pid};
        bpf_get_current_comm(&me.task, sizeof(me.task));
        whoami.update(&sk, &me);
    }

    if (state != TCP_CLOSE)
        return 0;

    // calculate lifespan
    u64 *tsp, delta_us;
    tsp = birth.lookup(&sk);
    if (tsp == 0) {
        whoami.delete(&sk);     // may not exist
        return 0;               // missed create
    }
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    birth.delete(&sk);

    // fetch possible cached data, and filter
    struct id_t *mep;
    mep = whoami.lookup(&sk);
    if (mep != 0)
        pid = mep->pid;

    // get tcp_sock stats
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    u64 bytes_received = 0, bytes_acked = 0, sport = 0, srtt_us, rttvar_us, mss_cache, advmss;
    u64 segs_in = 0, segs_out = 0;
    u64 max_window = 0, window_clamp = 0;
    u64 lost_out = 0, sacked_out = 0, fackets_out = 0;
    bytes_received = tp->bytes_received;
    bytes_acked = tp->bytes_acked;
    segs_in = tp->segs_in;
    segs_out = tp->segs_out;
    srtt_us = tp->srtt_us >> 3;
    rttvar_us = tp->mdev_us >> 2;
    mss_cache = tp->mss_cache;
    advmss = tp->advmss;
    max_window = tp->max_window;
    window_clamp = tp->window_clamp;
    lost_out = tp->lost_out;
    sacked_out = tp->sacked_out;
    fackets_out = tp->fackets_out;

    // get tcp_info stats
    struct tcp_info info;
    //int hz_to_usecs_num = 4000, hz_to_usecs_den = 1;
    const struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    memset(&info, 0, sizeof info);
    info.tcpi_rto = (icsk->icsk_rto * 4000) / 1;
    info.tcpi_ato = (icsk->icsk_ack.ato * 4000) / 1;

    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {
            .span_us = delta_us,
            .bytes_received = bytes_received, .bytes_acked = bytes_acked,
            .segs_in = segs_in, .segs_out = segs_out,
            .max_window = max_window, .window_clamp = window_clamp,
            .lost_out = lost_out, .sacked_out = sacked_out, .fackets_out = fackets_out,
            .tcpi_rto = info.tcpi_rto,
            .tcpi_ato = info.tcpi_ato,
        };
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        // a workaround until data4 compiles with separate lport/dport
        data4.pid = pid;
        data4.ports = ntohs(dport) + ((0ULL + lport) << 32);
        data4.srtt_us = srtt_us;
        data4.rttvar_us = rttvar_us;
        data4.mss_cache = mss_cache;
        data4.advmss = advmss;
        if (mep == 0) {
            bpf_get_current_comm(&data4.task, sizeof(data4.task));
        } else {
            bpf_probe_read(&data4.task, sizeof(data4.task), (void *)mep->task);
        }
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else /* 6 */ {
    }

    if (mep != 0)
        whoami.delete(&sk);

    return 0;
}
"""

if debug:
    print(bpf_text)

# event data
TASK_COMM_LEN = 16      # linux/sched.h

class Data_ipv4(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("ports", ct.c_ulonglong),
        ("bytes_received", ct.c_ulonglong),
        ("bytes_acked", ct.c_ulonglong),
        ("segs_in", ct.c_ulonglong),
        ("segs_out", ct.c_ulonglong),
        ("span_us", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN),
        ("srtt_us", ct.c_ulonglong),
        ("rttvar_us", ct.c_ulonglong),
        ("mss_cache", ct.c_ulonglong),
        ("advmss", ct.c_ulonglong),
        ("max_window", ct.c_ulonglong),
        ("window_clamp", ct.c_ulonglong),
        ("lost_out", ct.c_ulonglong),
        ("sacked_out", ct.c_ulonglong),
        ("fackets_out", ct.c_ulonglong),
        ("tcpi_rto", ct.c_ulonglong),
        ("tcpi_ato", ct.c_ulonglong),
    ]

# periodic scheduler from https://stackoverflow.com/a/2399145
def periodic(scheduler, interval, action, actionargs=()):
    scheduler.enter(interval, 1, periodic, (scheduler, interval, action, actionargs))
    action(*actionargs)

def format_ipv4_event(event):
    return 'pid={} task={} saddr={} sport={} daddr={} dport={} bytes_received={} bytes_acked={} segs_in={} segs_out={} span_us={} srtt_us={} rttvar_us={} mss_cache={} advmss={} max_window={}, window_clamp={} lost_out={} sacked_out={}, fackets_out={} tcpi_rto={} tcpi_ato={}'.format(
                event.pid, event.task.decode(),
                inet_ntop(AF_INET, pack("I", event.saddr)), event.ports >> 32,
                inet_ntop(AF_INET, pack("I", event.daddr)), event.ports & 0xffffffff,
                event.bytes_received, event.bytes_acked,
                event.segs_in, event.segs_out,
                event.span_us,
                event.srtt_us, event.rttvar_us,
                event.mss_cache, event.advmss,
                event.max_window, event.window_clamp,
                event.lost_out, event.sacked_out, event.fackets_out,
                event.tcpi_rto,
                event.tcpi_ato,
            )

# process event
def handle_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    curr_buff.append(event)


class MyScheduler(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.scheduler = sched.scheduler(time.time, time.sleep)

    def run(self):
        print('running scheduler')
        self.scheduler.run()


class MyWriter(threading.Thread):

    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        pass

    def write(self):
        if len(self.queue) == 0:
            return
        t = datetime.datetime.utcnow()
        ft = t.strftime('%Y%m%d-%H%M%S')
        fp = os.path.join('/mnt/data/tcpstats', ft)
        print('flushing buffer with {} events to {}'.format(len(self.queue), fp))
        events = [event for event in self.queue]
        s = '\n'.join([format_ipv4_event(event) for event in events]) + '\n'
        with open(fp, 'w') as f:
            f.write(s)
        self.clear()

    def clear(self):
        self.queue.clear()


# initialize BPF
b = BPF(text=bpf_text)

# set up buffer for events
curr_buff = deque()

# set up scheduler and writer for events
my_writer = MyWriter(queue=curr_buff)
my_writer.daemon = True
my_writer.start()
my_scheduler = MyScheduler()
my_scheduler.daemon = True
periodic(my_scheduler.scheduler, 5, my_writer.write)
my_scheduler.start()

# handle events
b["ipv4_events"].open_perf_buffer(handle_ipv4_event, page_cnt=64)
print('handling ipv4_events')
while 1:
    b.kprobe_poll()

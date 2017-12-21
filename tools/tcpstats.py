#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpstats  Trace the lifespan of TCP sessions and summarize.
#           For Linux, uses BCC, BPF. Embedded C.
#
# USAGE: tcpstats [-h] [-C] [-S] [-p PID] [interval [count]]
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
from time import sleep

# arguments
examples = """examples:
    ./tcpstats
"""
parser = argparse.ArgumentParser(
    description="Collect TCP session stats",
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

// event types
#define CLOSED      1
#define RETRANSMIT  2
#define TLP         3

// open types
#define ACTIVE  1
#define PASSIVE 2

struct birth_t {
    u64 ts;
    u64 open_type;
};
BPF_HASH(births, struct sock *, struct birth_t);

struct tcp_ipv4_sess_t {
    u64 event_type;
    u64 sample_rate;
    u64 ip_ver;
    u64 saddr;
    u64 daddr;
    u64 ports;
    u64 span_us;
    u64 open_type;
    u64 bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
    u64 bytes_acked; /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
    u64 segs_in; /* RFC4898 tcpEStatsPerfSegsIn */
    u64 segs_out; /* RFC4898 tcpEStatsPerfSegsOut */
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
BPF_PERF_OUTPUT(tcp_ipv4_sess_events);

int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (sk == NULL)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    struct birth_t b = {.ts = ts, .open_type = PASSIVE};
    births.update(&sk, &b);
    return 0;
}

int trace_connect(struct pt_regs *ctx, struct sock *sk)
{
    u64 ts = bpf_ktime_get_ns();
    struct birth_t b = {.ts = ts, .open_type = ACTIVE};
    births.update(&sk, &b);
    return 0;
};

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
    u16 lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    u16 family = sk->__sk_common.skc_family;
    
    if (state != TCP_CLOSE) {
        return 0;
    }

    struct birth_t *b;
    u64 ts = 0, open_type = 0;
    b = births.lookup(&sk);

    if (b != NULL) {
        ts = b->ts;
        open_type = b->open_type;
        births.delete(&sk);
    }

    u64 now = bpf_ktime_get_ns();
    
    struct tcp_sock *tcp_sock = (struct tcp_sock *)sk; 
    u64 bytes_received = 0, bytes_acked = 0;
    u64 segs_in = 0, segs_out = 0;
    u64 srtt_us = 0, rttvar_us = 0;
    u64 mss_cache = 0, advmss = 0;
    u64 max_window = 0, window_clamp = 0;
    u64 lost_out = 0, sacked_out = 0, fackets_out = 0;
    bytes_received = tcp_sock->bytes_received;
    bytes_acked = tcp_sock->bytes_acked;
    segs_in = tcp_sock->segs_in;
    segs_out = tcp_sock->segs_out;
    srtt_us = tcp_sock->srtt_us >> 3;
    rttvar_us = tcp_sock->mdev_us >> 2;
    mss_cache = tcp_sock->mss_cache;
    advmss = tcp_sock->advmss;
    max_window = tcp_sock->max_window;
    window_clamp = tcp_sock->window_clamp;
    lost_out = tcp_sock->lost_out;
    sacked_out = tcp_sock->sacked_out;
    fackets_out = tcp_sock->fackets_out; 

    struct tcp_info info;
    //int hz_to_usecs_num = 4000, hz_to_usecs_den = 1;
    const struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    memset(&info, 0, sizeof info);
    info.tcpi_rto = (icsk->icsk_rto * 4000) / 1;
    info.tcpi_ato = (icsk->icsk_ack.ato * 4000) / 1;

    if (family == AF_INET) {
        struct tcp_ipv4_sess_t sess = {
            .event_type = CLOSED,
            .sample_rate = 1,
            .ip_ver = 4,
            .open_type = open_type,
            .bytes_received = bytes_received, .bytes_acked = bytes_acked,
            .segs_in = segs_in, .segs_out = segs_out,
            .srtt_us = srtt_us, .rttvar_us = rttvar_us,
            .mss_cache = mss_cache, .advmss = advmss,
            .max_window = max_window, .window_clamp = window_clamp,
            .lost_out = lost_out, .sacked_out = sacked_out, .fackets_out = fackets_out,
            .tcpi_rto = info.tcpi_rto,
            .tcpi_ato = info.tcpi_ato,
        };
        sess.saddr = sk->__sk_common.skc_rcv_saddr;
        sess.daddr = sk->__sk_common.skc_daddr;
        sess.ports = ntohs(dport) + ((0ULL + lport) << 32);
        sess.span_us = (now - ts) / 1000;
        tcp_ipv4_sess_events.perf_submit(ctx, &sess, sizeof(sess));
    }

    return 0;
};



"""

class TCPIPv4Sess(ct.Structure):
    _fields_ = [
        ("event_type", ct.c_ulonglong),
        ("sample_rate", ct.c_ulonglong),
        ("ip_ver", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("ports", ct.c_ulonglong),
        ("span_us", ct.c_ulonglong),
        ("open_type", ct.c_ulonglong),
	("bytes_received", ct.c_ulonglong),
        ("bytes_acked", ct.c_ulonglong),
        ("segs_in", ct.c_ulonglong),
        ("segs_out", ct.c_ulonglong),
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

def on_tcp_ipv4_sess_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(TCPIPv4Sess)).contents
    print('event_type={} sample_rate={} ip_ver={} s={}:{} d={}:{} span={}us open_type={} bytes_received={} bytes_acked={} segs_in={} segs_out={} srtt_us={} rttvar_us={} mss_cache={} advmss={} max_window={}, window_clamp={} lost_out={} sacked_out={}, fackets_out={} tcpi_rto={}us tcpi_ato={}us'.format(
        event.event_type,
        event.sample_rate,
        event.ip_ver, 
        inet_ntop(AF_INET, pack("I", event.saddr)), 
        event.ports >> 32,
        inet_ntop(AF_INET, pack("I", event.daddr)), 
        event.ports & 0xffffffff,
        event.span_us,
        event.open_type,
	event.bytes_received, event.bytes_acked,
        event.segs_in, event.segs_out,
        event.srtt_us, event.rttvar_us,
        event.mss_cache, event.advmss,
        event.max_window, event.window_clamp,
        event.lost_out, event.sacked_out, event.fackets_out,
        event.tcpi_rto,
        event.tcpi_ato))

if debug:
    print(bpf_text)

# event data
TASK_COMM_LEN = 16      # linux/sched.h

# initialize BPF
wakeup_s = float(1)
poll_timeout = 1
exiting = False

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect")
#b.attach_kprobe(event="tcp_retransmit_skb", fn_name="trace_retransmit")
#b.attach_kprobe(event="tcp_send_loss_probe", fn_name="trace_tlp")

b["tcp_ipv4_sess_events"].open_perf_buffer(on_tcp_ipv4_sess_event, page_cnt=64)
while True:
    try:
        if not exiting:
            print('sleeping {}s'.format(wakeup_s))
            sleep(wakeup_s)
    except KeyboardInterrupt:
        exiting = True
    else:
        print('polling with {}s timeout'.format(poll_timeout))
        b.kprobe_poll(timeout=poll_timeout)
        if exiting:
            exit(0)
        continue

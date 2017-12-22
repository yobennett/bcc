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

struct tcp_ipv4_event_t {
    u64 event_type;
    u64 sample_rate;
    u64 ts_us; /* timestamp */
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
BPF_PERF_OUTPUT(tcp_ipv4_events);

int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (sk == NULL)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    struct birth_t b = {.ts = ts, .open_type = PASSIVE};
    births.update(&sk, &b);
    return 0;
}

int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    u64 ts = bpf_ktime_get_ns();
    struct birth_t b = {.ts = ts, .open_type = ACTIVE};
    births.update(&sk, &b);
    return 0;
};

static void get_sk_info(struct sock *sk, struct tcp_ipv4_event_t *event) {
    u16 lport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    u16 family = sk->__sk_common.skc_family;
    if (family == AF_INET) {
        event->saddr = sk->__sk_common.skc_rcv_saddr;
        event->daddr = sk->__sk_common.skc_daddr;
        event->ports = ntohs(dport) + ((0ULL + lport) << 32);
    }
}

static void get_tsk_info(struct tcp_sock *sk, struct tcp_ipv4_event_t *event) {
    event->bytes_received = sk->bytes_received;
    event->bytes_acked = sk->bytes_acked;
    event->segs_in = sk->segs_in;
    event->segs_out = sk->segs_out;
    event->srtt_us = sk->srtt_us >> 3;
    event->rttvar_us = sk->mdev_us >> 2;
    event->mss_cache = sk->mss_cache;
    event->advmss = sk->advmss;
    event->max_window = sk->max_window;
    event->window_clamp = sk->window_clamp;
    event->lost_out = sk->lost_out;
    event->sacked_out = sk->sacked_out;
    event->fackets_out = sk->fackets_out;
}

static void get_icsk_info(struct inet_connection_sock *sk, struct tcp_ipv4_event_t *event) {
    struct tcp_info info;
    //int hz_to_usecs_num = 4000, hz_to_usecs_den = 1;
    memset(&info, 0, sizeof info);
    info.tcpi_rto = (sk->icsk_rto * 4000) / 1;
    info.tcpi_ato = (sk->icsk_ack.ato * 4000) / 1;
    
    event->tcpi_rto = info.tcpi_rto;
    event->tcpi_ato = info.tcpi_ato;
}

static void get_birth_info(struct birth_t *b, struct tcp_ipv4_event_t *event) {
    u64 ts = 0, open_type = 0;
    u64 now = bpf_ktime_get_ns();
    if (b != NULL) {
        ts = b->ts;
        open_type = b->open_type;
        if (ts != 0) {
            event->span_us = (now - ts) / 1000;
        }
        if (open_type != 0) {
            event->open_type = open_type;
        }
    }
}

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    if (state != TCP_CLOSE) {
        return 0;
    }

    bpf_trace_printk("CLOSED\\n");
    struct tcp_ipv4_event_t event;
    memset(&event, 0, sizeof event);
    
    get_sk_info(sk, &event);

    struct birth_t *b;
    b = births.lookup(&sk);
    get_birth_info(b, &event);

    struct tcp_sock *tcp_sock = (struct tcp_sock *)sk; 
    get_tsk_info(tcp_sock, &event);
 
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    get_icsk_info(icsk, &event);

    event.ip_ver = 4;
    event.event_type = CLOSED;
    event.sample_rate = 1;
    event.ts_us = bpf_ktime_get_ns() / 1000;
    tcp_ipv4_events.perf_submit(ctx, &event, sizeof(event));

    if (b != NULL) {
        births.delete(&sk);
    }

    return 0;
};

int trace_retransmit(struct pt_regs *ctx, struct sock *sk) {
    bpf_trace_printk("RETRANSMIT\\n");
    struct tcp_ipv4_event_t event;
    memset(&event, 0, sizeof event);
    
    get_sk_info(sk, &event);

    struct birth_t *b;
    b = births.lookup(&sk);
    get_birth_info(b, &event);

    struct tcp_sock *tcp_sock = (struct tcp_sock *)sk; 
    get_tsk_info(tcp_sock, &event);
 
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    get_icsk_info(icsk, &event);

    event.ip_ver = 4;
    event.event_type = RETRANSMIT;
    event.sample_rate = 1;
    event.ts_us = bpf_ktime_get_ns() / 1000;
    tcp_ipv4_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_tlp(struct pt_regs *ctx, struct sock *sk) {
    bpf_trace_printk("TLP\\n");
    struct tcp_ipv4_event_t event;
    memset(&event, 0, sizeof event);
    
    get_sk_info(sk, &event);

    struct birth_t *b;
    b = births.lookup(&sk);
    get_birth_info(b, &event);

    struct tcp_sock *tcp_sock = (struct tcp_sock *)sk; 
    get_tsk_info(tcp_sock, &event);
 
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    get_icsk_info(icsk, &event);

    event.ip_ver = 4;
    event.event_type = TLP;
    event.sample_rate = 1;
    event.ts_us = bpf_ktime_get_ns() / 1000;
    tcp_ipv4_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}


"""

class TCPIPv4Event(ct.Structure):
    _fields_ = [
        ("event_type", ct.c_ulonglong),
        ("sample_rate", ct.c_ulonglong),
        ("ts_us", ct.c_ulonglong),
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

def on_tcp_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(TCPIPv4Event)).contents
    print('event_type={} sample_rate={} ts={}us ip_ver={} s={}:{} d={}:{} span={}us open_type={} bytes_received={} bytes_acked={} segs_in={} segs_out={} srtt_us={} rttvar_us={} mss_cache={} advmss={} max_window={}, window_clamp={} lost_out={} sacked_out={}, fackets_out={} tcpi_rto={}us tcpi_ato={}us'.format(
        event.event_type,
        event.sample_rate,
        event.ts_us,
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
b.attach_kprobe(event="tcp_retransmit_skb", fn_name="trace_retransmit")
b.attach_kprobe(event="tcp_send_loss_probe", fn_name="trace_tlp")
b["tcp_ipv4_events"].open_perf_buffer(on_tcp_ipv4_event, page_cnt=64)
while True:
    try:
        if not exiting:
            sleep(wakeup_s)
    except KeyboardInterrupt:
        exiting = True
    else:
        b.kprobe_poll(timeout=poll_timeout)
        if exiting:
            exit(0)
        continue

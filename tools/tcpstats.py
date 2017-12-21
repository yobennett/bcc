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

struct birth_t {
    u64 ts;
    u64 active;
};
BPF_HASH(births, struct sock *, struct birth_t);

struct id_t {
    u32 pid;
    char task[TASK_COMM_LEN];
};
BPF_HASH(whoami, struct sock *, struct id_t);

struct tcp_ipv4_sess_t {
    u64 ip_ver;
    u64 saddr;
    u64 daddr;
    u64 ports;
    u64 span_us;
    u64 active;
};
BPF_PERF_OUTPUT(tcp_ipv4_sess_events);

int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (sk == NULL)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    struct birth_t b = {.ts = ts, .active = 0};
    births.update(&sk, &b);
    return 0;
}

int trace_connect(struct pt_regs *ctx, struct sock *sk)
{
    u64 ts = bpf_ktime_get_ns();
    struct birth_t b = {.ts = ts, .active = 1};
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

    struct tcp_sock *tcp_sock = (struct tcp_sock *)sk; 

    struct birth_t *b;
    u64 ts = 0, active = 0;
    b = births.lookup(&sk);

    if (b != NULL) {
        ts = b->ts;
        active = b->active;
        births.delete(&sk);
    }

    u64 now = bpf_ktime_get_ns();

    if (family == AF_INET) {
        struct tcp_ipv4_sess_t sess = {
            .ip_ver = 4,
            .active = active,
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
        ("ip_ver", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("ports", ct.c_ulonglong),
        ("span_us", ct.c_ulonglong),
        ("active", ct.c_ulonglong),
    ]

def on_tcp_ipv4_sess_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(TCPIPv4Sess)).contents
    print('{} s={}:{} d={}:{} span={}us active={}'.format(
        event.ip_ver, 
        inet_ntop(AF_INET, pack("I", event.saddr)), 
        event.ports >> 32,
        inet_ntop(AF_INET, pack("I", event.daddr)), 
        event.ports & 0xffffffff,
        event.span_us,
        event.active))

if debug:
    print(bpf_text)

# event data
TASK_COMM_LEN = 16      # linux/sched.h

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect")

# handle events
b["tcp_ipv4_sess_events"].open_perf_buffer(on_tcp_ipv4_sess_event, page_cnt=64)
while True:
    b.kprobe_poll()

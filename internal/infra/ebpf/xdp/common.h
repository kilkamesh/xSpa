// +build ignore

#ifndef __COMMON_H
#define __COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef BPF_F_CURRENT_NETNS
#define BPF_F_CURRENT_NETNS (-1L)
#endif

struct bpf_ct_opts {
  int netns_id;
  int error;
  __u8 l4proto;
  __u8 dir;
  __u8 reserved[2];
};

struct __attribute__((packed)) spa_packet {
  __u64 siphash_mac;
  __u8 nonce[24];
  __u8 payload_tag[32];
};

extern struct nf_conn *bpf_xdp_ct_lookup(struct xdp_md *ctx,
                                         struct bpf_sock_tuple *tuple,
                                         __u32 tuple_len,
                                         struct bpf_ct_opts *opts,
                                         __u32 opts_len) __ksym;
extern void bpf_ct_release(struct nf_conn *nfct) __ksym;

volatile const __u32 SPA_PORT = 55555;
volatile __u8 SIPHASH_KEYS[16] = {0};

#endif
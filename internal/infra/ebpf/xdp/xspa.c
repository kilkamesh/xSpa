// +build ignore

#include "logic.h"

SEC("xdp")
int xspa_main(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_DROP;

  if (eth->h_proto == bpf_htons(ETH_P_ARP))
    return XDP_PASS;
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_DROP;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return XDP_DROP;

  __u32 src_ip = iph->saddr;
  __u16 sport = 0, dport = 0;

  if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (void *)(iph + 1);
    if ((void *)(udph + 1) > data_end)
      return XDP_DROP;
    sport = udph->source;
    dport = udph->dest;
  } else if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
      return XDP_DROP;
    sport = tcph->source;
    dport = tcph->dest;
  }

  if (check_conntrack(ctx, iph, sport, dport))
    return XDP_PASS;
  if (is_whitelisted(src_ip))
    return XDP_PASS;

  if (iph->protocol == IPPROTO_UDP) {
    return handle_spa(ctx, iph, data_end);
  }

  return XDP_DROP;
}

char __license[] SEC("license") = "Dual MIT/GPL";
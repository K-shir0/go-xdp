#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <arpa/inet.h>

SEC("xdp")
int xdp_prog_hello(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  int hdr_size = sizeof(*eth);

  // データ + ヘッダー がデータの終わりを超えないかどうか
  if (data + hdr_size > data_end)
      goto out;

  if (eth->h_proto == htons(ETH_P_IP)) {
    struct iphdr *iph = data + hdr_size;
    if ((void *)(iph + 1) > data_end)
      goto out;

    // ICMP == 1
    if (iph->protocol == 1) {
      return XDP_DROP;
    }
  }
  
  out:
    return XDP_PASS;
}
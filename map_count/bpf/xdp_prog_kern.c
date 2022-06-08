#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <arpa/inet.h>

struct datarec
{
  __u64 rx_packets;
  __u64 rx_bytes;
};

struct bpf_map_def SEC("maps") xdp_stats_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct datarec),
    .max_entries = 255,
};

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

SEC("xdp")
int xdp_prog_hello(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  int hdr_size = sizeof(*eth);

  // データ + ヘッダー がデータの終わりを超えないかどうか
  if (data + hdr_size > data_end)
  {
    goto out;
  }

  if (eth->h_proto == htons(ETH_P_IP))
  {
    struct iphdr *iph = data + hdr_size;
    if ((void *)(iph + 1) > data_end)
    {
      goto out;
    }

    struct datarec *rec;
    __u32 key = XDP_PASS; // これは何の為

    rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (!rec)
    {
      return XDP_ABORTED;
    }

    lock_xadd(&rec->rx_packets, 1);

    // バイト計算
    __u64 bytes = data_end - data;
    lock_xadd(&rec->rx_bytes, bytes);
  }

out:
  return XDP_PASS;
}
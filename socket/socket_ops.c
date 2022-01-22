#include <linux/bpf.h>

struct bpf_map_def __section("maps") sock_ops_map = {
    .type = BPF_MAP_TYPE_SOCKHASH,
    .key_size = sizeof(struct sock_key),
    .value_size = sizeof(int),
    .max_entries = 65535,
    .map_flags = 0,
};

struct sock_key {
  __u32 sip4;   // source ip
  __u32 dip4;   // destination ip
  __u8 family;  // 协议类型
  __u8 pad1;
  __u8 pad2;
  __u8 pad3;
  __u32 sport;  // source port
  __u32 dport;  // destination port
} __attribute__((packed));

void bpf_socket_ops(struct bpf_sock_ops *skops) {
  struct sock_key key = {};
  int res;

  // 从socket operations中获取socket信息到key中
  get_key_from_sock_ops(skops, &key);

  // 如果socket_hashmap中不存在该key，就更新
  res = sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
  if (res != 0) {
    printk("sock_hash_update failed, return value:%d", res);
  }

  printk("" sockmap
         : op % d, port % d-- > % d\n
                                    ", skops->op, skops->local_port, "
                                    "bpf_ntohl(skops->remote_port)");
};
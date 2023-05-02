
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "common_kern_user.h" 
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;
	__u64 bytes = data_end - data;

	rec->rx_packets++;
	rec->rx_bytes += bytes;
	return action;
}
static __always_inline
void xdp_print_ip(struct iphdr* ip){
	long i = ip->saddr;
	int j = i % 256;
	i /= 256;
	int f = i % (256);
	i /= 256;
	int s = i % (256);
	i /= 256;
	int q = i % 256;  
	bpf_printk("%d.%d",j,f);
	
	bpf_printk("%d.%d",s,q);
}
static __always_inline
void xdp_print_port(struct tcphdr* tcp){
	bpf_printk("%d",ntohs(tcp->dest));
	}
SEC("xdp_drop_HTTP")
int  xdp_drop_HTTP_func(struct xdp_md *ctx)
{
    const int l3_off = ETH_HLEN;                       // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr);  // TCP header offset
    const int l7_off = l4_off + sizeof(struct tcphdr); // L7 (e.g. HTTP)
	__u32 action;
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    
    
    if (data_end < data + l7_off){
        return XDP_PASS;
}
    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP)){
       return XDP_PASS;
}
    struct iphdr *ip = (struct iphdr *)(data + l3_off);
    if (ip->protocol != IPPROTO_TCP){
        return XDP_PASS;
        }
        if(ip->protocol == IPPROTO_TCP){    
    struct tcphdr *tcp = (struct tcphdr *)(data + l4_off);
    if (ntohs(tcp->dest) == 80){
        action =XDP_DROP;
        xdp_print_ip(ip);
        return xdp_stats_record_action(ctx, action);
        }
        }
    return XDP_PASS;
}

SEC("xdp_drop_HTTPS")
int  xdp_drop_HTTPS_func(struct xdp_md *ctx)
{
    const int l3_off = ETH_HLEN;                       // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr);  // TCP header offset
    const int l7_off = l4_off + sizeof(struct tcphdr); // L7 (e.g. HTTP)
    //const int l6_off = l4_off + sizeof(struct udphdr);	
	__u32 action;
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    
    
    if (data_end < data + l7_off){
        return XDP_PASS;
}
    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP)){
       return XDP_PASS;
}
    struct iphdr *ip = (struct iphdr *)(data + l3_off);
    if (ip->protocol != IPPROTO_TCP){
        return XDP_PASS;
        }
        if(ip->protocol == IPPROTO_TCP){    
    struct tcphdr *tcp = (struct tcphdr *)(data + l4_off);
    if (ntohs(tcp->dest) == 443){
        action =XDP_DROP;
        xdp_print_ip(ip);
        return xdp_stats_record_action(ctx, action);
        }
        }
    return XDP_PASS;
}


SEC("xdp_drop_port_range")
int  xdp_drop_port_range_func(struct xdp_md *ctx)
{
    const int l3_off = ETH_HLEN;                       // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr);  // TCP header offset
    const int l7_off = l4_off + sizeof(struct tcphdr); // L7 (e.g. HTTP)	
	__u32 action;
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    
    
    if (data_end < data + l7_off){
        return XDP_PASS;
}
    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP)){
       return XDP_PASS;
}
    struct iphdr *ip = (struct iphdr *)(data + l3_off);
    if (ip->protocol != IPPROTO_TCP){
        return XDP_PASS;
        }
        if(ip->protocol == IPPROTO_TCP){    
    struct tcphdr *tcp = (struct tcphdr *)(data + l4_off);
    if (ntohs(tcp->dest) > badportl &&  ntohs(tcp->dest) < badporth){
        action =XDP_DROP;
        xdp_print_ip(ip);
        xdp_print_port(tcp);
        return xdp_stats_record_action(ctx, action);
        }        
        }
        return XDP_PASS;
        }

SEC("xdp_drop_all")
int  xdp_drop_all_func(struct xdp_md *ctx)
{
	__u32 action = XDP_DROP;
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass_all")
int  xdp_pass_all_func(struct xdp_md *ctx)
{
	__u32 action = XDP_PASS;
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_drop_udp")
int  xdp_drop_udp_func(struct xdp_md *ctx)
{
    const int l3_off = ETH_HLEN;                      
    const int l4_off = l3_off + sizeof(struct iphdr);  
    const int l7_off = l4_off + sizeof(struct tcphdr); 
	__u32 action;
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    if (data_end < data + l7_off){
        return XDP_PASS;
}
    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP)){
       return XDP_PASS;
}
    struct iphdr *ip = (struct iphdr *)(data + l3_off);
    if (ip->protocol == IPPROTO_UDP){
        action = XDP_DROP;
        return xdp_stats_record_action(ctx, action);
        }
        
        return XDP_PASS;
	
}

SEC("xdp_drop_badIP")
int  xdp_drop_badIP_func(struct xdp_md *ctx)
{
    const int l3_off = ETH_HLEN;                      
    const int l4_off = l3_off + sizeof(struct iphdr);  
    const int l7_off = l4_off + sizeof(struct tcphdr); 
	__u32 action;
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    if (data_end < data + l7_off){
        return XDP_PASS;
}
    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP)){
       return XDP_PASS;
}
    struct iphdr *ip = (struct iphdr *)(data + l3_off);
	if(badip == ip->saddr){
		action=XDP_DROP;
		return xdp_stats_record_action(ctx, action);	
	}
	    
        
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";


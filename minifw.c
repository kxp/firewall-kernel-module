//Help:
//https://medium.com/@GoldenOak/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e

//#include "string.h"
//#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops telnet_in_hook;
static struct nf_hook_ops telnet_out_hook;

unsigned int telnet_out(void *priv, struct sk_buff *skb,
						const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}

unsigned int telnet_in(void *priv, struct sk_buff *skb,
						const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	int port;
	//unsigned int src_ip ;
	//unsigned int dest_ip ;
	
	iph = ip_hdr(skb);
	tcph = (void *)iph+iph->ihl*4;

	port = tcph->dest;
	//printk(KERN_INFO "Destination port: %d\n", port);

	//char *IPbuffer = inet_ntoa(*((struct in_addr*)  host_entry->h_addr_list[0]);

	//objectives:
	//block telnet protocol between two machines
	//block the access to a certain website

	if (iph->protocol == IPPROTO_TCP && port == htons(23)) {
		printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
		((unsigned char *)&iph->daddr)[0],
		((unsigned char *)&iph->daddr)[1],
		((unsigned char *)&iph->daddr)[2],
		((unsigned char *)&iph->daddr)[3]);

		//extractIpAddress(iph->daddr, ip_add);
		return NF_DROP;
	} 
	if (iph->daddr == (__be32)3232235781) {
		printk(KERN_INFO "Rejected connection to %d.%d.%d.%d\n",
		((unsigned char *)&iph->daddr)[0],
		((unsigned char *)&iph->daddr)[1],
		((unsigned char *)&iph->daddr)[2],
		((unsigned char *)&iph->daddr)[3]);
	}
	
	if (iph->daddr == (__be32)83994816) {
		printk(KERN_INFO "Rejected connection ip inverted to %d.%d.%d.%d\n",
		((unsigned char *)&iph->daddr)[0],
		((unsigned char *)&iph->daddr)[1],
		((unsigned char *)&iph->daddr)[2],
		((unsigned char *)&iph->daddr)[3]);
	}

	//struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	//src_ip = (unsigned int)iph->saddr;
	//dest_ip = (unsigned int)iph->daddr;
	//printk(KERN_INFO "Received packet from source address: %d\n",iph->daddr);	
	printk(KERN_INFO "Accepted packet to %d.%d.%d.%d\n",
		((unsigned char *)&iph->saddr)[0],
		((unsigned char *)&iph->saddr)[1],
		((unsigned char *)&iph->saddr)[2],
		((unsigned char *)&iph->saddr)[3]);

	return NF_ACCEPT;
}

int setup_out_rules(void){

	telnet_in_hook.hook = telnet_out; 
	telnet_in_hook.hooknum =  NF_INET_POST_ROUTING;
	telnet_in_hook.pf = PF_INET;
	telnet_in_hook.priority = NF_IP_PRI_FIRST;

	printk(KERN_INFO "Telnet out rules ptr: %p.\n", &telnet_out_hook );
	// Register the hook.
	nf_register_net_hook(&init_net, &telnet_out_hook );
	return 0;
}


int setup_in_rules(void) {

	telnet_in_hook.hook = telnet_in; 
	telnet_in_hook.hooknum =  NF_INET_PRE_ROUTING;
	telnet_in_hook.pf = PF_INET;
	telnet_in_hook.priority = NF_IP_PRI_FIRST;

	printk(KERN_INFO "Telnet in rules ptr: %p.\n", &telnet_in_hook );
	// Register the hook.
	nf_register_net_hook(&init_net, &telnet_in_hook );
	return 0;
}


void removeFilter(void) {
	printk(KERN_INFO "Telnet remove hook addr:%p.\n", &telnet_in_hook);
	
	if (&telnet_in_hook.hook != NULL) {
		nf_unregister_net_hook( &init_net, &telnet_in_hook );
	}
	if (&telnet_out_hook.hook != NULL) {
		nf_unregister_net_hook( &init_net, &telnet_out_hook );
	}
 	

	printk(KERN_INFO "Telnet filter pos removal.\n");
}


//module_init(setUpFilter);
module_exit(removeFilter);
MODULE_LICENSE("GPL");


int init_module(void)
{
	printk(KERN_INFO "starting a Telnet filter init.\n");
	setup_in_rules();
	//setup_out_rules();

	return 0;
}

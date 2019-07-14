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
						const struct nf_hook_state *state) {

	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);
	tcph = (void *)iph+iph->ihl*4;
	
	//ip address of the destination in as integer.
	if (iph->daddr == (__be32)83994816) {//192.168.1.5
		printk(KERN_INFO "Rejected connection to IP (inverted):%d.%d.%d.%d\n",
		((unsigned char *)&iph->daddr)[0],
		((unsigned char *)&iph->daddr)[1],
		((unsigned char *)&iph->daddr)[2],
		((unsigned char *)&iph->daddr)[3]);
		return NF_DROP;
	}

	return NF_ACCEPT;
}

unsigned int telnet_in(void *priv, struct sk_buff *skb,
						const struct nf_hook_state *state) {

	struct iphdr *iph;
	struct tcphdr *tcph;
	int port;

	iph = ip_hdr(skb);
	tcph = (void *)iph+iph->ihl*4;
	port = tcph->dest;
	
	//TCP packet and port 23
	if (iph->protocol == IPPROTO_TCP && port == htons(23)) {
		printk(KERN_INFO "Dropping packet on port 23(telnet) from: %d.%d.%d.%d\n",
		((unsigned char *)&iph->saddr)[0],
		((unsigned char *)&iph->saddr)[1],
		((unsigned char *)&iph->saddr)[2],
		((unsigned char *)&iph->saddr)[3]);

		return NF_DROP;
	} 

	// printk(KERN_INFO "Accepted packet to %d.%d.%d.%d\n",
	// 	((unsigned char *)&iph->saddr)[0],
	// 	((unsigned char *)&iph->saddr)[1],
	// 	((unsigned char *)&iph->saddr)[2],
	// 	((unsigned char *)&iph->saddr)[3]);

	return NF_ACCEPT;
}

int setup_out_rules(void){

	//function call that is called when a packet matching this conditions passthrough netfilter.
	telnet_out_hook.hook = telnet_out; 
	//set the condition os post route. handles the packets that exiting the machine
	telnet_out_hook.hooknum =  NF_INET_POST_ROUTING;
	//IP protocol
	telnet_out_hook.pf = PF_INET;
	//higher priority
	telnet_out_hook.priority = NF_IP_PRI_FIRST;

	// Register the hook.
	nf_register_net_hook(&init_net, &telnet_out_hook );
	printk(KERN_INFO "Telnet out rules ptr: %p.\n", &telnet_out_hook );

	return 0;
}


int setup_in_rules(void) {

	telnet_in_hook.hook = telnet_in; 
	//set the condition os pre route. handles the packets that are entiring the machine
	telnet_in_hook.hooknum =  NF_INET_PRE_ROUTING;
	telnet_in_hook.pf = PF_INET;
	telnet_in_hook.priority = NF_IP_PRI_FIRST;

	// Register the hook.
	nf_register_net_hook(&init_net, &telnet_in_hook );
	printk(KERN_INFO "Telnet in rules ptr: %p.\n", &telnet_in_hook );

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


//module_init(setUpFilter);	printk(KERN_INFO "Telnet in rules ptr: %p.\n", &telnet_in_hook );

module_exit(removeFilter);
MODULE_LICENSE("GPL");


int init_module(void)
{
	printk(KERN_INFO "starting a custom filter.\n");
	setup_in_rules();
	setup_out_rules();

	return 0;
}

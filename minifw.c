#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>


struct minifw_s{
	void *this;
	struct nf_hook_ops *telnetFilterHook;
};


//static struct nf_hook_ops telnetFilterHook;
static struct minifw_s this;


unsigned int telnetFilter(void *priv, struct sk_buff *skb,
						const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	int port;
	unsigned int src_ip ;
	unsigned int dest_ip ;
	
	
	iph = ip_hdr(skb);
	tcph = (void *)iph+iph->ihl*4;

	port = tcph->dest;
	printk(KERN_INFO "packet port%d\n", port);


	if (iph->protocol == IPPROTO_TCP && port == htons(23)) {
		printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
		((unsigned char *)&iph->daddr)[0],
		((unsigned char *)&iph->daddr)[1],
		((unsigned char *)&iph->daddr)[2],
		((unsigned char *)&iph->daddr)[3]);
		return NF_DROP;
	} 
	
	//struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	src_ip = (unsigned int)iph->saddr;
	dest_ip = (unsigned int)iph->daddr;
	//printk(KERN_DEBUG "Received packet from source address: %pI4\n",src_ip);
	//printk(KERN_DEBUG "A packet has a destination address of: %d.%d.%d.%d!\n",NIPQUAD(dest_ip));
	
	/* else {
		return NF_ACCEPT;
	}*/
	return NF_ACCEPT;
}


int setUpFilter(void) {
	//struct minifw_s this;
	struct nf_hook_ops local_telnetFilter;

	printk(KERN_INFO "starting a Telnet filter init.\n");

	local_telnetFilter.hook = telnetFilter; 
	local_telnetFilter.hooknum =  NF_INET_LOCAL_IN;
	local_telnetFilter.pf = PF_INET;
	local_telnetFilter.priority = NF_IP_PRI_FIRST;

	printk(KERN_INFO "Registering a Telnet filter.\n");

	this.telnetFilterHook = &local_telnetFilter;

	printk(KERN_INFO "Telnet init this add: %p.\n",(void*) &this );
	printk(KERN_INFO "Telnet init hook addr:%p.\n", this.telnetFilterHook);

	// Register the hook.
	nf_register_net_hook((void*)&this, this.telnetFilterHook );
	return 0;
}

void removeFilter(void) {
	printk(KERN_INFO "Telnet filter is being removed.\n");
	printk(KERN_INFO "Telnet remove this add: %p.\n",(void*) &this );
	printk(KERN_INFO "Telnet remove hook addr:%p.\n", this.telnetFilterHook);

	nf_unregister_net_hook((void*) &this, this.telnetFilterHook );

	printk(KERN_INFO "Telnet filter pos removal.\n");

}



module_init(setUpFilter);
module_exit(removeFilter);
MODULE_LICENSE("GPL");


// not used anymore
/* 
int init_module(void)
{
	printk(KERN_INFO "Hello world f63ec4fbba82 !\n"); 
	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "Goodbye world f63ec4fbba82 !\n");
}
 */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>


struct minifw_s{
	void *this;
};


static struct nf_hook_ops telnetFilterHook;

unsigned int telnetFilter(void *priv, struct sk_buff *skb,
						const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphpdr *tcph;
	int port;

	iph = ip_hdr(skb);
	tcph = (void *)iph+iph->ihl*4;

	port = tcph->dest;
	printk(KERN_INFO "packert port%d\n", port);


	if (iph->protocol == IPPROTO_TCP && port == htons(23)) {
		printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
		((unsigned char *)&iph->daddr)[0],
		((unsigned char *)&iph->daddr)[1],
		((unsigned char *)&iph->daddr)[2],
		((unsigned char *)&iph->daddr)[3]);
		return NF_DROP;
	} else {
		return NF_ACCEPT;
	}
}


int setUpFilter(void) {
	printk(KERN_INFO "Registering a Telnet filter.\n");

	telnetFilterHook.hook = telnetFilter; 
	telnetFilterHook.hooknum = NF_INET_POST_ROUTING;
	telnetFilterHook.pf = PF_INET;
	telnetFilterHook.priority = NF_IP_PRI_FIRST;

	// Register the hook.
	nf_register_net_hook(NULL, &telnetFilterHook);
	return 0;
}

void removeFilter(void) {
        printk(KERN_INFO "Telnet filter is being removed.\n");
        nf_unregister_net_hook(NULL, &telnetFilterHook);
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


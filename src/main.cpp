#include <Arduino.h>

#include "tcpip_adapter.h"
#include "lwip/ip_addr.h"
#include "lwip/dhcp.h"

#include <netif/etharp.h>
#include <mchdrv.h>
#include <enc28j60.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_eth.h"
#include "esp_event.h"

#include <netdb.h>
#include "freertos/event_groups.h"

static struct netif mchdrv_netif;
static enc_device_t mchdrv_hw;
tcpip_adapter_ip_info_t eth_ip;

static void dhcpc_cb(struct netif *netif) {
    printf("DHCP callback\n");
    if ( !ip4_addr_cmp(ip_2_ip4(&netif->ip_addr), IP4_ADDR_ANY) ) {
        //check whether IP is changed
        if ( !ip4_addr_cmp(ip_2_ip4(&netif->ip_addr), &eth_ip.ip) ||
                !ip4_addr_cmp(ip_2_ip4(&netif->netmask), &eth_ip.netmask) ||
                !ip4_addr_cmp(ip_2_ip4(&netif->gw), &eth_ip.gw) ) {

            ip4_addr_set(&eth_ip.ip, ip_2_ip4(&netif->ip_addr));
            ip4_addr_set(&eth_ip.netmask, ip_2_ip4(&netif->netmask));
            ip4_addr_set(&eth_ip.gw, ip_2_ip4(&netif->gw));
	        printf("SYSTEM_EVENT_ETH_GOTIP, ip:" IPSTR ", mask:" IPSTR ", gw:" IPSTR,
	            IP2STR(&eth_ip.ip),
	            IP2STR(&eth_ip.netmask),
	            IP2STR(&eth_ip.gw));
            //notify event
			system_event_t evt;
            evt.event_id = SYSTEM_EVENT_ETH_GOT_IP;
            memcpy(&evt.event_info.got_ip.ip_info, &eth_ip, sizeof(tcpip_adapter_ip_info_t));
			esp_event_send(&evt);
			printf("Set default\n");
			netif_set_default(&mchdrv_netif);

		    struct hostent *hp;
			struct ip4_addr *ip4_addr;
	        hp = gethostbyname((const char *)"google.com");

	        if (hp == NULL) {
	            printf("ERROR: DNS lookup failed\n");
	        } else {
				ip4_addr = (struct ip4_addr *)hp->h_addr;
				printf("DNS lookup succeeded. IP=%s\n", inet_ntoa(*ip4_addr));
			}
        } else {
            printf("NOTICE: IP unchanged\n");
        }
    }
    return;
}

static esp_err_t eth_event_handler(void *ctx, system_event_t *event) {
	printf("%d", event->event_id);
    switch(event->event_id) {
    case SYSTEM_EVENT_ETH_START:
        //set eth hostname here
        tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_ETH, "esp32-eth");
		printf("set hostname\n");
        break;
    case SYSTEM_EVENT_ETH_CONNECTED:
        //ethernet connected (if manual IP)
        break;
    case SYSTEM_EVENT_ETH_GOT_IP:
		printf("Got IP\n");
        break;
    case SYSTEM_EVENT_ETH_DISCONNECTED:
        //disconnected
		printf("ETH disconnected\n");
        break;
    default:
        break;
    }
    return ESP_OK;
}

void mch_net_init(void) {
	uint8_t mymac[6] = { 0x00,0x04,0xA3,0x2D,0x30,0x31 };
    ESP_ERROR_CHECK( esp_event_loop_init(eth_event_handler, NULL) );

	// tcpip_adapter_start
	mchdrv_netif.hwaddr_len = 6;
	mchdrv_netif.name[0] = (const char)'e';
	mchdrv_netif.name[1] = (const char)'t';
	memcpy(mchdrv_netif.hwaddr, mymac, 6);

    ip4_addr_set_zero(&eth_ip.ip);
    ip4_addr_set_zero(&eth_ip.gw);
    ip4_addr_set_zero(&eth_ip.netmask);

    // Add our netif to LWIP (netif_add calls our driver initialization function)
    if (netif_add(&mchdrv_netif, &eth_ip.ip, &eth_ip.netmask, &eth_ip.gw, &mchdrv_hw, mchdrv_init, ethernet_input) == NULL) {
		  LWIP_ASSERT("mch_net_init: netif_add (mchdrv_init) failed\n", 0);
    }

    netif_set_default(&mchdrv_netif);
    netif_set_up(&mchdrv_netif);

    if (dhcp_start(&mchdrv_netif) != ERR_OK) {
        printf("ERROR: DHCP client start failed\n");
        return;
    }

    dhcp_set_cb(&mchdrv_netif, dhcpc_cb);
	printf("Net init finished\n");
}

void mch_net_poll(void) {
    mchdrv_poll(&mchdrv_netif);
}

void setup(void) {
	mch_net_init();
}

void loop() {
	mch_net_poll();
}

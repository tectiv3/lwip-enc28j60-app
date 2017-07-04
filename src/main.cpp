#include <stdio.h>

#include "mgos_http_server.h"
#include "mongoose/mongoose.h"
#include "fw/src/mgos_app.h"
#include "fw/src/mgos_mongoose.h"
#include "fw/src/mgos.h"
#include "fw/src/mgos_init.h"
#include "fw/src/mgos_timers.h"

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

#include "common/cs_dbg.h"
#include "common/platform.h"
#include "frozen/frozen.h"


static struct netif mchdrv_netif;
static enc_device_t mchdrv_hw;
tcpip_adapter_ip_info_t eth_ip;

struct mg_connection *conn = NULL;

static mgos_timer_id s_loop_timer;

static void handle_conn(struct mg_connection *nc, int ev, void *ev_data, void *user_data) {
	printf("HC Event: %d", ev);
	switch (ev) {
		case MG_EV_CONNECT:
			if (*(int *) ev_data != 0) {
				fprintf("connect() failed: %s\n", strerror(*(int *) ev_data));
			}
			break;
		case MG_EV_HTTP_REPLY: {
			nc->flags |= MG_F_CLOSE_IMMEDIATELY;
			break;
		}
		case MG_EV_CLOSE: {
			conn = NULL;
			break;
		}
	}
	(void) ev_data;
	(void) user_data;
}

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

			char *eh = NULL, *pdata = NULL;
			conn = mg_connect_http(mgos_get_mgr(), handle_conn, NULL, "http://google.com", eh, pdata);
		    free(eh);
		    free(pdata);
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

    // do we need to initialize LWIP here? or is it already initialized in mg core?
    // lwip_init();
    // uint8_t mac[6];
    // esp_eth_get_mac(mac);
    // printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // tcpip_adapter_init();
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

void loop_cb(void *arg) {
	mch_net_poll();
	(void) arg;
}

static void ctl_handler(struct mg_connection *c, int ev, void *p, void *user_data) {
  if (ev == MG_EV_HTTP_REQUEST) {
    struct http_message *hm = (struct http_message *) p;
    struct mg_str *s = hm->body.len > 0 ? &hm->body : &hm->query_string;

    int pin, state, status = -1;
    if (json_scanf(s->p, s->len, "{pin: %d, state: %d}", &pin, &state) == 2) {
      mgos_gpio_set_mode(pin, MGOS_GPIO_MODE_OUTPUT);
      mgos_gpio_write(pin, state);
      status = 0;
    }
    mg_printf(c, "HTTP/1.0 200 OK\n\n{\"status\": %d}\n", status);
    c->flags |= MG_F_SEND_AND_CLOSE;
    LOG(LL_INFO, ("Got: [%.*s]", (int) s->len, s->p));
  }
  (void) user_data;
}

enum mgos_app_init_result mgos_app_init(void) {
	mch_net_init();
    // mgos_register_http_endpoint("/ctl", ctl_handler, NULL);
	s_loop_timer = mgos_set_timer(0, true /* repeat */, loop_cb, NULL);
	return MGOS_APP_INIT_SUCCESS;
}

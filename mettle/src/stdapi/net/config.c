/**
 * Copyright 2015 Rapid7
 * @brief Network Config API
 * @file config.c
 */

#include <unistd.h>

#include <dnet.h>
#include <mettle.h>
#include <sigar.h>

#include "log.h"
#include "tlv.h"
#include "utils.h"

static char * flags2string(u_short flags)
{
    static char buf[256];

    buf[0] = '\0';

    if (flags & INTF_FLAG_UP)
        strlcat(buf, ",UP", sizeof(buf));
    if (flags & INTF_FLAG_LOOPBACK)
        strlcat(buf, ",LOOPBACK", sizeof(buf));
    if (flags & INTF_FLAG_POINTOPOINT)
        strlcat(buf, ",POINTOPOINT", sizeof(buf));
    if (flags & INTF_FLAG_NOARP)
        strlcat(buf, ",NOARP", sizeof(buf));
    if (flags & INTF_FLAG_BROADCAST)
        strlcat(buf, ",BROADCAST", sizeof(buf));
    if (flags & INTF_FLAG_MULTICAST)
        strlcat(buf, ",MULTICAST", sizeof(buf));

    if (buf[0] != '\0')
        return (buf + 1);

    return buf;
}

static void log_addr(const char *name, const struct addr *a)
{
	char buf[128];
	addr_ntop(a, buf, 128);
	log_info("%s: %s", name, buf);
}

static int add_intf_info(const struct intf_entry *entry, void *arg)
{
	struct tlv_packet **parent = arg;
	struct tlv_packet *p = tlv_packet_new(TLV_TYPE_NETWORK_INTERFACE, 0);

	p = tlv_packet_add_str(p, TLV_TYPE_MAC_NAME, entry->intf_name);
	p = tlv_packet_add_u32(p, TLV_TYPE_INTERFACE_MTU, entry->intf_mtu);
	p = tlv_packet_add_u32(p, TLV_TYPE_INTERFACE_INDEX, entry->intf_index);
	p = tlv_packet_add_str(p, TLV_TYPE_INTERFACE_FLAGS,
			flags2string(entry->intf_flags));
	p = tlv_packet_add_addr(p, TLV_TYPE_MAC_ADDRESS, 0, 0,
			&entry->intf_link_addr);

	/*
	 * Only emit address entries if the interface has an address
	 */
	if (entry->intf_addr.addr_type != ADDR_TYPE_NONE) {
		p = tlv_packet_add_addr(p, TLV_TYPE_IP, TLV_TYPE_NETMASK,
				 entry->intf_index, &entry->intf_addr);
		log_addr(entry->intf_name, &entry->intf_addr);

		for (int i = 0; i < entry->intf_alias_num; i++) {
			p = tlv_packet_add_addr(p, TLV_TYPE_IP, TLV_TYPE_NETMASK,
					entry->intf_index, &entry->intf_alias_addrs[i]);
			log_addr(entry->intf_name, &entry->intf_alias_addrs[i]);
		}
	}

	*parent = tlv_packet_add_child(*parent, p);

	return 0;
}

struct tlv_packet *net_config_get_interfaces(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	intf_t *i = intf_open();
	intf_loop(i, add_intf_info, &p);
	intf_close(i);
	return p;
}

static bool is_link_local_route(const struct addr *a)
{
	return a->addr_type == ADDR_TYPE_IP6 &&
		a->addr_ip6.data[0] == 0xfe &&
		a->addr_ip6.data[1] == 0x80;
}

static bool is_autoconf_route(const struct addr *a, uint32_t metric)
{
	return a->addr_type == ADDR_TYPE_IP6 && metric == 0;
}

static int add_route_info(const struct route_entry *entry, void *arg)
{
	if (entry->metric < 256 &&
			!is_autoconf_route(&entry->route_dst, entry->metric) &&
			!is_link_local_route(&entry->route_dst)) {
		struct tlv_packet **parent = arg;
		struct tlv_packet *p = tlv_packet_new(TLV_TYPE_NETWORK_ROUTE, 0);
		p = tlv_packet_add_addr(p, TLV_TYPE_SUBNET, TLV_TYPE_NETMASK, 0, &entry->route_dst);
		p = tlv_packet_add_addr(p, TLV_TYPE_GATEWAY, 0, 0, &entry->route_gw);
		p = tlv_packet_add_u32(p, TLV_TYPE_ROUTE_METRIC, entry->metric);
		p = tlv_packet_add_str(p, TLV_TYPE_STRING, entry->intf_name);
		*parent = tlv_packet_add_child(*parent, p);
	}
	return 0;
}

struct tlv_packet *net_config_get_routes(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	route_t *r = route_open();
	route_loop(r, add_route_info, &p);
	route_close(r);
	return p;
}

static int add_arp_info(const struct arp_entry *entry, void *arg)
{
	struct tlv_packet **parent = arg;
	struct tlv_packet *p = tlv_packet_new(TLV_TYPE_ARP_ENTRY, 0);
	p = tlv_packet_add_addr(p, TLV_TYPE_IP, 0, 0, &entry->arp_pa);
	p = tlv_packet_add_addr(p, TLV_TYPE_MAC_ADDRESS, 0, 0, &entry->arp_ha);

	intf_t *intf = NULL;
	if ((intf = intf_open()) != NULL) {
		struct intf_entry if_entry;
		if_entry.intf_len = sizeof(if_entry);

		struct addr dst;
		memcpy(&dst, &entry->arp_pa, sizeof(dst));

		if (intf_get_dst(intf, &if_entry, &dst) == 0) {
			p = tlv_packet_add_str(p, TLV_TYPE_MAC_NAME, (char*)&if_entry.intf_name);
		}
		intf_close(intf);
	}

	*parent = tlv_packet_add_child(*parent, p);
	return 0;
}

struct tlv_packet *net_config_get_arp_table(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	arp_t *a = arp_open();
	arp_loop(a, add_arp_info, &p);
	arp_close(a);
	return p;
}

typedef enum {
	UPDATE_ROUTE_ADD,
	UPDATE_ROUTE_REMOVE
} update_route_action_t;

static
int update_route(struct tlv_packet *p, update_route_action_t action)
{
	int ret_val = TLV_RESULT_SUCCESS;
	const char *subnet_str = tlv_packet_get_str(p, TLV_TYPE_SUBNET_STRING);
	const char *netmask_str = tlv_packet_get_str(p, TLV_TYPE_NETMASK_STRING);
	const char *gateway_str = tlv_packet_get_str(p, TLV_TYPE_GATEWAY_STRING);

	route_t *r = route_open();
	if (!r) {
		ret_val = TLV_RESULT_FAILURE;
		goto done;
	}

	struct route_entry entry;
	memset(&entry, 0, sizeof(entry));
	if (addr_pton(subnet_str, &entry.route_dst)) {
		ret_val = TLV_RESULT_EINVAL;
		goto done;
	}
	if (netmask_str && strlen(netmask_str)) {
		if (entry.route_dst.addr_type == ADDR_TYPE_IP) {
			ip_addr_t mask;
			if (ip_pton(netmask_str, &mask) == 0) {
				addr_mtob(&mask, sizeof(mask), &entry.route_dst.addr_bits);
			}
		} else if (entry.route_dst.addr_type == ADDR_TYPE_IP6) {
			ip6_addr_t mask;
			if (ip6_pton(netmask_str, &mask) == 0) {
				addr_mtob(&mask, sizeof(mask), &entry.route_dst.addr_bits);
			}
		}
	}
	if (addr_pton(gateway_str, &entry.route_gw)) {
		ret_val = TLV_RESULT_EINVAL;
		goto done;
	}

	if (action == UPDATE_ROUTE_ADD) {
		if (route_add(r, &entry) != 0) {
			ret_val = TLV_RESULT_FAILURE;
		}
	} else if (action == UPDATE_ROUTE_REMOVE) {
		if (route_delete(r, &entry) != 0) {
			ret_val = TLV_RESULT_FAILURE;
		}
	}

done:
	route_close(r);
	return ret_val;
}

struct tlv_packet *net_config_add_route(struct tlv_handler_ctx *ctx)
{
	return tlv_packet_response_result(ctx, update_route(ctx->req, UPDATE_ROUTE_ADD));
}

struct tlv_packet *net_config_remove_route(struct tlv_handler_ctx *ctx)
{
	return tlv_packet_response_result(ctx, update_route(ctx->req, UPDATE_ROUTE_REMOVE));
}

struct tlv_packet *net_config_get_proxy(struct tlv_handler_ctx *ctx)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);

	char *proxy = getenv("http_proxy");
	if (proxy) {
		p = tlv_packet_add_str(p, TLV_TYPE_PROXY_CFG_PROXY, proxy);
	}

	char *proxy_bypass = getenv("no_proxy");
	if (proxy_bypass) {
		p = tlv_packet_add_str(p, TLV_TYPE_PROXY_CFG_PROXYBYPASS, proxy_bypass);
	}

	return p;
}

const char * const tcp_connection_states[] = {
   "", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT",
   "CLOSED", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING", "UNKNOWN"
};
const char * const udp_connection_states[] = {
   "", "ESTABLISHED", "", "", "", "", "", "", "", "", "", "", "UNKNOWN"
};

static
void get_netstat_async(struct eio_req *req)
{
	struct tlv_handler_ctx *ctx = req->data;
	sigar_t *sigar = mettle_get_sigar(ctx->arg);
	struct tlv_packet *p_response = tlv_packet_response(ctx);
	int ret_val = TLV_RESULT_SUCCESS;

	sigar_net_connection_list_t connections;
	int status = sigar_net_connection_list_get(sigar, &connections,
			SIGAR_NETCONN_TCP | SIGAR_NETCONN_UDP | \
			SIGAR_NETCONN_CLIENT | SIGAR_NETCONN_SERVER);
	if (status != SIGAR_OK) {
		log_debug("netstat error: %d (%s)",
				status, sigar_strerror(sigar, status));
		ret_val = TLV_RESULT_FAILURE;
		goto done;
	}

	for (int i = 0; i < connections.number; i++) {
		sigar_net_connection_t *connection = &connections.data[i];
		struct addr local_addr = { 0 };
		struct addr remote_addr = { 0 };
		struct tlv_packet *p = tlv_packet_new(TLV_TYPE_NETSTAT_ENTRY, 0);

		if (connection->local_address.family == SIGAR_AF_INET) {
			local_addr.addr_type = remote_addr.addr_type = ADDR_TYPE_IP;
			local_addr.addr_ip = connection->local_address.addr.in;
			remote_addr.addr_ip = connection->remote_address.addr.in;
		} else if (connection->local_address.family == SIGAR_AF_INET6) {
			local_addr.addr_type = remote_addr.addr_type = ADDR_TYPE_IP6;
			memcpy(&local_addr.addr_ip6, &connection->local_address.addr.in6,
					sizeof(local_addr.addr_ip6));
			memcpy(&remote_addr.addr_ip6, &connection->remote_address.addr.in6,
					sizeof(remote_addr.addr_ip6));
		}

		if (local_addr.addr_type) {
			p = tlv_packet_add_addr(p, TLV_TYPE_LOCAL_HOST_RAW, 0, 0, &local_addr);
			p = tlv_packet_add_addr(p, TLV_TYPE_PEER_HOST_RAW, 0, 0, &remote_addr);
		}

		p = tlv_packet_add_u32(p, TLV_TYPE_LOCAL_PORT, connection->local_port);
		p = tlv_packet_add_u32(p, TLV_TYPE_PEER_PORT, connection->remote_port);

		if (connection->type == SIGAR_NETCONN_TCP) {
			p = tlv_packet_add_str(p, TLV_TYPE_MAC_NAME, "tcp");
			if (connection->state && connection->state < COUNT_OF(tcp_connection_states)) {
				p = tlv_packet_add_str(p, TLV_TYPE_SUBNET_STRING,
						tcp_connection_states[connection->state]);
			}
		} else if (connection->type == SIGAR_NETCONN_UDP) {
			p = tlv_packet_add_str(p, TLV_TYPE_MAC_NAME, "udp");
			if (connection->state && connection->state < COUNT_OF(udp_connection_states)) {
				p = tlv_packet_add_str(p, TLV_TYPE_SUBNET_STRING,
						udp_connection_states[connection->state]);
			}
		}
		p = tlv_packet_add_u32(p, TLV_TYPE_PID, connection->uid);

		p_response = tlv_packet_add_child(p_response, p);
	}

	sigar_net_connection_list_destroy(sigar, &connections);
done:
	tlv_packet_add_result(p_response, ret_val);
	tlv_dispatcher_enqueue_response(ctx->td, p_response);
	tlv_handler_ctx_free(ctx);
}

struct tlv_packet *net_config_get_netstat(struct tlv_handler_ctx *ctx)
{
	struct mettle *m = ctx->arg;
	eio_custom(get_netstat_async, 0, NULL, ctx);
	return NULL;
}

void net_config_register_handlers(struct mettle *m)
{
	struct tlv_dispatcher *td = mettle_get_tlv_dispatcher(m);

	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_NET_CONFIG_GET_INTERFACES, net_config_get_interfaces, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_NET_CONFIG_GET_ROUTES, net_config_get_routes, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_NET_CONFIG_ADD_ROUTE, net_config_add_route, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_NET_CONFIG_REMOVE_ROUTE, net_config_remove_route, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_NET_CONFIG_GET_ARP_TABLE, net_config_get_arp_table, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_NET_CONFIG_GET_PROXY, net_config_get_proxy, m);
	tlv_dispatcher_add_handler(td, COMMAND_ID_STDAPI_NET_CONFIG_GET_NETSTAT, net_config_get_netstat, m);
}

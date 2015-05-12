/**
 * Copyright 2015 Rapid7
 * @brief Core API calls
 * @file tlv_stdapi.c
 */

#include <unistd.h>

#include <dnet.h>
#include <mettle.h>
#include <sigar.h>

#include "log.h"
#include "tlv.h"

struct tlv_packet *sys_config_getuid(struct tlv_handler_ctx *ctx, void *arg)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	return tlv_packet_add_printf(p, TLV_TYPE_USER_NAME,
			"uid=%d, gid=%d, euid=%d, egid=%d",
			getuid(), geteuid(), getgid(), getegid());
}

struct tlv_packet *sys_config_sysinfo(struct tlv_handler_ctx *ctx, void *arg)
{
	struct mettle *m = arg;
	sigar_sys_info_t sys_info;
	if (sigar_sys_info_get(mettle_get_sigar(m), &sys_info) == -1) {
		return NULL;
	}

	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);

	p = tlv_packet_add_str(p, TLV_TYPE_COMPUTER_NAME, mettle_get_fqdn(m));
	p = tlv_packet_add_printf(p, TLV_TYPE_OS_NAME, "%s (%s %s)",
			sys_info.description, sys_info.name, sys_info.version);
	p = tlv_packet_add_str(p, TLV_TYPE_ARCHITECTURE, sys_info.arch);

	return p;
}

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

static int add_intf_info(const struct intf_entry *entry, void *arg)
{
	struct tlv_packet **parent = arg;
	struct tlv_packet *p = tlv_packet_new(TLV_TYPE_NETWORK_INTERFACE, 0);

	p = tlv_packet_add_str(p, TLV_TYPE_MAC_NAME, entry->intf_name);
	p = tlv_packet_add_u32(p, TLV_TYPE_INTERFACE_MTU, entry->intf_mtu);
	p = tlv_packet_add_u32(p, TLV_TYPE_INTERFACE_MTU, entry->intf_mtu);
	p = tlv_packet_add_str(p, TLV_TYPE_INTERFACE_FLAGS, flags2string(entry->intf_flags));
	p = tlv_packet_add_u32(p, TLV_TYPE_INTERFACE_INDEX, entry->intf_index);
	p = tlv_packet_add_raw(p, TLV_TYPE_MAC_ADDRESS, entry->intf_addr.addr_data8, ETH_ADDR_LEN);
	p = tlv_packet_add_addr(p, TLV_TYPE_IP, TLV_TYPE_NETMASK, &entry->intf_addr);

	for (int i = 0; i < entry->intf_alias_num; i++) {
		p = tlv_packet_add_addr(p, TLV_TYPE_IP, TLV_TYPE_NETMASK,
				&entry->intf_alias_addrs[i]);
	}

	*parent = tlv_packet_add_child(*parent, p, tlv_packet_len(p));
	tlv_packet_free(p);

	return 0;
}

struct tlv_packet *sys_config_get_interfaces(struct tlv_handler_ctx *ctx, void *arg)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	intf_t *i = intf_open();
	intf_loop(i, add_intf_info, &p);
	intf_close(i);
	return p;
}

static int add_route_info(const struct route_entry *entry, void *arg)
{
	struct tlv_packet **parent = arg;
	struct tlv_packet *p = tlv_packet_new(TLV_TYPE_NETWORK_ROUTE, 0);
	p = tlv_packet_add_addr(p, TLV_TYPE_SUBNET, TLV_TYPE_NETMASK, &entry->route_dst);
	p = tlv_packet_add_addr(p, TLV_TYPE_GATEWAY, 0, &entry->route_gw);
	p = tlv_packet_add_u32(p, TLV_TYPE_ROUTE_METRIC, entry->metric);
	p = tlv_packet_add_str(p, TLV_TYPE_STRING, entry->intf_name);
	*parent = tlv_packet_add_child(*parent, p, tlv_packet_len(p));
	tlv_packet_free(p);
	return 0;
}

struct tlv_packet *sys_config_get_routes(struct tlv_handler_ctx *ctx, void *arg)
{
	struct tlv_packet *p = tlv_packet_response_result(ctx, TLV_RESULT_SUCCESS);
	route_t *r = route_open();
	route_loop(r, add_route_info, &p);
	route_close(r);
	return p;
}


void tlv_register_stdapi(struct mettle *m, struct tlv_dispatcher *td)
{
	tlv_dispatcher_add_handler(td, "stdapi_sys_config_getuid", sys_config_getuid, m);
	tlv_dispatcher_add_handler(td, "stdapi_sys_config_sysinfo", sys_config_sysinfo, m);
	tlv_dispatcher_add_handler(td, "stdapi_net_config_get_interfaces", sys_config_get_interfaces, m);
	tlv_dispatcher_add_handler(td, "stdapi_net_config_get_routes", sys_config_get_routes, m);
}

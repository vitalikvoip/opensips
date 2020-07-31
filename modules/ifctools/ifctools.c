/*
 * Options Reply Module
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */

#include "../../sr_module.h"
#include "../../mod_fix.h"
#include "../../str.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_uri.h"
#include "../tm/tm_load.h"
#include "../../pvar.h"
#include "../../resolve.h"

enum helper_type {
	ADDR,
	ADDRPORT
};

static int mod_init(void);
static void mod_destroy(void);
static int pv_get_sendsock_helper(struct sip_msg* msg,  pv_param_t* pvp, pv_value_t* val, enum helper_type);
static int pv_get_sendsock_addr(struct sip_msg* msg,  pv_param_t* pvp, pv_value_t* val);
static int pv_get_sendsock_addrport(struct sip_msg* msg,  pv_param_t* pvp, pv_value_t* val);
static int get_route_f(struct sip_msg* m, char *dst, char* route);
static int fixup_get_route(void **param, int param_no);

static pv_export_t mod_pv[] = {
	{ {"sendsock_addr",     sizeof("sendsock_addr")-1},     PVT_EXTRA, pv_get_sendsock_addr, 0, 0, 0, 0, 0},
	{ {"sendsock_addrport", sizeof("sendsock_addrport")-1}, PVT_EXTRA, pv_get_sendsock_addrport, 0, 0, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static cmd_export_t cmds[] = {
	{"get_route",  (cmd_function)get_route_f, 2, fixup_get_route, 0, REQUEST_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE},
	{0, 0, 0, 0, 0, 0}
};

/*
 * Module description
 */
struct module_exports exports = {
	"ifctools",       /* Module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,            /* Exported functions */
	NULL,            /* Exported async functions */
	NULL,            /* Exported parameters */
	0,               /* exported statistics */
	0,               /* exported MI functions */
	mod_pv,          /* exported pseudo-variables */
	0,			 	 /* exported transformations */
	0,               /* extra processes */
	0,
	mod_init,        /* Initialization function */
	0,               /* Response function */
	mod_destroy,     /* Destroy function */
	0                /* Child init function */
};

/*
 * initialize module
 */
static int mod_init(void) {
	LM_INFO("initializing...\n");

	return 0;
}

static void mod_destroy(void) {
	LM_INFO("destroy...\n");
}

static int pv_get_sendsock_helper(struct sip_msg* msg,  pv_param_t* pvp, pv_value_t* val, enum helper_type type)
{
	struct socket_info *send_sock;
	union sockaddr_union to_su;

	if (msg->first_line.type == SIP_REQUEST) {
		LM_DBG("Processing request to %.*s\n", (GET_NEXT_HOP(msg))->len, (GET_NEXT_HOP(msg))->s);

		send_sock = uri2sock2(msg,GET_NEXT_HOP(msg),&to_su,PROTO_UDP);
		if (!send_sock) {
			LM_ERR("uri2sock failed for uri: %.*s\n", (GET_NEXT_HOP(msg))->len, (GET_NEXT_HOP(msg))->s);
			goto error;
		}
	} else if (msg->first_line.type == SIP_REPLY) {
		LM_DBG("Processing reply\n");

		if ((parse_headers(msg, HDR_VIA2_F, 0) < 0) || !msg->via2 || msg->via2->error != PARSE_OK) {
			goto error;
		}

		if (update_sock_struct_from_via(&to_su,msg,msg->via2) < 0) {
			goto error;
		}

		send_sock = get_send_socket(msg, &to_su, PROTO_UDP);
		if (!send_sock) {
			LM_ERR("get_send_socket() failed\n");
			goto error;
		}
	} else {
		LM_ERR("Unknown msg type: %d\n", msg->first_line.type);
		goto error;
	}

	char *ip;
	unsigned short port;
	get_su_info(&to_su, ip, port);
	LM_DBG("Found sockaddr for destination: %s:%d\n", ip,port);

	static char buf[256];
	int maxlen = sizeof(buf) - 1;
	int len = 0;

	memset(buf,0,sizeof(buf));

	if (type == ADDR)
	{
		len = send_sock->address_str.len;
		len = (len > maxlen) ? maxlen : len;
		memcpy(buf, send_sock->address_str.s, len);
	}
	else
	{
		len = send_sock->address_str.len + send_sock->port_no_str.len + 1;
		len = (len > maxlen) ? maxlen : len;
		memcpy(buf, send_sock->address_str.s, send_sock->address_str.len);
		memcpy(buf + send_sock->address_str.len, ":", 1);
		memcpy(buf + send_sock->address_str.len + 1, send_sock->port_no_str.s, send_sock->port_no_str.len);

	}

	val->rs.s   = buf;
	val->rs.len = len;
	val->flags  = PV_VAL_STR;

	return 0;

error:
	LM_ERR("Couldn't find an outgoing socket\n");
	return -1;
}

static int pv_get_sendsock_addr(struct sip_msg* msg,  pv_param_t* pvp, pv_value_t* val)
{
	return pv_get_sendsock_helper(msg,pvp,val,ADDR);
}

static int pv_get_sendsock_addrport(struct sip_msg* msg,  pv_param_t* pvp, pv_value_t* val)
{
	return pv_get_sendsock_helper(msg,pvp,val,ADDRPORT);
}

static int fixup_get_route(void **param, int param_no)
{
	return fixup_pvar(param);
}

static int get_route_f(struct sip_msg* msg, char *_dst, char* _route)
{
	pv_value_t dst_val,route_val;
	str dst;
	union sockaddr_union dst_su;
	struct socket_info *send_sock;
	struct hostent *he;
	unsigned short port = 5060;
	unsigned short proto = PROTO_UDP;

	if (!_dst || !_route)
		return -1;

	if (pv_get_spec_value(msg, (pv_spec_p)_dst, &dst_val)) {
		LM_ERR("failed to get dst PV value!\n");
		return -1;
	}

	if ((dst_val.flags & PV_VAL_STR) == 0) {
		LM_ERR("dst PV vals is not string\n");
		return -1;
	}

	dst = dst_val.rs;

	he=sip_resolvehost(&dst, &port, &proto, 0, 0);
	if (!he) {
		LM_NOTICE("resolve_host(%.*s) failure\n", dst.len, dst.s);
		return -1;
	}

	hostent2su(&dst_su, he, 0, port);

	send_sock=get_out_socket(&dst_su, PROTO_UDP);
	if (!send_sock) {
		LM_ERR("get_send_socket() failed\n");
	}

	route_val.flags = PV_VAL_STR;
	route_val.rs = send_sock->address_str;

	if (pv_set_value(msg,(pv_spec_p)_route, 0, &route_val) != 0)
	{
		LM_ERR("SET route value failed.\n");
		return -1;
	}

	return 1;
}

/* (C) 2021 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Oliver Smith <osmith@sysmocom.de>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/lienses/>.
 *
 */

#pragma once

#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>
#include <osmocom/mgcp_client/mgcp_client_pool.h>
#include <osmocom/sigtran/sccp_sap.h>

enum bsc_nat_net {
	BSC_NAT_NET_CN = 0,
	BSC_NAT_NET_RAN
};

struct bsc_nat_sccp_inst {
	uint32_t ss7_id;
	struct osmo_ss7_instance *ss7_inst;

	struct osmo_sccp_addr addr; /* OsmoBSCNAT's local address */
	struct osmo_sccp_user *scu;
};

struct bsc_nat {
	struct osmo_fsm_inst *fi;
	struct llist_head subscr_conns; /* list of struct subscr_conn */

	struct {
		struct mgcp_client_pool *pool;
		struct osmo_tdef *tdefs;
	} mgw;

	struct {
		struct bsc_nat_sccp_inst *sccp_inst;
		uint32_t subscr_conn_id_next;
		struct llist_head mscs; /* list of struct msc */
	} cn;

	struct {
		struct bsc_nat_sccp_inst *sccp_inst;
		uint32_t subscr_conn_id_next;
		struct llist_head bscs; /* list of struct bsc */
	} ran;
};

struct bsc_nat *bsc_nat_alloc(void *tall_ctx);
void bsc_nat_free(struct bsc_nat *bsc_nat);

#define bsc_nat_print_addr_cn(addr) bsc_nat_print_addr(BSC_NAT_NET_CN, addr)
#define bsc_nat_print_addr_ran(addr) bsc_nat_print_addr(BSC_NAT_NET_RAN, addr)
const char *bsc_nat_print_addr(enum bsc_nat_net net, struct osmo_sccp_addr *addr);

extern void *tall_bsc_nat_ctx;
extern struct bsc_nat *g_bsc_nat;
extern struct osmo_tdef_group g_bsc_nat_tdef_group[];

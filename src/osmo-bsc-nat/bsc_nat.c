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

#include "config.h"
#include <inttypes.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/bsc_nat/bsc.h>
#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/bsc_nat_fsm.h>
#include <osmocom/bsc_nat/logging.h>
#include <osmocom/bsc_nat/msc.h>
#include <osmocom/bsc_nat/subscr_conn.h>

struct osmo_tdef g_mgw_tdefs[] = {
	{ .T = -2427, .default_val = 5, .desc = "timeout for MGCP response from MGW" },
	{}
};

struct osmo_tdef_group g_bsc_nat_tdef_group[] = {
	{ .name = "mgw", .tdefs = g_mgw_tdefs, .desc = "MGW (Media Gateway) interface" },
	{}
};

struct bsc_nat *bsc_nat_alloc(void *tall_ctx)
{
	struct bsc_nat *bsc_nat;

	bsc_nat = talloc_zero(tall_ctx, struct bsc_nat);
	OSMO_ASSERT(bsc_nat);

	bsc_nat->mgw.pool = mgcp_client_pool_alloc(bsc_nat);
	bsc_nat->mgw.tdefs = g_mgw_tdefs;
	osmo_tdefs_reset(bsc_nat->mgw.tdefs);

	bsc_nat->cn.sccp_inst = talloc_zero(bsc_nat, struct bsc_nat_sccp_inst);
	OSMO_ASSERT(bsc_nat->cn.sccp_inst);
	talloc_set_name_const(bsc_nat->cn.sccp_inst, "struct bsc_nat_sccp_inst (CN)");

	bsc_nat->ran.sccp_inst = talloc_zero(bsc_nat, struct bsc_nat_sccp_inst);
	OSMO_ASSERT(bsc_nat->ran.sccp_inst);
	talloc_set_name_const(bsc_nat->ran.sccp_inst, "struct bsc_nat_sccp_inst (RAN)");

	INIT_LLIST_HEAD(&bsc_nat->subscr_conns);
	INIT_LLIST_HEAD(&bsc_nat->cn.mscs);
	INIT_LLIST_HEAD(&bsc_nat->ran.bscs);

	bsc_nat_fsm_alloc(bsc_nat);

	return bsc_nat;
}

void bsc_nat_free(struct bsc_nat *bsc_nat)
{
	struct subscr_conn *subscr_conn, *s;
	struct msc *msc, *m;
	struct bsc *bsc, *b;

	if (bsc_nat->fi) {
		osmo_fsm_inst_free(bsc_nat->fi);
		bsc_nat->fi = NULL;
	}

	llist_for_each_entry_safe(subscr_conn, s, &bsc_nat->subscr_conns, list) {
		subscr_conn_free(subscr_conn);
	}

	llist_for_each_entry_safe(msc, m, &bsc_nat->cn.mscs, list) {
		msc_free(msc);
	}

	llist_for_each_entry_safe(bsc, b, &bsc_nat->ran.bscs, list) {
		bsc_free(bsc);
	}

	talloc_free(bsc_nat);
}

const char *bsc_nat_print_addr(enum bsc_nat_net net, struct osmo_sccp_addr *addr)
{
	static char buf[25];

	snprintf(buf, sizeof(buf), "PC=%s in %s", osmo_ss7_pointcode_print(NULL, addr->pc),
		 net == BSC_NAT_NET_CN ? "CN" : "RAN");

	return buf;
}

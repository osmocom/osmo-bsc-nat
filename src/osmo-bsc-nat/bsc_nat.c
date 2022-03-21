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
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/bsc_nat_fsm.h>

struct bsc_nat *bsc_nat_alloc(void *tall_ctx)
{
	struct bsc_nat *bsc_nat;

	bsc_nat = talloc_zero(tall_ctx, struct bsc_nat);
	OSMO_ASSERT(bsc_nat);

	bsc_nat->cn = talloc_zero(bsc_nat, struct bsc_nat_sccp_inst);
	OSMO_ASSERT(bsc_nat->cn);
	talloc_set_name_const(bsc_nat->cn, "struct bsc_nat_sccp_inst (CN)");

	bsc_nat->ran = talloc_zero(bsc_nat, struct bsc_nat_sccp_inst);
	OSMO_ASSERT(bsc_nat->ran);
	talloc_set_name_const(bsc_nat->ran, "struct bsc_nat_sccp_inst (RAN)");

	bsc_nat_fsm_alloc(bsc_nat);

	return bsc_nat;
}

void bsc_nat_free(struct bsc_nat *bsc_nat)
{
	if (bsc_nat->fi) {
		osmo_fsm_inst_free(bsc_nat->fi);
		bsc_nat->fi = NULL;
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

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
#include <osmocom/bsc_nat/bsc.h>
#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/logging.h>
#include <osmocom/bsc_nat/subscr_conn.h>

struct bsc *bsc_alloc(struct osmo_sccp_addr *addr)
{
	struct bsc *bsc = talloc_zero(g_bsc_nat, struct bsc);

	OSMO_ASSERT(bsc);
	talloc_set_name(bsc, "BSC(PC=%s)", osmo_ss7_pointcode_print(NULL, addr->pc));

	LOGP(DMAIN, LOGL_DEBUG, "Add %s\n", talloc_get_name(bsc));

	bsc->addr = *addr;

	INIT_LLIST_HEAD(&bsc->list);
	llist_add(&bsc->list, &g_bsc_nat->ran.bscs);

	return bsc;
}

struct bsc *bsc_get_by_pc(uint32_t pointcode)
{
	struct bsc *bsc;

	llist_for_each_entry(bsc, &g_bsc_nat->ran.bscs, list) {
		if (bsc->addr.pc == pointcode)
			return bsc;
	}

	return NULL;
}

void bsc_free_subscr_conn_all(struct bsc *bsc)
{
	struct subscr_conn *subscr_conn;

	llist_for_each_entry(subscr_conn, &g_bsc_nat->subscr_conns, list) {
		if (subscr_conn->ran.bsc == bsc)
			subscr_conn_free(subscr_conn);
	}
}

void bsc_free(struct bsc *bsc)
{
	LOGP(DMAIN, LOGL_DEBUG, "Del %s\n", talloc_get_name(bsc));
	bsc_free_subscr_conn_all(bsc);
	llist_del(&bsc->list);
	talloc_free(bsc);
}

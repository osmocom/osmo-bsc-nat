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
#include <errno.h>
#include <osmocom/bsc_nat/msc.h>
#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/logging.h>

extern struct osmo_fsm msc_fsm;

struct msc *msc_alloc(struct osmo_sccp_addr *addr)
{
	struct msc *msc = talloc_zero(g_bsc_nat, struct msc);

	OSMO_ASSERT(msc);
	talloc_set_name(msc, "MSC(PC=%s)", osmo_ss7_pointcode_print(NULL, addr->pc));

	LOGP(DMAIN, LOGL_DEBUG, "Add %s\n", talloc_get_name(msc));

	msc->addr = *addr;

	INIT_LLIST_HEAD(&msc->list);
	llist_add(&msc->list, &g_bsc_nat->cn.mscs);

	msc->fi = osmo_fsm_inst_alloc(&msc_fsm, msc, msc, LOGL_INFO, NULL);
	OSMO_ASSERT(msc->fi);

	msc_tx_reset(msc);

	return msc;
}

int msc_alloc_from_addr_book(void)
{
	struct osmo_sccp_addr addr;

	/* For now only one MSC is supported */
	if (osmo_sccp_addr_by_name_local(&addr, "msc", g_bsc_nat->cn.sccp_inst->ss7_inst) < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Configuration error, MSC not found in address book\n");
		return -ENOENT;
	}

	msc_alloc(&addr);
	return 0;
}

struct msc *msc_get(void)
{
	/* For now only one MSC is supported */

	OSMO_ASSERT(!llist_empty(&g_bsc_nat->cn.mscs));

	return llist_first_entry(&g_bsc_nat->cn.mscs, struct msc, list);
}

void msc_free(struct msc *msc)
{
	LOGP(DMAIN, LOGL_DEBUG, "Del %s\n", talloc_get_name(msc));
	llist_del(&msc->list);
	osmo_fsm_inst_free(msc->fi);
	talloc_free(msc);
}

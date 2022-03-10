/* (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
#include <osmocom/bsc_nat/bsc.h>
#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/msc.h>
#include <osmocom/bsc_nat/subscr_conn.h>
#include <osmocom/bsc_nat/logging.h>

/* Get the next available id in either CN or RAN. */
int subscr_conn_get_next_id(enum bsc_nat_net net)
{
	uint32_t *id;

	if (net == BSC_NAT_NET_RAN)
		id = &g_bsc_nat->ran.subscr_conn_id_next;
	else
		id = &g_bsc_nat->cn.subscr_conn_id_next;

	for (int i = 0; i < 0xFFFFFF; i++) {
		struct subscr_conn *subscr_conn;
		bool already_used = false;

		*id = (*id + 1) & 0xffffff;

		llist_for_each_entry(subscr_conn, &g_bsc_nat->subscr_conns, list) {
			if ((net == BSC_NAT_NET_RAN && subscr_conn->ran.id == *id)
			    || (net == BSC_NAT_NET_CN && subscr_conn->cn.id == *id)) {
				already_used = true;
				break;
			}
		}

		if (!already_used)
			return *id;
	}
	return -1;
}

struct subscr_conn *subscr_conn_alloc(struct msc *msc, struct bsc *bsc, uint32_t id_cn, uint32_t id_ran)
{
	struct subscr_conn *subscr_conn = talloc_zero(g_bsc_nat, struct subscr_conn);

	OSMO_ASSERT(subscr_conn);
	talloc_set_name(subscr_conn, "SUBSCR-CONN %s:%" PRIu32 " <=> %s:%" PRIu32,
			talloc_get_name(msc), id_cn,
			talloc_get_name(bsc), id_ran);

	LOGP(DMAIN, LOGL_DEBUG, "Add %s\n", talloc_get_name(subscr_conn));

	subscr_conn->cn.id = id_cn;
	subscr_conn->cn.msc = msc;
	subscr_conn->ran.id = id_ran;
	subscr_conn->ran.bsc = bsc;

	INIT_LLIST_HEAD(&subscr_conn->list);
	llist_add(&subscr_conn->list, &g_bsc_nat->subscr_conns);

	return subscr_conn;
}

struct subscr_conn *subscr_conn_get_by_id(uint32_t id, enum bsc_nat_net net)
{
	struct subscr_conn *subscr_conn;

	llist_for_each_entry(subscr_conn, &g_bsc_nat->subscr_conns, list) {
		if ((net == BSC_NAT_NET_RAN && subscr_conn->ran.id == id)
		    || (net == BSC_NAT_NET_CN && subscr_conn->cn.id == id))
			return subscr_conn;
	}

	return NULL;
}

void subscr_conn_free(struct subscr_conn *subscr_conn)
{
	LOGP(DMAIN, LOGL_DEBUG, "Del %s\n", talloc_get_name(subscr_conn));
	llist_del(&subscr_conn->list);
	talloc_free(subscr_conn);
}

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
#include <osmocom/bsc_nat/subscr_conn.h>

extern struct osmo_fsm msc_fsm;

struct msc *msc_alloc(uint16_t id)
{
	struct msc *msc = talloc_zero(g_bsc_nat, struct msc);

	OSMO_ASSERT(msc);
	talloc_set_name(msc, "MSC(ID=%" PRIu16 ")", id);

	LOGP(DMAIN, LOGL_DEBUG, "Add %s\n", talloc_get_name(msc));

	INIT_LLIST_HEAD(&msc->list);
	llist_add(&msc->list, &g_bsc_nat->cn.mscs);

	msc->fi = osmo_fsm_inst_alloc(&msc_fsm, msc, msc, LOGL_INFO, NULL);
	OSMO_ASSERT(msc->fi);

	msc_tx_reset(msc);

	return msc;
}

struct msc *msc_get_by_id(uint16_t id)
{
	struct msc *msc;

	llist_for_each_entry(msc, &g_bsc_nat->cn.mscs, list) {
		if (msc->id == id)
			return msc;
	}

	return NULL;
}

struct msc *msc_get_by_mi(const struct osmo_mobile_identity *mi)
{
	struct msc *msc;
	struct msc *msc_target = NULL;
	struct msc *msc_round_robin_next = NULL;
	struct msc *msc_round_robin_first = NULL;
	uint8_t round_robin_id_next;
	int16_t nri_v = -1;
	bool is_null_nri = false;

#define LOG_NRI(LOGLEVEL, FORMAT, ARGS...) \
	LOGP(DMSC, LOGLEVEL, "%s NRI(%d)=0x%x=%d: " FORMAT, osmo_mobile_identity_to_str_c(OTC_SELECT, mi), \
	     net->nri_bitlen, nri_v, nri_v, ##ARGS)

	/* Extract NRI bits from TMSI, possibly indicating which MSC is
	 * responsible */
	if (mi->type == GSM_MI_TYPE_TMSI) {
		if (osmo_tmsi_nri_v_get(&nri_v, mi->tmsi, net->nri_bitlen)) {
			LOGP(DMSC, LOGL_ERROR, "Unable to retrieve NRI from TMSI, nri_bitlen == %u\n", net->nri_bitlen);
			nri_v = -1;
		} else {
			is_null_nri = osmo_nri_v_matches_ranges(nri_v, net->null_nri_ranges);
			if (is_null_nri)
				LOG_NRI(LOGL_DEBUG, "this is a NULL-NRI\n");
		}
	}

	/* Iterate MSCs to find one that matches the extracted NRI, and the
	 * next round-robin target for the case no NRI match is found. */
	round_robin_id_next = g_bsc_nat->cn.msc_id_next;
	llist_for_each_entry(msc, &g_bsc_nat->mscs, list) {
		bool nri_matches_msc = (nri_v >= 0 && osmo_nri_v_matches_ranges(nri_v, msc->nri_ranges));

		if (!msc_is_connected(msc)) {
			if (nri_matches_msc) {
				LOG_NRI(LOGL_DEBUG, "matches %s, but this MSC is currently not connected\n",
					talloc_get_name(msc));
			}
			continue;
		}

		/* Return MSC if it matches this NRI, with debug logging. */
		if (nri_matches_msc) {
			if (is_null_nri) {
				LOG_NRI(LOGL_DEBUG, "matches %s, but this NRI is also configured as NULL-NRI\n",
					talloc_get_name(msc));
			} else {
				LOG_NRI(LOGL_DEBUG, "matches %s\n", talloc_get_name(msc));
				return msc;
			}
		}

		/* Figure out the next round-robin MSC, same logic as in
		 * osmo-bsc.git bsc_find_msc() (see lenghty comment there). */
		if (!msc->allow_attach)
			continue;
		if (!msc_round_robin_first || msc->id < msc_round_robin_first->id)
			msc_round_robin_first = msc;
		if (msc->id >= round_robin_id_next
		    && (!msc_round_robin_next || msc->id < msc_round_robin_next->id))
			msc_round_robin_next = msc;
	}

	if (nri_v >= 0 && !is_null_nri)
		LOG_NRI(LOGL_DEBUG, "No MSC found for this NRI, doing round-robin\n");

	/* No dedicated MSC found. Choose by round-robin. If
	 * msc_round_robin_next is NULL, there are either no more MSCs at/after
	 * msc_id_next, or none of them are usable -- wrap to the start. */
	msc_target = msc_round_robin_next ? : msc_round_robin_first;
	if (!msc_target)
		return NULL;

	LOGP(DMSC, LOGL_DEBUG, "New subscriber %s: MSC round-robin selects %s\n",
	     osmo_mobile_identity_to_str_c(OTC_SELECT, mi), talloc_get_name(msc_target));

	/* An MSC was picked by round-robin, so update the next id to pick */
	g_bsc_nat->cn.msc_id_next = msc_target->id + 1;
	return msc_target;
#undef LOG_NRI
}

void msc_free_subscr_conn_all(struct msc *msc)
{
	struct subscr_conn *subscr_conn;

	llist_for_each_entry(subscr_conn, &g_bsc_nat->subscr_conns, list) {
		if (subscr_conn->cn.msc == msc)
			subscr_conn_free(subscr_conn);
	}
}

void msc_free(struct msc *msc)
{
	LOGP(DMAIN, LOGL_DEBUG, "Del %s\n", talloc_get_name(msc));
	msc_free_subscr_conn_all(msc);
	llist_del(&msc->list);
	osmo_fsm_inst_free(msc->fi);
	talloc_free(msc);
}

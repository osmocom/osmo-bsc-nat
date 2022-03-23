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
#include <osmocom/core/fsm.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/bssap.h>
#include <osmocom/bsc_nat/logging.h>
#include <osmocom/bsc_nat/msc.h>

#define X(s) (1 << (s))

enum msc_fsm_states {
	MSC_FSM_ST_DISCONNECTED,
	MSC_FSM_ST_CONNECTING,
	MSC_FSM_ST_CONNECTED,
};

enum msc_fsm_events {
	MSC_FSM_EV_TX_RESET,
	MSC_FSM_EV_RX_RESET_ACK,
	MSC_FSM_EV_DISCONNECT
};

static void st_connecting(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case MSC_FSM_EV_RX_RESET_ACK:
		osmo_fsm_inst_state_chg(fi, MSC_FSM_ST_CONNECTED, 0, 0);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void st_disconnected_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_stat)
{
	osmo_fsm_inst_dispatch(fi, MSC_FSM_EV_TX_RESET, NULL);
}

static void st_disconnected(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct msc *msc = fi->priv;

	switch (event) {
	case MSC_FSM_EV_TX_RESET:
		LOGP(DMAIN, LOGL_DEBUG, "Tx RESET to %s\n", talloc_get_name(msc));

		if (bssmap_tx_reset(g_bsc_nat->cn.sccp_inst, &msc->addr) < 0) {
			LOGP(DMAIN, LOGL_ERROR, "Could not send RESET to MSC (SCCP not up yet?)\n");
		}

		/* Retry in 3s if RESET ACK was not received from MSC */
		osmo_fsm_inst_state_chg(fi, MSC_FSM_ST_CONNECTING, 3, 0);

		break;
	default:
		OSMO_ASSERT(false);
	}
}

int msc_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->state) {
	case MSC_FSM_ST_CONNECTING:
		osmo_fsm_inst_state_chg(fi, MSC_FSM_ST_DISCONNECTED, 0, 0);
		break;
	default:
		OSMO_ASSERT(false);
	}
	return 0;
}

static struct osmo_fsm_state msc_fsm_states[] = {
	[MSC_FSM_ST_DISCONNECTED] = {
		.name = "DISCONNECTED",
		.in_event_mask = 0
			| X(MSC_FSM_EV_TX_RESET)
			,
		.out_state_mask = 0
			| X(MSC_FSM_ST_CONNECTING)
			,
		.action = st_disconnected,
		.onenter = st_disconnected_on_enter,
	},
	[MSC_FSM_ST_CONNECTING] = {
		.name = "CONNECTING",
		.in_event_mask = 0
			| X(MSC_FSM_EV_RX_RESET_ACK)
			,
		.out_state_mask = 0
			| X(MSC_FSM_ST_CONNECTED)
			| X(MSC_FSM_ST_DISCONNECTED)
			,
		.action = st_connecting,
	},
	[MSC_FSM_ST_CONNECTED] = {
		.name = "CONNECTED",
		.in_event_mask = 0
			| X(MSC_FSM_EV_DISCONNECT)
			,
		.out_state_mask = 0
			| X(MSC_FSM_ST_DISCONNECTED)
			,
	},
};

const struct value_string msc_fsm_event_names[] = {
	OSMO_VALUE_STRING(MSC_FSM_EV_TX_RESET),
	OSMO_VALUE_STRING(MSC_FSM_EV_RX_RESET_ACK),
	OSMO_VALUE_STRING(MSC_FSM_EV_DISCONNECT),
	{ 0, NULL }
};

struct osmo_fsm msc_fsm = {
	.name = "MSC",
	.states = msc_fsm_states,
	.num_states = ARRAY_SIZE(msc_fsm_states),
	.log_subsys = DMAIN,
	.event_names = msc_fsm_event_names,
	.timer_cb = msc_fsm_timer_cb,
};

static __attribute__((constructor)) void msc_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&msc_fsm) == 0);
}

void msc_tx_reset(struct msc *msc)
{
	osmo_fsm_inst_dispatch(msc->fi, MSC_FSM_EV_TX_RESET, NULL);
}

void msc_rx_reset_ack(struct msc *msc)
{
	osmo_fsm_inst_dispatch(msc->fi, MSC_FSM_EV_RX_RESET_ACK, NULL);
}

bool msc_is_connected(struct msc *msc)
{
	return msc->fi->state == MSC_FSM_ST_CONNECTED;
}

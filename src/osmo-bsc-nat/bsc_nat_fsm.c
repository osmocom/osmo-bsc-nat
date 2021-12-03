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
#include <stdint.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/select.h>

#include <osmocom/sigtran/osmo_ss7.h>

#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/bsc_nat_fsm.h>
#include <osmocom/bsc_nat/logging.h>

#define DEFAULT_PC_RAN "0.23.1" /* same as default for OsmoMSC */
#define DEFAULT_PC_CN "0.23.3" /* same as default for OsmoBSC */

#define X(s) (1 << (s))

enum bsc_nat_fsm_states {
	BSC_NAT_FSM_ST_STOPPED,
	BSC_NAT_FSM_ST_STARTING,
	BSC_NAT_FSM_ST_STARTED,
};

enum bsc_nat_fsm_events {
	BSC_NAT_FSM_EV_START,
	BSC_NAT_FSM_EV_STOP,
};

static int sccp_sap_up(struct osmo_prim_hdr *oph, void *priv)
{
	LOGP(DMAIN, LOGL_NOTICE, "STUB: sccp_sap_up() called\n");

	return 0;
}

static int ss7_inst_init(struct bsc_nat_ss7_inst *inst, const char *name, const char *default_pc_str,
			 enum osmo_sccp_ssn ssn)
{
	int default_pc;
	struct osmo_sccp_instance *sccp;

	default_pc = osmo_ss7_pointcode_parse(NULL, default_pc_str);
	OSMO_ASSERT(default_pc >= 0);

	sccp = osmo_sccp_simple_client_on_ss7_id(inst, inst->ss7_id, name, default_pc, OSMO_SS7_ASP_PROT_M3UA, 0, NULL,
						 0, NULL);
	if (!sccp) {
		LOGP(DMAIN, LOGL_ERROR, "%s: failed to request sccp client instance for sccp user\n", name);
		return -1;
	}

	osmo_sccp_local_addr_by_instance(&inst->local_sccp_addr, sccp, ssn);

	inst->scu = osmo_sccp_user_bind(sccp, name, sccp_sap_up, ssn);
	if (!inst->scu) {
		LOGP(DMAIN, LOGL_ERROR, "%s: failed to bind sccp user\n", name);
		return -2;
	}

	osmo_sccp_user_set_priv(inst->scu, inst);
	return 0;
}

static void ss7_inst_free(struct bsc_nat_ss7_inst *inst)
{
	if (inst->scu) {
		osmo_sccp_user_unbind(inst->scu);
		inst->scu = NULL;
	}

	struct osmo_ss7_instance *ss7 = osmo_ss7_instance_find(inst->ss7_id);
	if (ss7)
		osmo_ss7_instance_destroy(ss7);

	talloc_free(inst);
}

static void st_starting_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bsc_nat *bsc_nat = (struct bsc_nat *)fi->priv;

	if (ss7_inst_init(bsc_nat->cn, "OsmoBSCNAT-CN", DEFAULT_PC_CN, OSMO_SCCP_SSN_RANAP) < 0) {
		osmo_fsm_inst_state_chg(fi, BSC_NAT_FSM_ST_STOPPED, 0, 0);
		return;
	}

	if (ss7_inst_init(bsc_nat->ran, "OsmoBSCNAT-RAN", DEFAULT_PC_RAN, OSMO_SCCP_SSN_MSC) < 0) {
		osmo_fsm_inst_state_chg(fi, BSC_NAT_FSM_ST_STOPPED, 0, 0);
		return;
	}

	osmo_fsm_inst_state_chg(fi, BSC_NAT_FSM_ST_STARTED, 0, 0);
}

static void st_started(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case BSC_NAT_FSM_EV_STOP:
		osmo_fsm_inst_state_chg(fi, BSC_NAT_FSM_ST_STOPPED, 0, 0);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void st_stopped_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bsc_nat *bsc_nat = (struct bsc_nat *)fi->priv;

	ss7_inst_free(bsc_nat->cn);
	bsc_nat->cn = NULL;

	ss7_inst_free(bsc_nat->ran);
	bsc_nat->ran = NULL;
}

static void st_stopped(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case BSC_NAT_FSM_EV_START:
		osmo_fsm_inst_state_chg(fi, BSC_NAT_FSM_ST_STARTING, 0, 0);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static struct osmo_fsm_state bsc_nat_fsm_states[] = {
	[BSC_NAT_FSM_ST_STOPPED] = {
		.name = "STOPPED",
		.in_event_mask = 0
			| X(BSC_NAT_FSM_EV_START)
			,
		.out_state_mask = 0
			| X(BSC_NAT_FSM_ST_STARTING)
			,
		.action = st_stopped,
		.onenter = st_stopped_on_enter,
	},
	[BSC_NAT_FSM_ST_STARTING] = {
		.name = "STARTING",
		.out_state_mask = 0
			| X(BSC_NAT_FSM_ST_STARTED)
			| X(BSC_NAT_FSM_ST_STOPPED)
			,
		.onenter = st_starting_on_enter,
	},
	[BSC_NAT_FSM_ST_STARTED] = {
		.name = "STARTED",
		.in_event_mask = 0
			| X(BSC_NAT_FSM_EV_STOP)
			,
		.out_state_mask = 0
			| X(BSC_NAT_FSM_ST_STOPPED)
			,
		.action = st_started,
	},
};

const struct value_string bsc_nat_fsm_event_names[] = {
	OSMO_VALUE_STRING(BSC_NAT_FSM_EV_START),
	OSMO_VALUE_STRING(BSC_NAT_FSM_EV_STOP),
	{ 0, NULL }
};

struct osmo_fsm bsc_nat_fsm = {
	.name = "BSC_NAT",
	.states = bsc_nat_fsm_states,
	.num_states = ARRAY_SIZE(bsc_nat_fsm_states),
	.log_subsys = DMAIN,
	.event_names = bsc_nat_fsm_event_names,
};

static __attribute__((constructor)) void bsc_nat_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&bsc_nat_fsm) == 0);
}

void bsc_nat_fsm_alloc(struct bsc_nat *bsc_nat)
{
	bsc_nat->fi = osmo_fsm_inst_alloc(&bsc_nat_fsm, bsc_nat, bsc_nat, LOGL_INFO, NULL);
	OSMO_ASSERT(bsc_nat->fi);
}

void bsc_nat_fsm_start(struct bsc_nat *bsc_nat)
{
	osmo_fsm_inst_dispatch(bsc_nat->fi, BSC_NAT_FSM_EV_START, NULL);
}

void bsc_nat_fsm_stop(struct bsc_nat *bsc_nat)
{
	osmo_fsm_inst_dispatch(bsc_nat->fi, BSC_NAT_FSM_EV_STOP, NULL);
}

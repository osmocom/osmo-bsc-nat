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

#include <osmocom/gsm/gsm0808.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/bsc_nat_fsm.h>
#include <osmocom/bsc_nat/logging.h>

#define DEFAULT_PC_RAN "0.23.1" /* same as default for OsmoMSC */
#define DEFAULT_PC_CN "0.23.3" /* same as default for OsmoBSC */

static char log_buf[255];

#define LOG_SCCP(sccp_inst, peer_addr_in, level, fmt, args...) do { \
	if (peer_addr_in) \
		osmo_sccp_addr_to_str_buf(log_buf, sizeof(log_buf), NULL, peer_addr_in); \
	LOGP(DMAIN, level, "(%s%s%s) " fmt, \
	     peer_addr_in ? log_buf : "", \
	     peer_addr_in ? " from " : "", \
	     sccp_inst == g_bsc_nat->ran ? "RAN" : "CN", \
	     ## args); \
} while (0)

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

static struct bsc_nat_sccp_inst *sccp_inst_dest(struct bsc_nat_sccp_inst *src)
{
	if (src == g_bsc_nat->cn)
		return g_bsc_nat->ran;
	return g_bsc_nat->cn;
}

/* For connection-oriented messages, figure out which side is not the BSCNAT,
 * either the called_addr or calling_addr. */
static int sccp_sap_get_peer_addr_in(struct bsc_nat_sccp_inst *src, struct osmo_sccp_addr **peer_addr_in,
				     struct osmo_sccp_addr *called_addr, struct osmo_sccp_addr *calling_addr)
{
	if (osmo_sccp_addr_ri_cmp(&src->local_sccp_addr, called_addr) != 0) {
		*peer_addr_in = called_addr;
		return 0;
	} else if (osmo_sccp_addr_ri_cmp(&src->local_sccp_addr, calling_addr) != 0) {
		*peer_addr_in = calling_addr;
		return 0;
	}

	char buf_called[255];
	char buf_calling[255];

	osmo_sccp_addr_to_str_buf(buf_called, sizeof(buf_called), NULL, called_addr);
	osmo_sccp_addr_to_str_buf(buf_calling, sizeof(buf_calling), NULL, calling_addr);

	LOG_SCCP(src, NULL, LOGL_ERROR, "Invalid connection oriented message, locally configured address %s"
		 " is neither called address %s nor calling address %s!\n",
		 osmo_sccp_inst_addr_name(NULL, &src->local_sccp_addr), buf_called, buf_calling);
	return -1;
}

/* Figure out who will receive the message.
 * For now this is simplified by assuming there is only one MSC, one BSC. */
static int sccp_sap_get_peer_addr_out(struct bsc_nat_sccp_inst *src, struct osmo_sccp_addr *peer_addr_in,
				      struct osmo_sccp_addr *peer_addr_out)
{
	struct bsc_nat_sccp_inst *dest = sccp_inst_dest(src);

	if (src == g_bsc_nat->ran) {
		if (osmo_sccp_addr_by_name_local(peer_addr_out, "msc", dest->ss7_inst) < 0) {
			LOG_SCCP(src, peer_addr_in, LOGL_ERROR, "Could not find MSC in address book\n");
			return -1;
		}
	} else {
		if (osmo_sccp_addr_by_name_local(peer_addr_out, "bsc", dest->ss7_inst) < 0) {
			LOG_SCCP(src, peer_addr_in, LOGL_ERROR, "Could not find BSC in address book\n");
			return -2;
		}
	}

	return 0;
}

/* Handle incoming messages. For now this is simplified by assuming there is
 * only one MSC, one BSC (not yet translating connection ids etc.). */
static int sccp_sap_up(struct osmo_prim_hdr *oph, void *scu)
{
	struct bsc_nat_sccp_inst *src = osmo_sccp_user_get_priv(scu);
	struct bsc_nat_sccp_inst *dest = sccp_inst_dest(src);
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	struct osmo_sccp_addr *peer_addr_in;
	struct osmo_sccp_addr peer_addr_out;
	int rc = -1;

	switch (OSMO_PRIM_HDR(oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_CONFIRM):
		/* indication of connection confirm */
		LOG_SCCP(src, NULL, LOGL_DEBUG, "%s(%s)\n", __func__, osmo_scu_prim_name(oph));

		if (sccp_sap_get_peer_addr_in(src, &peer_addr_in, &prim->u.connect.called_addr,
					      &prim->u.connect.calling_addr) < 0)
			goto error;

		if (sccp_sap_get_peer_addr_out(src, peer_addr_in, &peer_addr_out) < 0)
			goto error;

		LOG_SCCP(src, peer_addr_in, LOGL_NOTICE, "Forwarding to %s in %s\n",
			 osmo_sccp_inst_addr_name(NULL, &peer_addr_out),
			 dest == g_bsc_nat->ran ? "RAN" : "CN");

		msgb_pull_to_l2(oph->msg);
		osmo_sccp_tx_conn_resp(dest->scu, prim->u.connect.conn_id, &peer_addr_out, oph->msg->data,
				       msgb_length(oph->msg));
		rc = 0;
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		/* indication of new inbound connection request */
		LOG_SCCP(src, NULL, LOGL_DEBUG, "%s(%s)\n", __func__, osmo_scu_prim_name(oph));

		if (sccp_sap_get_peer_addr_in(src, &peer_addr_in, &prim->u.connect.called_addr,
					      &prim->u.connect.calling_addr) < 0)
			goto error;

		if (sccp_sap_get_peer_addr_out(src, peer_addr_in, &peer_addr_out) < 0)
			goto error;

		LOG_SCCP(src, peer_addr_in, LOGL_NOTICE, "Forwarding to %s in %s\n",
			 osmo_sccp_inst_addr_name(NULL, &peer_addr_out),
			 dest == g_bsc_nat->ran ? "RAN" : "CN");

		msgb_pull_to_l2(oph->msg);
		osmo_sccp_tx_conn_req(dest->scu, prim->u.connect.conn_id, &dest->local_sccp_addr, &peer_addr_out,
				      oph->msg->data, msgb_length(oph->msg));
		rc = 0;
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		/* connection-oriented data received */
		LOG_SCCP(src, NULL, LOGL_DEBUG, "%s(%s)\n", __func__, osmo_scu_prim_name(oph));

		if (sccp_sap_get_peer_addr_out(src, NULL, &peer_addr_out) < 0)
			goto error;

		LOG_SCCP(src, NULL, LOGL_NOTICE, "Forwarding to %s in %s\n",
			 osmo_sccp_inst_addr_name(NULL, &peer_addr_out),
			 dest == g_bsc_nat->ran ? "RAN" : "CN");

		msgb_pull_to_l2(oph->msg);
		osmo_sccp_tx_data(dest->scu, prim->u.data.conn_id, oph->msg->data, msgb_length(oph->msg));
		rc = 0;
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION):
		/* indication of disconnect */
		LOG_SCCP(src, NULL, LOGL_DEBUG, "%s(%s)\n", __func__, osmo_scu_prim_name(oph));

		if (sccp_sap_get_peer_addr_out(src, NULL, &peer_addr_out) < 0)
			goto error;

		LOG_SCCP(src, NULL, LOGL_NOTICE, "Forwarding to %s in %s\n",
			 osmo_sccp_inst_addr_name(NULL, &peer_addr_out),
			 dest == g_bsc_nat->ran ? "RAN" : "CN");

		osmo_sccp_tx_disconn(dest->scu, prim->u.disconnect.conn_id, &prim->u.disconnect.responding_addr,
				     prim->u.disconnect.cause);
		rc = 0;
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		/* connection-less data received */
		peer_addr_in = &prim->u.unitdata.calling_addr;
		LOG_SCCP(src, peer_addr_in, LOGL_DEBUG, "%s(%s)\n", __func__, osmo_scu_prim_name(oph));

		if (sccp_sap_get_peer_addr_out(src, peer_addr_in, &peer_addr_out) < 0)
			goto error;

		LOG_SCCP(src, peer_addr_in, LOGL_NOTICE, "Forwarding to %s in %s\n",
			 osmo_sccp_inst_addr_name(NULL, &peer_addr_out),
			 dest == g_bsc_nat->ran ? "RAN" : "CN");

		/* oph->msg stores oph and unitdata msg. Move oph->msg->data to
		 * unitdata msg and send it again. */
		msgb_pull_to_l2(oph->msg);
		osmo_sccp_tx_unitdata(dest->scu, &dest->local_sccp_addr, &peer_addr_out, oph->msg->data,
				      msgb_length(oph->msg));
		rc = 0;
		break;

	default:
		LOG_SCCP(src, NULL, LOGL_ERROR, "%s(%s) is not implemented!\n", __func__, osmo_scu_prim_name(oph));
		break;
	}

error:
	msgb_free(oph->msg);
	return rc;
}

static int sccp_inst_init(struct bsc_nat_sccp_inst *sccp_inst, const char *name, const char *default_pc_str,
			 enum osmo_sccp_ssn ssn)
{
	int default_pc;
	struct osmo_sccp_instance *sccp;

	default_pc = osmo_ss7_pointcode_parse(NULL, default_pc_str);
	OSMO_ASSERT(default_pc >= 0);

	sccp = osmo_sccp_simple_client_on_ss7_id(sccp_inst, sccp_inst->ss7_id, name, default_pc, OSMO_SS7_ASP_PROT_M3UA,
						 0, NULL, 0, NULL);
	if (!sccp) {
		LOGP(DMAIN, LOGL_ERROR, "%s: failed to request sccp client instance for sccp user\n", name);
		return -1;
	}

	sccp_inst->ss7_inst = osmo_ss7_instance_find(sccp_inst->ss7_id);

	osmo_sccp_local_addr_by_instance(&sccp_inst->local_sccp_addr, sccp, ssn);

	sccp_inst->scu = osmo_sccp_user_bind(sccp, name, sccp_sap_up, ssn);
	if (!sccp_inst->scu) {
		LOGP(DMAIN, LOGL_ERROR, "%s: failed to bind sccp user\n", name);
		return -2;
	}

	osmo_sccp_user_set_priv(sccp_inst->scu, sccp_inst);
	return 0;
}

static void sccp_inst_free(struct bsc_nat_sccp_inst *sccp_inst)
{
	if (sccp_inst->scu) {
		osmo_sccp_user_unbind(sccp_inst->scu);
		sccp_inst->scu = NULL;
	}

	if (sccp_inst->ss7_inst) {
		osmo_ss7_instance_destroy(sccp_inst->ss7_inst);
		sccp_inst->ss7_inst = NULL;
	}

	talloc_free(sccp_inst);
}

static void st_starting_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct bsc_nat *bsc_nat = (struct bsc_nat *)fi->priv;

	if (sccp_inst_init(bsc_nat->cn, "OsmoBSCNAT-CN", DEFAULT_PC_CN, OSMO_SCCP_SSN_BSSAP) < 0) {
		osmo_fsm_inst_state_chg(fi, BSC_NAT_FSM_ST_STOPPED, 0, 0);
		return;
	}

	if (sccp_inst_init(bsc_nat->ran, "OsmoBSCNAT-RAN", DEFAULT_PC_RAN, OSMO_SCCP_SSN_BSSAP) < 0) {
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

	sccp_inst_free(bsc_nat->cn);
	bsc_nat->cn = NULL;

	sccp_inst_free(bsc_nat->ran);
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

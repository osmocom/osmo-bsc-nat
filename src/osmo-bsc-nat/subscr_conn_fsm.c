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
#include <osmocom/core/fsm.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>
#include <osmocom/mgcp_client/mgcp_client_fsm.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/bssap.h>
#include <osmocom/bsc_nat/logging.h>
#include <osmocom/bsc_nat/subscr_conn.h>
#include <osmocom/bsc_nat/subscr_conn_fsm.h>

#define X(s) (1 << (s))
#define TIMEOUT_MGW 10
#define TIMEOUT_BSC 20

enum subscr_conn_fsm_states {
	SUBSCR_CONN_FSM_ST_IDLE,
	SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_REQUEST_CRCX_CN,
	SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_REQUEST_MDCX_CN,
	SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_REQUEST_CRCX_RAN,
	SUBSCR_CONN_FSM_ST_WAITING_FOR_ASSIGNMENT_COMPLETE,
	SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_COMPLETE_MDCX_RAN,
	SUBSCR_CONN_FSM_ST_WAITING_FOR_CLEAR_COMMAND,
};

static int tx_ass_req_to_ran(struct subscr_conn *subscr_conn)
{
	const struct mgcp_conn_peer *rtp_info;
	struct sockaddr_storage ss;
	struct osmo_sockaddr_str aoip_transp_addr;
	int rc;

	/* Fill sockaddr_storage from rtp_info */
	rtp_info = osmo_mgcpc_ep_ci_get_rtp_info(subscr_conn->ran.ci);
	if (!rtp_info) {
		LOGPFSML(subscr_conn->fi, LOGL_ERROR, "Failed to get RTP info from MGW, aborting assignment request\n");
		return -1;
	}
	if (osmo_sockaddr_str_from_str(&aoip_transp_addr, rtp_info->addr, rtp_info->port) < 0
	    || osmo_sockaddr_str_to_sockaddr((const struct osmo_sockaddr_str *)&aoip_transp_addr, &ss) < 0) {
		LOGPFSML(subscr_conn->fi, LOGL_ERROR, "RTP info from MGW is invalid, aborting assignment request\n");
		return -1;
	}

	if (bssmap_replace_ie_aoip_transp_addr(&subscr_conn->ass.msg, &ss) < 0) {
		LOGPFSML(subscr_conn->fi, LOGL_ERROR, "Failed to replace AoIP transport layer address, aborting"
			 " assignment request\n");
		return -1;
	}

	rc = osmo_sccp_tx_data_msg(g_bsc_nat->ran.sccp_inst->scu, subscr_conn->ran.id, subscr_conn->ass.msg);
	subscr_conn->ass.msg = NULL;
	return rc;
}

static int tx_ass_compl_to_cn(struct subscr_conn *subscr_conn)
{
	const struct mgcp_conn_peer *rtp_info;
	struct sockaddr_storage ss;
	struct osmo_sockaddr_str aoip_transp_addr;
	int rc;

	/* Fill sockaddr_storage from rtp_info */
	rtp_info = osmo_mgcpc_ep_ci_get_rtp_info(subscr_conn->cn.ci);
	if (!rtp_info) {
		LOGPFSML(subscr_conn->fi, LOGL_ERROR, "Failed to get RTP info from MGW, aborting assignment complete\n");
		return -1;
	}
	if (osmo_sockaddr_str_from_str(&aoip_transp_addr, rtp_info->addr, rtp_info->port) < 0
	    || osmo_sockaddr_str_to_sockaddr((const struct osmo_sockaddr_str *)&aoip_transp_addr, &ss) < 0) {
		LOGPFSML(subscr_conn->fi, LOGL_ERROR, "RTP info from MGW is invalid, aborting assignment complete\n");
		return -1;
	}

	if (bssmap_replace_ie_aoip_transp_addr(&subscr_conn->ass.msg, &ss) < 0) {
		LOGPFSML(subscr_conn->fi, LOGL_ERROR, "Failed to replace AoIP transport layer address, aborting"
			 " assignment complete\n");
		return -1;
	}

	rc = osmo_sccp_tx_data_msg(g_bsc_nat->cn.sccp_inst->scu, subscr_conn->cn.id, subscr_conn->ass.msg);
	subscr_conn->ass.msg = NULL;
	return rc;
}


static void st_idle_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct subscr_conn *subscr_conn = (struct subscr_conn *)fi->priv;
	if (!subscr_conn->ep)
		return;

	osmo_mgcpc_ep_clear(subscr_conn->ep);

	subscr_conn->ep = NULL;
	subscr_conn->ran.ci = NULL;
	subscr_conn->cn.ci = NULL;
}

static void st_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SUBSCR_CONN_FSM_EV_BSSMAP_ASSIGNMENT_REQUEST:
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_REQUEST_CRCX_CN, TIMEOUT_MGW, 0);
		break;
	case SUBSCR_CONN_FSM_EV_MGCP_EP_TERM:
		/* This event is expected, as we terminate the MGCP EP in
		 * st_idle_on_enter(). Nothing to do here. */
		break;
	case SUBSCR_CONN_FSM_EV_BSSMAP_CLEAR_COMMAND:
		/* Clear commands sent to this FSM in idle state are not
		 * relevant, so ignore them here. bssmap_cn_handle_clear_cmd()
		 * forwards them from CN to RAN. */
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void st_processing_ass_req_crcx_cn_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_stat)
{
	struct mgcp_client *mgcp_client;
	struct mgcp_conn_peer crcx_info = {};
	struct subscr_conn *subscr_conn = (struct subscr_conn *)fi->priv;
	int call_id = subscr_conn_get_next_id_mgw();

	if (call_id < 0) {
		LOGPFSML(fi, LOGL_ERROR, "Failed to get next_id_mgw, aborting assignment request processing\n");
		bssmap_tx_assignment_failure_cn(subscr_conn, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_IDLE, 0, 0);
	}

	/* MGCP EP */
	mgcp_client = mgcp_client_pool_get(g_bsc_nat->mgw.pool);
	OSMO_ASSERT(mgcp_client);
	subscr_conn->ep = osmo_mgcpc_ep_alloc(subscr_conn->fi, SUBSCR_CONN_FSM_EV_MGCP_EP_TERM, mgcp_client,
					      g_bsc_nat->mgw.tdefs, "SUBSCR-CONN-EP",
					      mgcp_client_rtpbridge_wildcard(mgcp_client));

	/* MGCP CRCX CN */
	LOGPFSML(fi, LOGL_DEBUG, "Set MGW call_id=%d for %s\n", call_id, talloc_get_name(subscr_conn));
	crcx_info.call_id = subscr_conn->mgw_call_id = call_id;
	subscr_conn->cn.ci = osmo_mgcpc_ep_ci_add(subscr_conn->ep, "CI-%"PRIu32"-CN", crcx_info.call_id);
	osmo_mgcpc_ep_ci_request(subscr_conn->cn.ci, MGCP_VERB_CRCX, &crcx_info, subscr_conn->fi,
				 SUBSCR_CONN_FSM_EV_MGCP_EP_OK, SUBSCR_CONN_FSM_EV_MGCP_EP_FAIL, NULL);
}

static void st_processing_ass_req_crcx_cn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct subscr_conn *subscr_conn = (struct subscr_conn *)fi->priv;

	switch (event) {
	case SUBSCR_CONN_FSM_EV_MGCP_EP_OK:
		LOGPFSML(fi, LOGL_DEBUG, "Rx MGCP OK\n");
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_REQUEST_MDCX_CN, TIMEOUT_MGW, 0);
		break;
	case SUBSCR_CONN_FSM_EV_MGCP_EP_FAIL:
		LOGPFSML(fi, LOGL_ERROR, "MGCP failure, aborting assignment request processing\n");
		bssmap_tx_assignment_failure_cn(subscr_conn, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_IDLE, 0, 0);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void st_processing_ass_req_mdcx_cn_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_stat)
{
	struct mgcp_conn_peer mdcx_info = {};
	struct subscr_conn *subscr_conn = (struct subscr_conn *)fi->priv;
	struct osmo_sockaddr_str *addr = &subscr_conn->ass.aoip_transp_addr;

	/* Set RTP addr + port */
	osmo_static_assert(sizeof(mdcx_info.addr) == sizeof(addr->ip), sizeof_addr);
	memcpy(mdcx_info.addr, addr->ip, sizeof(mdcx_info.addr));
	mdcx_info.port = addr->port;

	/* MGCP MDCX CN */
	osmo_mgcpc_ep_ci_request(subscr_conn->cn.ci, MGCP_VERB_MDCX, &mdcx_info, subscr_conn->fi,
				 SUBSCR_CONN_FSM_EV_MGCP_EP_OK, SUBSCR_CONN_FSM_EV_MGCP_EP_FAIL, NULL);
}

static void st_processing_ass_req_mdcx_cn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct subscr_conn *subscr_conn = (struct subscr_conn *)fi->priv;

	switch (event) {
	case SUBSCR_CONN_FSM_EV_MGCP_EP_OK:
		LOGPFSML(fi, LOGL_DEBUG, "Rx MGCP OK\n");
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_REQUEST_CRCX_RAN, TIMEOUT_MGW, 0);
		break;
	case SUBSCR_CONN_FSM_EV_MGCP_EP_FAIL:
		LOGPFSML(fi, LOGL_ERROR, "MGCP failure, aborting assignment request processing\n");
		bssmap_tx_assignment_failure_cn(subscr_conn, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_IDLE, 0, 0);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void st_processing_ass_req_crcx_ran_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_stat)
{
	struct subscr_conn *subscr_conn = (struct subscr_conn *)fi->priv;
	struct mgcp_conn_peer crcx_info = {};
	crcx_info.call_id = subscr_conn->mgw_call_id;

	subscr_conn->ran.ci = osmo_mgcpc_ep_ci_add(subscr_conn->ep, "CI-%"PRIu32"-RAN", crcx_info.call_id);
	osmo_mgcpc_ep_ci_request(subscr_conn->ran.ci, MGCP_VERB_CRCX, &crcx_info, subscr_conn->fi,
				 SUBSCR_CONN_FSM_EV_MGCP_EP_OK, SUBSCR_CONN_FSM_EV_MGCP_EP_FAIL, NULL);
}

static void st_processing_ass_req_crcx_ran(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct subscr_conn *subscr_conn = (struct subscr_conn *)fi->priv;

	switch (event) {
	case SUBSCR_CONN_FSM_EV_MGCP_EP_OK:
		LOGPFSML(fi, LOGL_DEBUG, "Rx MGCP OK\n");
		if (tx_ass_req_to_ran(subscr_conn) < 0) {
			bssmap_tx_assignment_failure_cn(subscr_conn, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
			osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_IDLE, 0, 0);
			return;
		}
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_WAITING_FOR_ASSIGNMENT_COMPLETE, TIMEOUT_BSC, 0);
		break;
	case SUBSCR_CONN_FSM_EV_MGCP_EP_FAIL:
		LOGPFSML(fi, LOGL_ERROR, "MGCP failure, aborting assignment request processing\n");
		bssmap_tx_assignment_failure_cn(subscr_conn, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_IDLE, 0, 0);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void st_waiting_for_ass_compl(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SUBSCR_CONN_FSM_EV_BSSMAP_ASSIGNMENT_COMPLETE:
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_COMPLETE_MDCX_RAN, TIMEOUT_MGW, 0);
		break;
	case SUBSCR_CONN_FSM_EV_BSSMAP_ASSIGNMENT_FAILURE:
		/* The original bssmap message gets forwarded from RAN to CN by
		 * bssmap_ran_handle_assignment_failure() already, so just
		 * reset the FSM to idle here (clears the mgw endpoint). */
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_IDLE, 0, 0);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void st_processing_ass_compl_mdcx_ran_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_stat)
{
	struct mgcp_conn_peer mdcx_info = {};
	struct subscr_conn *subscr_conn = (struct subscr_conn *)fi->priv;
	struct osmo_sockaddr_str *aoip_transp_addr = &subscr_conn->ass.aoip_transp_addr;

	/* Set RTP addr + port */
	osmo_static_assert(sizeof(mdcx_info.addr) == sizeof(aoip_transp_addr->ip), sizeof_addr);
	memcpy(mdcx_info.addr, aoip_transp_addr->ip, sizeof(mdcx_info.addr));
	mdcx_info.port = aoip_transp_addr->port;

	/* MGCP MDCX RAN */
	osmo_mgcpc_ep_ci_request(subscr_conn->ran.ci, MGCP_VERB_MDCX, &mdcx_info, subscr_conn->fi,
				 SUBSCR_CONN_FSM_EV_MGCP_EP_OK, SUBSCR_CONN_FSM_EV_MGCP_EP_FAIL, NULL);
}

static void st_processing_ass_compl_mdcx_ran(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct subscr_conn *subscr_conn = (struct subscr_conn *)fi->priv;

	switch (event) {
	case SUBSCR_CONN_FSM_EV_MGCP_EP_OK:
		LOGPFSML(fi, LOGL_DEBUG, "Rx MGCP EP OK\n");
		if (tx_ass_compl_to_cn(subscr_conn) < 0) {
			bssmap_tx_assignment_failure_cn(subscr_conn, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
			bssmap_tx_assignment_failure_ran(subscr_conn, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
			osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_IDLE, 0, 0);
			return;
		}
		/* No timeout for ST_WAITING_FOR_CLEAR_COMMAND, as the FSM will
		 * stay in this state until the call is done. */
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_WAITING_FOR_CLEAR_COMMAND, 0, 0);
		break;
	case SUBSCR_CONN_FSM_EV_MGCP_EP_FAIL:
		LOGPFSML(fi, LOGL_ERROR, "MGCP failure, aborting assignment complete processing\n");
		bssmap_tx_assignment_failure_cn(subscr_conn, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
		bssmap_tx_assignment_failure_ran(subscr_conn, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_IDLE, 0, 0);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

static void st_waiting_for_clear_command(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SUBSCR_CONN_FSM_EV_BSSMAP_CLEAR_COMMAND:
		/* The original bssmap message gets forwarded from CN to RAN by
		 * bssmap_cn_handle_clear_cmd() already, so just reset the FSM
		 * to idle here (clears the mgw endpoint). */
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_IDLE, 0, 0);
		break;
	default:
		OSMO_ASSERT(false);
	}
}

int subscr_conn_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	LOGPFSML(fi, LOGL_ERROR, "Timeout reached, reset FSM to idle\n");
	osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_FSM_ST_IDLE, 0, 0);
	return 0;
}

static struct osmo_fsm_state subscr_conn_fsm_states[] = {
	[SUBSCR_CONN_FSM_ST_IDLE] = {
		.name = "IDLE",
		.in_event_mask = 0
			| X(SUBSCR_CONN_FSM_EV_BSSMAP_ASSIGNMENT_REQUEST)
			| X(SUBSCR_CONN_FSM_EV_BSSMAP_CLEAR_COMMAND)
			| X(SUBSCR_CONN_FSM_EV_MGCP_EP_TERM)
			,
		.out_state_mask = 0
			| X(SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_REQUEST_CRCX_CN)
			,
		.action = st_idle,
		.onenter = st_idle_on_enter,
	},
	[SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_REQUEST_CRCX_CN] = {
		.name = "PROCESSING_ASSIGNMENT_REQUEST_CRCX_CN",
		.in_event_mask = 0
			| X(SUBSCR_CONN_FSM_EV_MGCP_EP_OK)
			| X(SUBSCR_CONN_FSM_EV_MGCP_EP_FAIL)
			,
		.out_state_mask = 0
			| X(SUBSCR_CONN_FSM_ST_IDLE)
			| X(SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_REQUEST_MDCX_CN)
			,
		.action = st_processing_ass_req_crcx_cn,
		.onenter = st_processing_ass_req_crcx_cn_on_enter,
	},
	[SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_REQUEST_MDCX_CN] = {
		.name = "PROCESSING_ASSIGNMENT_REQUEST_MDCX_CN",
		.in_event_mask = 0
			| X(SUBSCR_CONN_FSM_EV_MGCP_EP_OK)
			| X(SUBSCR_CONN_FSM_EV_MGCP_EP_FAIL)
			,
		.out_state_mask = 0
			| X(SUBSCR_CONN_FSM_ST_IDLE)
			| X(SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_REQUEST_CRCX_RAN)
			,
		.action = st_processing_ass_req_mdcx_cn,
		.onenter = st_processing_ass_req_mdcx_cn_on_enter,
	},
	[SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_REQUEST_CRCX_RAN] = {
		.name = "PROCESSING_ASSIGNMENT_REQUEST_CRCX_RAN",
		.in_event_mask = 0
			| X(SUBSCR_CONN_FSM_EV_MGCP_EP_OK)
			| X(SUBSCR_CONN_FSM_EV_MGCP_EP_FAIL)
			,
		.out_state_mask = 0
			| X(SUBSCR_CONN_FSM_ST_IDLE)
			| X(SUBSCR_CONN_FSM_ST_WAITING_FOR_ASSIGNMENT_COMPLETE)
			,
		.action = st_processing_ass_req_crcx_ran,
		.onenter = st_processing_ass_req_crcx_ran_on_enter,
	},
	[SUBSCR_CONN_FSM_ST_WAITING_FOR_ASSIGNMENT_COMPLETE] = {
		.name = "WAITING_FOR_ASSIGNMENT_COMPLETE",
		.in_event_mask = 0
			| X(SUBSCR_CONN_FSM_EV_BSSMAP_ASSIGNMENT_COMPLETE)
			| X(SUBSCR_CONN_FSM_EV_BSSMAP_ASSIGNMENT_FAILURE)
			,
		.out_state_mask = 0
			| X(SUBSCR_CONN_FSM_ST_IDLE)
			| X(SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_COMPLETE_MDCX_RAN)
			,
		.action = st_waiting_for_ass_compl,
	},
	[SUBSCR_CONN_FSM_ST_PROCESSING_ASSIGNMENT_COMPLETE_MDCX_RAN] = {
		.name = "PROCESSING_ASSIGNMENT_COMPLETE",
		.in_event_mask = 0
			| X(SUBSCR_CONN_FSM_EV_MGCP_EP_OK)
			| X(SUBSCR_CONN_FSM_EV_MGCP_EP_FAIL)
			,
		.out_state_mask = 0
			| X(SUBSCR_CONN_FSM_ST_IDLE)
			| X(SUBSCR_CONN_FSM_ST_WAITING_FOR_CLEAR_COMMAND)
			,
		.action = st_processing_ass_compl_mdcx_ran,
		.onenter = st_processing_ass_compl_mdcx_ran_on_enter,
	},
	[SUBSCR_CONN_FSM_ST_WAITING_FOR_CLEAR_COMMAND] = {
		.name = "WAITING_FOR_CLEAR_COMMAND",
		.in_event_mask = 0
			| X(SUBSCR_CONN_FSM_EV_BSSMAP_CLEAR_COMMAND)
			,
		.out_state_mask = 0
			| X(SUBSCR_CONN_FSM_ST_IDLE)
			,
		.action = st_waiting_for_clear_command,
	},
};

const struct value_string subscr_conn_fsm_event_names[] = {
	OSMO_VALUE_STRING(SUBSCR_CONN_FSM_EV_BSSMAP_ASSIGNMENT_REQUEST),
	OSMO_VALUE_STRING(SUBSCR_CONN_FSM_EV_BSSMAP_ASSIGNMENT_COMPLETE),
	OSMO_VALUE_STRING(SUBSCR_CONN_FSM_EV_BSSMAP_ASSIGNMENT_FAILURE),
	OSMO_VALUE_STRING(SUBSCR_CONN_FSM_EV_BSSMAP_CLEAR_COMMAND),
	OSMO_VALUE_STRING(SUBSCR_CONN_FSM_EV_MGCP_EP_OK),
	OSMO_VALUE_STRING(SUBSCR_CONN_FSM_EV_MGCP_EP_FAIL),
	OSMO_VALUE_STRING(SUBSCR_CONN_FSM_EV_MGCP_EP_TERM),
	{ 0, NULL }
};

struct osmo_fsm subscr_conn_fsm = {
	.name = "SUBSCR_CONN",
	.states = subscr_conn_fsm_states,
	.num_states = ARRAY_SIZE(subscr_conn_fsm_states),
	.log_subsys = DMAIN,
	.event_names = subscr_conn_fsm_event_names,
	.timer_cb = subscr_conn_fsm_timer_cb,
};

static void ass_update(struct subscr_conn *subscr_conn, const struct osmo_sockaddr_str *aoip_transp_addr,
		       struct msgb *msg)
{
	struct msgb *copy = msgb_copy_c(subscr_conn, msg, talloc_get_name(msg));
	OSMO_ASSERT(copy);

	if (subscr_conn->ass.msg)
		msgb_free(subscr_conn->ass.msg);

	subscr_conn->ass.msg = copy;
	subscr_conn->ass.aoip_transp_addr = *aoip_transp_addr;
}

int subscr_conn_rx_ass_req(struct subscr_conn *subscr_conn, const struct osmo_sockaddr_str *aoip_transp_addr,
			   struct msgb *msg)
{
	if (subscr_conn->fi->state != SUBSCR_CONN_FSM_ST_IDLE) {
		LOGPFSML(subscr_conn->fi, LOGL_ERROR, "Unexpected Rx BSSMAP assignment request\n");
		return -1;
	}

	ass_update(subscr_conn, aoip_transp_addr, msg);
	return osmo_fsm_inst_dispatch(subscr_conn->fi, SUBSCR_CONN_FSM_EV_BSSMAP_ASSIGNMENT_REQUEST, NULL);
}

int subscr_conn_rx_ass_compl(struct subscr_conn *subscr_conn, const struct osmo_sockaddr_str *aoip_transp_addr,
			     struct msgb *msg)
{
	if (subscr_conn->fi->state != SUBSCR_CONN_FSM_ST_WAITING_FOR_ASSIGNMENT_COMPLETE) {
		LOGPFSML(subscr_conn->fi, LOGL_ERROR, "Unexpected Rx BSSMAP assignment complete\n");
		return -1;
	}

	ass_update(subscr_conn, aoip_transp_addr, msg);
	return osmo_fsm_inst_dispatch(subscr_conn->fi, SUBSCR_CONN_FSM_EV_BSSMAP_ASSIGNMENT_COMPLETE, NULL);
}

static __attribute__((constructor)) void subscr_conn_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&subscr_conn_fsm) == 0);
}

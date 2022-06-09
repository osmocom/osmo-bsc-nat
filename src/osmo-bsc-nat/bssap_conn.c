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
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/bsc_nat/logging.h>
#include <osmocom/bsc_nat/subscr_conn.h>
#include <osmocom/bsc_nat/subscr_conn_fsm.h>

int bssmap_replace_ie_aoip_transp_addr(struct msgb **msg, struct sockaddr_storage *ss)
{
	struct msgb *msg_new;
	struct msgb *msg_old = *msg;
	const struct tlv_definition *def = gsm0808_att_tlvdef();
	int ofs = 1; /* first byte is bssmap message type */
	int rc;

	msg_new = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM, talloc_get_name(msg_old));
	OSMO_ASSERT(msg_new);
	msgb_v_put(msg_new, msg_old->l3h[0]); /* bssmap message type */

	while (ofs < msgb_l3len(msg_old)) {
		int rv;
		uint8_t tag;
		const uint8_t *val;
		uint16_t len;

		rv = tlv_parse_one(&tag, &len, &val, def, &msg_old->l3h[ofs], msgb_l3len(msg_old) - ofs);
		if (rv < 0) {
			LOGP(DMAIN, LOGL_ERROR, "Failed to parse bssmap msg\n");
			msgb_free(msg_new);
			return rv;
		}

		if (tag == GSM0808_IE_AOIP_TRASP_ADDR)
			rc = gsm0808_enc_aoip_trasp_addr(msg_new, ss);
		else
			rc = tlv_encode_one(msg_new, def->def[tag].type, tag, len, val);

		if (rc < 0) {
			LOGP(DMAIN, LOGL_ERROR, "Failed to encode tag %d into copy of bssmap msg\n", tag);
			msgb_free(msg_new);
			return rc;
		}

		ofs += rv;
	}

	msg_new->l3h = msgb_tv_push(msg_new, BSSAP_MSG_BSS_MANAGEMENT, msgb_length(msg_new));
	msgb_free(msg_old);
	*msg = msg_new;
	return 0;
}

int bssmap_tx_assignment_failure(enum bsc_nat_net net, struct subscr_conn *subscr_conn, enum gsm0808_cause cause)
{
	struct bsc_nat_sccp_inst *sccp_inst;
	uint32_t id;
	struct msgb *msg;

	LOGP(DMAIN, LOGL_ERROR, "Tx BSSMAP assignment failure %s to %s via %s\n",
	     gsm0808_cause_name(cause),
	     net == BSC_NAT_NET_CN ? "CN" : "RAN",
	     talloc_get_name(subscr_conn));

	if (net == BSC_NAT_NET_CN) {
		sccp_inst = g_bsc_nat->cn.sccp_inst;
		id = subscr_conn->cn.id;
	} else {
		sccp_inst = g_bsc_nat->ran.sccp_inst;
		id = subscr_conn->ran.id;
	}

	msg = gsm0808_create_ass_fail(cause, NULL, NULL);
	return osmo_sccp_tx_data_msg(sccp_inst->scu, id, msg);
}

static int bssap_fwd_to_cn(struct subscr_conn *subscr_conn, struct msgb *msg, unsigned int length)
{
	LOGP(DMAIN, LOGL_DEBUG, "Fwd BSSAP to CN via %s\n", talloc_get_name(subscr_conn));

	msgb_pull_to_l2(msg);

	return osmo_sccp_tx_data(g_bsc_nat->cn.sccp_inst->scu, subscr_conn->cn.id, msg->data, msgb_length(msg));
}

static int bssap_fwd_to_ran(struct subscr_conn *subscr_conn, struct msgb *msg, unsigned int length)
{
	LOGP(DMAIN, LOGL_DEBUG, "Fwd BSSAP to RAN via %s\n", talloc_get_name(subscr_conn));

	msgb_pull_to_l2(msg);

	return osmo_sccp_tx_data(g_bsc_nat->ran.sccp_inst->scu, subscr_conn->ran.id, msg->data, msgb_length(msg));
}

static int bssmap_cn_handle_ass_req(struct subscr_conn *subscr_conn, struct msgb *msg, unsigned int length)
{
	struct gsm0808_channel_type ct;
	struct tlv_parsed tp;
	struct sockaddr_storage ss;
	struct tlv_p_entry *e;
	struct osmo_sockaddr_str aoip_transp_addr;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, length - 1, 0, 0);

	/* Get channel type */
	if (!(e = TLVP_GET(&tp, GSM0808_IE_CHANNEL_TYPE))) {
		LOGP(DMAIN, LOGL_ERROR, "Missing IE: channel type\n");
		bssmap_tx_assignment_failure_cn(subscr_conn, GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING);
		return -1;
	}
	if (gsm0808_dec_channel_type(&ct, e->val, e->len) <= 0) {
		LOGP(DMAIN, LOGL_ERROR, "Invalid IE: channel type\n");
		bssmap_tx_assignment_failure_cn(subscr_conn, GSM0808_CAUSE_INCORRECT_VALUE);
		return -1;
	}

	/* Not speech: fwd directly */
	if ((ct.ch_indctr & 0x0f) != GSM0808_CHAN_SPEECH) {
		LOGP(DMAIN, LOGL_DEBUG, "Channel type is not speech, forwarding without modification\n");
		if (bssap_fwd_to_ran(subscr_conn, msg, length) < 0) {
			bssmap_tx_assignment_failure_cn(subscr_conn, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
			return -1;
		}
		return 0;
	}

	/* Get AoIP transport layer address */
	if (!(e = TLVP_GET(&tp, GSM0808_IE_AOIP_TRASP_ADDR))) {
		LOGP(DMAIN, LOGL_ERROR, "Missing IE: AoIP transport layer address\n");
		bssmap_tx_assignment_failure_cn(subscr_conn, GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING);
		return -1;
	}
	if (gsm0808_dec_aoip_trasp_addr(&ss, e->val, e->len) <= 0
	    || osmo_sockaddr_str_from_sockaddr(&aoip_transp_addr, &ss) < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Invalid IE: AoIP transport layer address\n");
		bssmap_tx_assignment_failure_cn(subscr_conn, GSM0808_CAUSE_INCORRECT_VALUE);
		return -1;
	}

	/* Don't forward the message directly. Instead, let the subscr_conn FSM
	 * allocate new MGCP connections in the BSCNAT's MGW and then send a
	 * similar assignment request, but with the RTP address replaced. */
	if (subscr_conn_rx_ass_req(subscr_conn, &aoip_transp_addr, msg) < 0) {
		bssmap_tx_assignment_failure_cn(subscr_conn, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
		return -1;
	}

	return 0;
}

static void bssmap_ran_error_ass_compl(struct subscr_conn *subscr_conn, enum gsm0808_cause cause_ran)
{
	bssmap_tx_assignment_failure_cn(subscr_conn, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
	bssmap_tx_assignment_failure_ran(subscr_conn, cause_ran);

	/* For the FSM, treat this the same as if the BSC had responded with
	 * assignment failure. */
	osmo_fsm_inst_dispatch(subscr_conn->fi, SUBSCR_CONN_FSM_EV_BSSMAP_ASSIGNMENT_FAILURE, NULL);
}

static int bssmap_ran_handle_ass_compl(struct subscr_conn *subscr_conn, struct msgb *msg, unsigned int length)
{
	struct tlv_parsed tp;
	struct sockaddr_storage ss;
	struct tlv_p_entry *e;
	struct osmo_sockaddr_str aoip_transp_addr;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, length - 1, 0, 0);

	/* Get AoIP transport layer address */
	if (!(e = TLVP_GET(&tp, GSM0808_IE_AOIP_TRASP_ADDR))) {
		LOGP(DMAIN, LOGL_ERROR, "Missing IE: AoIP transport layer address\n");
		bssmap_ran_error_ass_compl(subscr_conn, GSM0808_CAUSE_INFORMATION_ELEMENT_OR_FIELD_MISSING);
		return -1;
	}
	if (gsm0808_dec_aoip_trasp_addr(&ss, e->val, e->len) <= 0
	    || osmo_sockaddr_str_from_sockaddr(&aoip_transp_addr, &ss) < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Invalid IE: AoIP transport layer address\n");
		bssmap_ran_error_ass_compl(subscr_conn, GSM0808_CAUSE_INCORRECT_VALUE);
		return -1;
	}

	/* Don't forward the message directly. Instead, let the subscr_conn FSM
	 * use the RTP info to MDCX the BSC-side connection in the BSCNAT's MGW
	 * and then send a similar assignment complete to the MSC, but with the
	 * RTP address replaced. */
	if (subscr_conn_rx_ass_compl(subscr_conn, &aoip_transp_addr, msg) < 0) {
		bssmap_ran_error_ass_compl(subscr_conn, GSM0808_CAUSE_PROTOCOL_ERROR_BETWEEN_BSS_AND_MSC);
		return -1;
	}

	return 0;
}

static int bssmap_ran_handle_assignment_failure(struct subscr_conn *subscr_conn, struct msgb *msg, unsigned int length)
{
	osmo_fsm_inst_dispatch(subscr_conn->fi, SUBSCR_CONN_FSM_EV_BSSMAP_ASSIGNMENT_FAILURE, NULL);
	bssap_fwd_to_ran(subscr_conn, msg, length);
	return 0;
}

static int bssmap_cn_handle_clear_cmd(struct subscr_conn *subscr_conn, struct msgb *msg, unsigned int length)
{
	osmo_fsm_inst_dispatch(subscr_conn->fi, SUBSCR_CONN_FSM_EV_BSSMAP_CLEAR_COMMAND, NULL);
	bssap_fwd_to_ran(subscr_conn, msg, length);
	return 0;
}

static int bssmap_cn_rcvmsg_dt(struct subscr_conn *subscr_conn, struct msgb *msg, unsigned int length)
{
	int ret = 0;

	switch (msg->l3h[0]) {
	case BSS_MAP_MSG_ASSIGNMENT_RQST:
		ret = bssmap_cn_handle_ass_req(subscr_conn, msg, length);
		break;
	case BSS_MAP_MSG_CLEAR_CMD:
		ret = bssmap_cn_handle_clear_cmd(subscr_conn, msg, length);
		break;
	default:
		ret = bssap_fwd_to_ran(subscr_conn, msg, length);
		break;
	}

	return ret;
}

static int bssmap_ran_rcvmsg_dt(struct subscr_conn *subscr_conn, struct msgb *msg, unsigned int length)
{
	int ret = 0;

	switch (msg->l3h[0]) {
	case BSS_MAP_MSG_ASSIGNMENT_COMPLETE:
		ret = bssmap_ran_handle_ass_compl(subscr_conn, msg, length);
		break;
	case BSS_MAP_MSG_ASSIGNMENT_FAILURE:
		ret = bssmap_ran_handle_assignment_failure(subscr_conn, msg, length);
		break;
	default:
		ret = bssap_fwd_to_cn(subscr_conn, msg, length);
		break;
	}

	return ret;
}

static int bssmap_rcvmsg_dt(enum bsc_nat_net net, struct subscr_conn *subscr_conn, struct msgb *msg,
				 unsigned int length)
{
	if (length < 1) {
		LOGP(DMAIN, LOGL_ERROR, "Not enough room: %u\n", length);
		return -1;
	}

	LOGP(DMAIN, LOGL_NOTICE, "Rx DT BSSMAP %s\n", gsm0808_bssmap_name(msg->l3h[0]));

	if (net == BSC_NAT_NET_CN)
		return bssmap_cn_rcvmsg_dt(subscr_conn, msg, length);
	return bssmap_ran_rcvmsg_dt(subscr_conn, msg, length);
}

int bssap_handle_dt(enum bsc_nat_net net, struct subscr_conn *subscr_conn, struct msgb *msgb, unsigned int length)
{
	struct bssmap_header *bs;
	int rc = -1;

	LOGP(DMAIN, LOGL_DEBUG, "Rx DT: %s\n", osmo_hexdump(msgb->l2h, length));

	if (length < sizeof(*bs)) {
		LOGP(DMAIN, LOGL_ERROR, "The header is too short\n");
		return -1;
	}

	switch (msgb->l2h[0]) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		bs = (struct bssmap_header *)msgb->l2h;
		if (bs->length < length - sizeof(*bs)) {
			LOGP(DMAIN, LOGL_ERROR, "Failed to parse BSSMAP header\n");
			return -1;
		}
		msgb->l3h = &msgb->l2h[sizeof(*bs)];
		rc = bssmap_rcvmsg_dt(net, subscr_conn, msgb, length - sizeof(*bs));
		break;
	case BSSAP_MSG_DTAP:
		LOGP(DMAIN, LOGL_DEBUG, "Rx DT DTAP\n");
		if (net == BSC_NAT_NET_CN)
			rc = bssap_fwd_to_ran(subscr_conn, msgb, length);
		else
			rc = bssap_fwd_to_cn(subscr_conn, msgb, length);
		break;
	default:
		LOGP(DMAIN, LOGL_ERROR, "%s(%s) is not implemented!\n", __func__, gsm0808_bssap_name(msgb->l2h[0]));
	}

	return rc;
}

static int bssmap_get_mi(struct osmo_mobile_identity *mi, struct msgb *msgb, unsigned int length)
{
	struct tlv_parsed tp;
	struct tlv_p_entry *e;
	struct msgb *dtap;
	unsigned char *pos;
	int rc;

	if (length < 1) {
		LOGP(DMAIN, LOGL_ERROR, "Not enough room: %u\n", length);
		return -1;
	}

	if (msg->l3h[0] != BSS_MAP_MSG_COMPLETE_LAYER_3) {
		LOGP(DMAIN, LOGL_ERROR, "%s(%s) is not implemented!\n", __func__, gsm0808_bssmap_name(msgb->l3h[0]));
		return -1;
	}

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 1, length - 1, 0, 0);

	if (!(e = TLVP_GET(&tp, GSM0808_IE_LAYER_3_INFORMATION))) {
		LOGP(DMAIN, LOGL_ERROR, "Missing IE: Layer 3 Information\n");
		return -1;
	}
	e->val

	dtap = msgb_alloc(len, "DTAP from Complete Layer 3 Information");
	pos = msgb_put(dtap, e->len);
	memcpy(pos, e->val, e->len);
	dtap->l3h = pos;
	rc = osmo_mobile_identity_decode_from_l3(&mi, msg, false);
	msgb_free(dtap);

	return rc;
}

int bssap_get_mi_from_cr(struct osmo_mobile_identity *mi, struct msgb *msgb, unsigned int length)
{
	struct bssmap_header *bs;

	LOGP(DMAIN, LOGL_DEBUG, "Rx CR: %s\n", osmo_hexdump(msgb->l2h, length));

	if (length < sizeof(*bs)) {
		LOGP(DMAIN, LOGL_ERROR, "The header is too short\n");
		return -1;
	}

	switch (msgb->l2h[0]) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		bs = (struct bssmap_header *)msgb->l2h;
		if (bs->length < length - sizeof(*bs)) {
			LOGP(DMAIN, LOGL_ERROR, "Failed to parse BSSMAP header\n");
			return -1;
		}
		msgb->l3h = &msgb->l2h[sizeof(*bs)];
		return bssmap_get_mi(mi, msgb, length - sizeof(*bs));
	default:
		LOGP(DMAIN, LOGL_ERROR, "%s(%s) is not implemented!\n", __func__, gsm0808_bssap_name(msgb->l2h[0]));
	}

	return -1;
}

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

static int bssmap_cn_rcvmsg_dt(struct subscr_conn *subscr_conn, struct msgb *msg, unsigned int length)
{
	int ret = 0;

	switch (msg->l3h[0]) {
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

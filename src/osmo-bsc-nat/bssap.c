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
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/logging.h>

static int bssap_ran_handle_reset(struct osmo_sccp_addr *addr, struct msgb *msg, unsigned int length)
{
	struct bsc_nat_sccp_inst *sccp_inst = g_bsc_nat->ran;

	LOGP(DMAIN, LOGL_NOTICE, "Rx RESET from %s\n", bsc_nat_print_addr(sccp_inst, addr));

	LOGP(DMAIN, LOGL_NOTICE, "Tx RESET ACK to %s\n", bsc_nat_print_addr(sccp_inst, addr));
	msg = gsm0808_create_reset_ack();
	return osmo_sccp_tx_unitdata_msg(sccp_inst->scu, &sccp_inst->addr, addr, msg);
}

static int bssap_ran_rcvmsg_udt(struct osmo_sccp_addr *addr, struct msgb *msg, unsigned int length)
{
	int ret = 0;

	switch (msg->l3h[0]) {
	case BSS_MAP_MSG_RESET:
		ret = bssap_ran_handle_reset(addr, msg, length);
		break;
	default:
		LOGP(DMAIN, LOGL_NOTICE, "Unimplemented BSSMAP UDT %s\n", gsm0808_bssap_name(msg->l3h[0]));
		break;
	}

	return ret;
}

static int bssap_rcvmsg_udt(struct bsc_nat_sccp_inst *sccp_inst, struct osmo_sccp_addr *addr, struct msgb *msg,
			    unsigned int length)
{
	if (length < 1) {
		LOGP(DMAIN, LOGL_ERROR, "Not enough room: %u\n", length);
		return -1;
	}

	LOGP(DMAIN, LOGL_NOTICE, "Rx UDT BSSMAP %s\n", gsm0808_bssap_name(msg->l3h[0]));

	/* NOTE: bssap_cn_rcvmsg_udt() will be added in a future patch */
	return bssap_ran_rcvmsg_udt(addr, msg, length);
}

int bssap_handle_udt(struct bsc_nat_sccp_inst *sccp_inst, struct osmo_sccp_addr *addr, struct msgb *msgb,
		      unsigned int length)
{
	struct bssmap_header *bs;
	int rc = -1;

	LOGP(DMAIN, LOGL_DEBUG, "Rx UDT: %s\n", osmo_hexdump(msgb->l2h, length));

	if (length < sizeof(*bs)) {
		LOGP(DMAIN, LOGL_ERROR, "The header is too short\n");
		return -1;
	}

	bs = (struct bssmap_header *)msgb->l2h;
	if (bs->length < length - sizeof(*bs)) {
		LOGP(DMAIN, LOGL_ERROR, "Failed to parse BSSMAP header\n");
		return -1;
	}

	switch (bs->type) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msgb->l3h = &msgb->l2h[sizeof(*bs)];
		rc = bssap_rcvmsg_udt(sccp_inst, addr, msgb, length - sizeof(*bs));
		break;
	default:
		LOGP(DMAIN, LOGL_NOTICE, "Unimplemented msg type: %s\n", gsm0808_bssap_name(bs->type));
	}

	return rc;
}

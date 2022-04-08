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

#pragma once

#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/bssap.h>

/* connection for one subscriber */
struct subscr_conn {
	struct llist_head list;
	struct osmo_fsm_inst *fi;
	struct osmo_mgcpc_ep *ep;
	uint32_t mgw_call_id;

	struct {
		uint32_t id;
		struct osmo_mgcpc_ep_ci *ci;
		struct msc *msc;
	} cn;

	struct {
		uint32_t id;
		struct osmo_mgcpc_ep_ci *ci;
		struct bsc *bsc;
	} ran;

	/* Copy of BSSMAP Assignment Request/Complete while being processed by
	 * subscr_conn_fsm. */
	struct {
		struct msgb *msg;
		struct osmo_sockaddr_str aoip_transp_addr;
	} ass;
};

int subscr_conn_get_next_id_ran();
int subscr_conn_get_next_id_mgw();

struct subscr_conn *subscr_conn_alloc(struct msc *msc, struct bsc *bsc, uint32_t id_cn, uint32_t id_ran);

struct subscr_conn *subscr_conn_get_by_id(uint32_t id, enum bsc_nat_net net);

int subscr_conn_rx_ass_req(struct subscr_conn *subscr_conn, const struct osmo_sockaddr_str *aoip_transp_addr,
			   struct msgb *msg);
int subscr_conn_rx_ass_compl(struct subscr_conn *subscr_conn, const struct osmo_sockaddr_str *aoip_transp_addr,
			     struct msgb *msg);

void subscr_conn_free(struct subscr_conn *subscr_conn);

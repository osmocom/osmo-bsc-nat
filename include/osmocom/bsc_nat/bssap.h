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

#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/bsc_nat/bsc_nat.h>

/* connection-less */
int bssap_handle_udt(struct bsc_nat_sccp_inst *sccp_inst, struct osmo_sccp_addr *addr, struct msgb *msgb,
		     unsigned int length);

int bssmap_tx_reset(struct bsc_nat_sccp_inst *sccp_inst, struct osmo_sccp_addr *addr);

/* connection-oriented */
struct subscr_conn;

int bssap_handle_dt(enum bsc_nat_net net, struct subscr_conn *subscr_conn, struct msgb *msgb, unsigned int length);

#define bssmap_tx_assignment_failure_cn(subscr_conn, cause) \
	bssmap_tx_assignment_failure(BSC_NAT_NET_CN, subscr_conn, cause)
#define bssmap_tx_assignment_failure_ran(subscr_conn, cause) \
	bssmap_tx_assignment_failure(BSC_NAT_NET_RAN, subscr_conn, cause)
int bssmap_tx_assignment_failure(enum bsc_nat_net net, struct subscr_conn *subscr_conn, enum gsm0808_cause cause);

int bssmap_replace_ie_aoip_transp_addr(struct msgb **msg, struct sockaddr_storage *ss);

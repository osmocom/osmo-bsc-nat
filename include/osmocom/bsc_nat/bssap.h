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
#include <osmocom/bsc_nat/bsc_nat.h>

/* connection-less */
int bssap_handle_udt(struct bsc_nat_sccp_inst *sccp_inst, struct osmo_sccp_addr *addr, struct msgb *msgb,
		     unsigned int length);

int bssmap_tx_reset(struct bsc_nat_sccp_inst *sccp_inst, struct osmo_sccp_addr *addr);

/* connection-oriented */
struct subscr_conn;

int bssap_handle_dt(enum bsc_nat_net net, struct subscr_conn *subscr_conn, struct msgb *msgb, unsigned int length);

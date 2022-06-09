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

#include <osmocom/core/fsm.h>
#include <osmocom/sigtran/sccp_sap.h>

struct msc {
	struct llist_head list;
	uint16_t id;
	struct osmo_sccp_addr *addr;
	struct osmo_fsm_inst *fi;
	struct osmo_nri_ranges *nri_ranges;
	bool allow_attach;
};

struct msc *msc_alloc(uint16_t id);

struct msc *msc_get_by_id(uint16_t id);

void msc_tx_reset(struct msc *msc);
void msc_rx_reset_ack(struct msc *msc);

bool msc_is_connected(struct msc *msc);

void msc_free(struct msc *msc);
void msc_free_subscr_conn_all(struct msc *msc);

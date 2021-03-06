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

#include <osmocom/sigtran/sccp_sap.h>

struct bsc {
	struct llist_head list;
	struct osmo_sccp_addr addr;
};

struct bsc *bsc_alloc(struct osmo_sccp_addr *addr);
struct bsc *bsc_get_by_pc(uint32_t pointcode);
void bsc_free(struct bsc *bsc);
void bsc_free_subscr_conn_all(struct bsc *bsc);

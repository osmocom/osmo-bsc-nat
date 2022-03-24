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

/* connection for one subscriber */
struct subscr_conn {
	struct llist_head list;

	struct {
		uint32_t id;
		struct msc *msc;
	} cn;

	struct {
		uint32_t id;
		struct bsc *bsc;
	} ran;
};

int subscr_conn_get_next_id(enum bsc_nat_net net);

struct subscr_conn *subscr_conn_alloc(struct msc *msc, struct bsc *bsc, uint32_t id_cn, uint32_t id_ran);

struct subscr_conn *subscr_conn_get_by_id(uint32_t id, enum bsc_nat_net net);

void subscr_conn_free(struct subscr_conn *subscr_conn);

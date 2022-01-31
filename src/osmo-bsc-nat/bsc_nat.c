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

#include "config.h"

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/bsc_nat/bsc_nat.h>

struct bsc_nat *bsc_nat_alloc(void *tall_ctx)
{
	struct bsc_nat *bsc_nat;

	bsc_nat = talloc_zero(tall_ctx, struct bsc_nat);
	OSMO_ASSERT(bsc_nat);

	return bsc_nat;
}

void bsc_nat_free(struct bsc_nat *bsc_nat)
{
	talloc_free(bsc_nat);
}

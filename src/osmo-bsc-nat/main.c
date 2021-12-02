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

#include <osmocom/core/application.h>
#include <osmocom/vty/cpu_sched_vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/telnet_interface.h>

#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/logging.h>
#include <osmocom/bsc_nat/vty.h>

static const char *const copyright =
	"OsmoBSCNAT - Osmocom BSC NAT\r\n"
	"Copyright (C) 2021 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>\r\n"
	"Author: Oliver Smith\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

void *tall_bsc_nat_ctx;
struct bsc_nat *g_bsc_nat;

static struct vty_app_info vty_info = {
	.name		= "OsmoBSCNAT",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_nat_vty_go_parent,
};

static void main_vty_init()
{
	int rc;

	vty_info.copyright = copyright;
	vty_info.tall_ctx = tall_bsc_nat_ctx;
	vty_init(&vty_info);

	bsc_nat_vty_init();

	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();
	osmo_cpu_sched_vty_init(tall_bsc_nat_ctx);

	rc = telnet_init_dynif(tall_bsc_nat_ctx, g_bsc_nat, vty_get_bind_addr(), OSMO_VTY_PORT_BSC_NAT);
	if (rc < 0) {
		perror("Error binding VTY port");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	int rc;

	talloc_enable_null_tracking();
	tall_bsc_nat_ctx = talloc_named_const(NULL, 0, "bsc_nat");

	rc = osmo_init_logging2(tall_bsc_nat_ctx, &bsc_nat_log_info);
	if (rc < 0)
		exit(1);

	g_bsc_nat = bsc_nat_alloc(tall_bsc_nat_ctx);

	main_vty_init();

	while (!osmo_select_shutdown_done())
		osmo_select_main_ctx(0);

	talloc_report_full(tall_bsc_nat_ctx, stderr);
	talloc_free(tall_bsc_nat_ctx);
	talloc_free(tall_vty_ctx);
	talloc_report_full(NULL, stderr);
	talloc_disable_null_tracking();

	return 0;
}

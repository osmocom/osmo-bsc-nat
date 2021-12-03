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

#include <getopt.h>

#include <osmocom/core/application.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/vty/cpu_sched_vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/telnet_interface.h>

#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/bsc_nat_fsm.h>
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

static struct {
	const char *config_file;
} bsc_nat_cmdline_config = {
	.config_file = "osmo-bsc-nat.cfg",
};

static void print_help()
{
	printf("usage: osmo-bsc-nat <options>\n");
	printf("\n");
	printf("optional arguments:\n");
	printf("  -h, --help            show this help message and exit\n");
	printf("  -c, --config-file     the config file to use\n");
	printf("  -V, --version         show version number and exit\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int idx = 0, c;
		static const struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"config-file", 1, 0, 'c'},
			{"version", 0, 0, 'V' },
			{ 0, 0, 0, 0 },
		};

		c = getopt_long(argc, argv, "hc:V", long_options, &idx);

		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 'c':
			bsc_nat_cmdline_config.config_file = optarg;
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		default:
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
			break;
		}
	}
}

static void main_vty_init(int argc, char **argv)
{
	int rc;

	vty_info.copyright = copyright;
	vty_info.tall_ctx = tall_bsc_nat_ctx;
	vty_init(&vty_info);

	bsc_nat_vty_init();

	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();
	osmo_fsm_vty_add_cmds();
	osmo_cpu_sched_vty_init(tall_bsc_nat_ctx);
	osmo_ss7_vty_init_asp(NULL);
	osmo_sccp_vty_init();

	handle_options(argc, argv);

	rc = vty_read_config_file(bsc_nat_cmdline_config.config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n",
			bsc_nat_cmdline_config.config_file);
		exit(1);
	}

	rc = telnet_init_dynif(tall_bsc_nat_ctx, g_bsc_nat, vty_get_bind_addr(), OSMO_VTY_PORT_BSC_NAT);
	if (rc < 0) {
		perror("Error binding VTY port");
		exit(1);
	}
}

static void signal_handler(int signum)
{
	fprintf(stdout, "signal %u received\n", signum);

	switch (signum) {
	case SIGINT:
	case SIGTERM:
		/* If SIGTERM was already sent before, just terminate immediately. */
		if (osmo_select_shutdown_requested())
			exit(-1);
		osmo_select_shutdown_request();
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report and
		 * then run default SIGABRT handler, who will generate coredump
		 * and abort the process. abort() should do this for us after we
		 * return, but program wouldn't exit if an external SIGABRT is
		 * received.
		 */
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_bsc_nat_ctx, stderr);
		signal(SIGABRT, SIG_DFL);
		raise(SIGABRT);
		break;
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_bsc_nat_ctx, stderr);
		break;
	default:
		break;
	}
}

static void signal_handler_init(void)
{
	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();
}

int main(int argc, char **argv)
{
	int rc;

	talloc_enable_null_tracking();
	tall_bsc_nat_ctx = talloc_named_const(NULL, 0, "bsc_nat");

	rc = osmo_init_logging2(tall_bsc_nat_ctx, &bsc_nat_log_info);
	if (rc < 0)
		exit(1);

	rc = osmo_ss7_init();
	if (rc < 0)
		exit(1);

	g_bsc_nat = bsc_nat_alloc(tall_bsc_nat_ctx);

	main_vty_init(argc, argv);
	signal_handler_init();

	bsc_nat_fsm_start(g_bsc_nat);

	while (!osmo_select_shutdown_done())
		osmo_select_main_ctx(0);

	bsc_nat_fsm_stop(g_bsc_nat);

	talloc_report_full(g_bsc_nat, stderr);
	bsc_nat_free(g_bsc_nat);
	log_fini();
	talloc_report_full(tall_bsc_nat_ctx, stderr);
	talloc_free(tall_bsc_nat_ctx);
	talloc_free(tall_vty_ctx);
	talloc_report_full(NULL, stderr);
	talloc_disable_null_tracking();

	return 0;
}

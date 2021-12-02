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

#include <unistd.h>

#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/command.h>

#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/vty.h>

int bsc_nat_vty_go_parent(struct vty *vty)
{
	switch (vty->node) {
	case BSC_NAT_NODE:
		vty->node = CONFIG_NODE;
		vty->index = g_bsc_nat;
		break;
	case CONFIG_NODE:
		vty->node = ENABLE_NODE;
		vty->index = NULL;
		break;
	default:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	}

	return vty->node;
}

static struct cmd_node bsc_nat_node = {
	BSC_NAT_NODE,
	"%s(config-bsc-nat)# ",
	1,
};

DEFUN(cfg_bsc_nat,
      cfg_bsc_nat_cmd,
      "bsc-nat", "Configure the BSC NAT\n")
{
	OSMO_ASSERT(g_bsc_nat);
	vty->index = g_bsc_nat;
	vty->node = BSC_NAT_NODE;

	return CMD_SUCCESS;
}

static int config_write_bsc_nat(struct vty *vty)
{
	vty_out(vty, "bsc-nat%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}


void bsc_nat_vty_init(void)
{
	install_element(CONFIG_NODE, &cfg_bsc_nat_cmd);
	install_node(&bsc_nat_node, config_write_bsc_nat);
}

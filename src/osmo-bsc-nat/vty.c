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
#include <osmocom/gsm/gsm23236.h>
#include <osmocom/mgcp_client/mgcp_client_pool.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/tdef_vty.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/bsc_nat/bsc_nat.h>
#include <osmocom/bsc_nat/vty.h>

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

void config_write_bsc_nat_nri(struct vty *vty)
{
	struct osmo_nri_range *r;

	if (g_bsc_nat->nri_bitlen != OSMO_NRI_BITLEN_DEFAULT)
		vty_out(vty, " nri bitlen %u%s", g_bsc_nat->nri_bitlen, VTY_NEWLINE);

	llist_for_each_entry(r, &g_bsc_nat->null_nri_ranges->entries, entry) {
		vty_out(vty, " nri null add %d", r->first);
		if (r->first != r->last)
			vty_out(vty, " %d", r->last);
		vty_out(vty, "%s", VTY_NEWLINE);
	}
}

static int config_write_bsc_nat(struct vty *vty)
{
	vty_out(vty, "bsc-nat%s", VTY_NEWLINE);
	vty_out(vty, " cs7-instance-cn %u%s", g_bsc_nat->cn.sccp_inst->ss7_id, VTY_NEWLINE);
	vty_out(vty, " cs7-instance-ran %u%s", g_bsc_nat->ran.sccp_inst->ss7_id, VTY_NEWLINE);

	config_write_bsc_nat_nri(vty);

	return CMD_SUCCESS;
}

#define SS7_REF_STR "SS7 instance reference number\n"

DEFUN(cfg_cs7_instance_cn,
      cfg_cs7_instance_cn_cmd,
      "cs7-instance-cn <0-15>",
      "Set SS7 to be used to connect to CN-side\n" SS7_REF_STR)
{
	g_bsc_nat->cn.sccp_inst->ss7_id = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_cs7_instance_ran,
      cfg_cs7_instance_ran_cmd,
      "cs7-instance-ran <0-15>",
      "Set SS7 to be used to connect to RAN-side\n" SS7_REF_STR)
{
	g_bsc_nat->ran.sccp_inst->ss7_id = atoi(argv[0]);
	return CMD_SUCCESS;
}

#define NRI_STR "Mapping of Network Resource Indicators for MSC pooling\n"
#define NULL_NRI_STR "Define NULL-NRI values that cause re-assignment of an MS to a different MSC, for MSC pooling.\n"
#define NRI_FIRST_LAST_STR "First value of the NRI value range, should not surpass the configured 'nri bitlen'.\n" \
	"Last value of the NRI value range, should not surpass the configured 'nri bitlen' and be larger than the" \
	" first value; if omitted, apply only the first value.\n"
#define NRI_ARGS_TO_STR_FMT "%s%s%s"
#define NRI_ARGS_TO_STR_ARGS(ARGC, ARGV) ARGV[0], (ARGC > 1) ? ".." : "", (ARGC > 1) ? ARGV[1] : ""
#define NRI_WARN(MSC, FORMAT, args...) do { \
		vty_out(vty, "%% Warning: msc %d: " FORMAT "%s", MSC->nr, ##args, VTY_NEWLINE); \
		LOGP(DMSC, LOGL_ERROR, "msc %d: " FORMAT "\n", MSC->nr, ##args); \
	} while (0)

DEFUN_ATTR(cfg_nri_bitlen,
	   cfg_nri_bitlen_cmd,
	   "nri bitlen <1-15>",
	   NRI_STR
	   "Set number of bits that an NRI has, to extract from TMSI identities (always starting just after the TMSI's most significant octet).\n"
	   "bit count (default: " OSMO_STRINGIFY_VAL(OSMO_NRI_BITLEN_DEFAULT) ")\n",
	   CMD_ATTR_IMMEDIATE)
{
	g_bsc_nat->nri_bitlen = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_nri_null_add,
	   cfg_nri_null_add_cmd,
	   "nri null add <0-32767> [<0-32767>]",
	   NRI_STR NULL_NRI_STR "Add NULL-NRI value (or range)\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	int rc;
	const char *message;
	rc = osmo_nri_ranges_vty_add(&message, NULL, g_bsc_nat->null_nri_ranges, argc, argv,
				     g_bsc_nat->nri_bitlen);
	if (message) {
		vty_out(vty, "%% %s: " NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	}
	if (rc < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_nri_null_del,
	   cfg_nri_null_del_cmd,
	   "nri null del <0-32767> [<0-32767>]",
	   NRI_STR NULL_NRI_STR "Remove NRI value or range from the NRI mapping\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	int rc;
	const char *message;
	rc = osmo_nri_ranges_vty_del(&message, NULL, g_bsc_nat->null_nri_ranges, argc, argv);
	if (message) {
		vty_out(vty, "%% %s: " NRI_ARGS_TO_STR_FMT "%s", message, NRI_ARGS_TO_STR_ARGS(argc, argv),
			VTY_NEWLINE);
	}
	if (rc < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN(show_nri, show_nri_cmd,
      "show nri [" MSC_NR_RANGE "]",
      SHOW_STR NRI_STR "Optional MSC number to limit to\n")
{
	struct msc *msc;
	if (argc > 0) {
		uint16_t msc_id = atoi(argv[0]);
		msc = msc_get_by_id(msc_id);
		if (!msc) {
			vty_out(vty, "%% No such MSC%s", VTY_NEWLINE);
			return CMD_SUCCESS;
		}
		msc_write_nri(vty, msc, true);
		return CMD_SUCCESS;
	}

	llist_for_each_entry(msc, &g_bsc_nat->cn.mscs, list) {
		msc_write_nri(vty, msc, true);
	}
	return CMD_SUCCESS;
}

static struct cmd_node msc_node = {
	MSC_NODE,
	"%s(config-msc)# ",
	1,
};

#define MSC_NR_RANGE "<0-1000>"

DEFUN_ATTR(cfg_msc,
	   cfg_msc_cmd,
	   "msc [" MSC_NR_RANGE "]", "Configure MSC details\n" "MSC connection to configure\n",
	   CMD_ATTR_IMMEDIATE)
{
	int index = argc == 1 ? atoi(argv[0]) : 0;
	struct msc *msc;

	msc = msc_alloc(index);
	if (!msc) {
		vty_out(vty, "%% Failed to allocate MSC data.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->index = msc;
	vty->node = MSC_NODE;
	return CMD_SUCCESS;
}

static void config_write_msc_nri(struct vty *vty, struct msc *msc, bool verbose)
{
	struct osmo_nri_range *r;

	if (verbose) {
		vty_out(vty, "msc " PRIu16 "%s", msc->id, VTY_NEWLINE);
		if (llist_empty(&msc->nri_ranges->list)) {
			vty_out(vty, " %% no NRI mappings%s", VTY_NEWLINE);
			return;
		}
	}

	llist_for_each_entry(r, &msc->nri_ranges->entries, list) {
		if (osmo_nri_range_validate(r, 255))
			vty_out(vty, " %% INVALID RANGE:");
		vty_out(vty, " nri add %d", r->first);
		if (r->first != r->last)
			vty_out(vty, " %d", r->last);
		vty_out(vty, "%s", VTY_NEWLINE);
	}
}

static int config_write_msc(struct vty *vty)
{
	struct msc *msc;

	llist_for_each_entry(msc, &g_bsc_nat->mscs, list) {
		vty_out(vty, "msc " PRIu16 "%s", msc->id, VTY_NEWLINE);

		if (msc->addr_name)
			vty_out(vty, " msc-addr %s%s", msc->addr_name, VTY_NEWLINE);

		config_write_msc_nri(vty, msc, false);

		if (!msc->allow_attach)
			vty_out(vty, " no allow-attach%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_msc_cs7_msc_addr,
      cfg_msc_cs7_msc_addr_cmd,
      "msc-addr NAME",
      "Called Address (remote address of the MSC)\n" "SCCP address name\n")
{
	struct msc *msc = vty->index;
	const char *addr_name = argv[0];

	struct osmo_sccp_addr addr;

	if (osmo_sccp_addr_by_name_local(&addr, addr_name, g_bsc_nat->cn.sccp_inst->ss7_inst) < 0) {
		vty_out(vty, "Error: No such SCCP addressbook entry: '%s'%s", addr_name, VTY_NEWLINE);
		return CMD_ERR_INCOMPLETE;
	}

	if (msc->addr)
		talloc_free(msc->addr);
	msc->addr = talloc_memdup(msc, &addr, sizeof(addr));
	OSMO_ASSERT(msc->addr);

	if (msc->addr_name)
		talloc_free(msc->addr_name);
	msc->addr_name = talloc_strdup(msc, addr_name);
	OSMO_ASSERT(msc->addr_name);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_msc_nri_add, cfg_msc_nri_add_cmd,
	   "nri add <0-32767> [<0-32767>]",
	   NRI_STR "Add NRI value or range to the NRI mapping for this MSC\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct msc *msc = vty->index;
	struct msc *other_msc;
	bool before;
	int rc;
	const char *message;
	struct osmo_nri_range add_range;

	rc = osmo_nri_ranges_vty_add(&message, &add_range, msc->nri_ranges, argc, argv, g_bsc_nat->nri_bitlen);
	if (message) {
		NRI_WARN(msc, "%s: " NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	}
	if (rc < 0)
		return CMD_WARNING;

	/* Issue a warning about NRI range overlaps (but still allow them).
	 * Overlapping ranges will map to whichever MSC comes fist in the g_bsc_nat->cn.mscs llist,
	 * which is not necessarily in the order of increasing msc->nr. */
	before = true;
	llist_for_each_entry(other_msc, &g_bsc_nat->cn.mscs, entry) {
		if (other_msc == msc) {
			before = false;
			continue;
		}
		if (osmo_nri_range_overlaps_ranges(&add_range, other_msc->nri_ranges)) {
			NRI_WARN(msc, "NRI range [%d..%d] overlaps between msc %d and msc %d."
				 " For overlaps, msc %d has higher priority than msc %d",
				 add_range.first, add_range.last, msc->nr, other_msc->nr,
				 before ? other_msc->nr : msc->nr, before ? msc->nr : other_msc->nr);
		}
	}
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_msc_nri_del, cfg_msc_nri_del_cmd,
	   "nri del <0-32767> [<0-32767>]",
	   NRI_STR "Remove NRI value or range from the NRI mapping for this MSC\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct msc *msc = vty->index;
	int rc;
	const char *message;

	rc = osmo_nri_ranges_vty_del(&message, NULL, msc->nri_ranges, argc, argv);
	if (message) {
		NRI_WARN(msc, "%s: " NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	}
	if (rc < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_show_nri, cfg_msc_show_nri_cmd,
      "show nri",
      SHOW_STR NRI_STR)
{
	struct msc *msc = vty->index;
	msc_write_nri(vty, msc, true);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_msc_allow_attach, cfg_msc_allow_attach_cmd,
	   "allow-attach",
	   "Allow this MSC to attach new subscribers (default).\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct msc *msc = vty->index;
	msc->allow_attach = true;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_msc_no_allow_attach, cfg_msc_no_allow_attach_cmd,
	   "no allow-attach",
	   NO_STR
	   "Do not assign new subscribers to this MSC."
	   " Useful if an MSC in an MSC pool is configured to off-load subscribers."
	   " The MSC will still be operational for already IMSI-Attached subscribers,"
	   " but the NAS node selection function will skip this MSC for new subscribers\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct msc *msc = vty->index;
	msc->allow_attach = false;
	return CMD_SUCCESS;
}

void bsc_nat_vty_init(void)
{
	install_element(CONFIG_NODE, &cfg_bsc_nat_cmd);
	install_element(CONFIG_NODE, &cfg_msc_cmd);

	install_node(&bsc_nat_node, config_write_bsc_nat);
	install_element(BSC_NAT_NODE, &cfg_cs7_instance_cn_cmd);
	install_element(BSC_NAT_NODE, &cfg_cs7_instance_ran_cmd);
	install_element(BSC_NAT_NODE, &cfg_nri_bitlen_cmd);
	install_element(BSC_NAT_NODE, &cfg_nri_null_add_cmd);
	install_element(BSC_NAT_NODE, &cfg_nri_null_del_cmd);

	install_node(&msc_node, config_write_msc);
	install_element(MSC_NODE, &cfg_msc_cs7_bsc_nat_addr_cmd);
	install_element(MSC_NODE, &cfg_msc_cs7_msc_addr_cmd);
	install_element(MSC_NODE, &cfg_msc_nri_add_cmd);
	install_element(MSC_NODE, &cfg_msc_nri_del_cmd);
	install_element(MSC_NODE, &cfg_msc_show_nri_cmd);
	install_element(MSC_NODE, &cfg_msc_allow_attach_cmd);
	install_element(MSC_NODE, &cfg_msc_no_allow_attach_cmd);

	install_element_ve(&show_nri_cmd);

	osmo_tdef_vty_groups_init(CONFIG_NODE, g_bsc_nat_tdef_group);

	mgcp_client_pool_vty_init(CONFIG_NODE, MGW_NODE, "", g_bsc_nat->mgw.pool);
}

#!/usr/bin/env python3

# (C) 2021 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

app_configs = {
    "osmo-bsc-nat": ["doc/examples/osmo-bsc-nat/osmo-bsc-nat.cfg"]
}

apps = [(4244, "src/osmo-bsc-nat/osmo-bsc-nat", "OsmoBSCNAT", "osmo-bsc-nat")
        ]

vty_command = ["./src/osmo-bsc-nat/osmo-bsc-nat", "-c",
               "doc/examples/osmo-bsc-nat/osmo-bsc-nat.cfg"]

vty_app = apps[0]

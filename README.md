osmo-bsc-nat
===========================================

OsmoBSCNAT masquerades multiple BSCs behind one. It is part of the
[Osmocom](https://osmocom.org/) Open Source Mobile Communications project.

Homepage
--------

The official homepage of the project is
https://osmocom.org/projects/osmo-bscnat/wiki

GIT Repository
--------------

You can clone from the official osmo-bsc-nat.git repository using

	git clone git://git.osmocom.org/osmo-bsc-nat.git

There is a cgit interface at https://git.osmocom.org/osmo-bsc-nat/

Documentation
-------------

User Manuals and VTY reference manuals are optionally built in PDF form
as part of the build process.

Pre-rendered PDF version of the current "master" can be found at
[User Manual](https://ftp.osmocom.org/docs/latest/osmobscnat-usermanual.pdf)
as well as the [VTY Reference Manual](https://ftp.osmocom.org/docs/latest/osmobscnat-vty-reference.pdf)


Mailing List
------------

Discussions related to osmo-bsc-nat are happening on the
openbsc@lists.osmocom.org mailing list, please see
https://lists.osmocom.org/mailman/listinfo/openbsc for subscription
options and the list archive.

Please observe the
[Osmocom Mailing List Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Manual Testing With osmo-dev
----------

With [osmo-dev](https://git.osmocom.org/osmo-dev/) it is possible to
build all Osmocom components for a full test network with OsmoBSCNAT,
and run the network on your PC. Set up the make directory as described
in osmo-dev's README, then build components with:

```
$ make cn-bsc-nat
```

Set up a network as described in osmo-dev's net/README, then put the
following in your configuration to let it run osmo-bsc-nat with one
virtual BSC, BTS and MS (can be used next to a real BSC/BTS/MS):

```
BSC_COUNT=2
BTS1_RUN_IN_OSMO_DEV=1
STP_RAN_IP="127.0.0.2"
MS_RUN_IN_OSMO_DEV=1
```

Contributing
------------

Our coding standards are described at
https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards

We us a gerrit based patch submission/review process for managing
contributions.  Please see
https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit for
more details

The current patch queue for osmo-bsc-nat can be seen at
https://gerrit.osmocom.org/#/q/project:osmo-bsc-nat+status:open

EXTRA_DIST = \
    osmobscnat-usermanual.adoc \
    osmobscnat-usermanual-docinfo.xml \
    osmobscnat-vty-reference.xml \
    chapters \
    regen_doc.sh \
    vty

if BUILD_MANUALS
  ASCIIDOC = osmobscnat-usermanual.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc
  osmobscnat-usermanual.pdf: $(srcdir)/chapters/*.adoc

# TODO: enable once we have VTY available in osmo-bsc-nat
#  VTY_REFERENCE = osmobscnat-vty-reference.xml

#  BUILT_REFERENCE_XML = $(builddir)/vty/bsc_nat_vty_reference.xml
#  $(builddir)/vty/bsc_nat_vty_reference.xml: $(top_builddir)/src/osmo-bsc-nat/osmo-bsc-nat
#	mkdir -p $(builddir)/vty
#	$(top_builddir)/src/osmo-bsc-nat/osmo-bsc-nat --vty-ref-xml > $@

#  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  OSMO_REPOSITORY = osmo-bsc-nat
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif

#
# Makefile for Provenance LSM
#
obj-$(CONFIG_SECURITY_PROVENANCE) := provenance.o

provenance-y := hooks.o propagate.o

ccflags-y := -I$(srctree)/security/provenance/include

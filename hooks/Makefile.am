hooksdir=@LXCHOOKDIR@
binhooksdir=@LXCBINHOOKDIR@

hooks_SCRIPTS = \
	clonehostname \
	mountecryptfsroot \
	ubuntu-cloud-prep \
	dhclient-script \
	dhclient \
	squid-deb-proxy-client \
	nvidia

binhooks_PROGRAMS = unmount-namespace \
		    cgroup-mount

unmount_namespace_SOURCES = unmount-namespace.c
cgroup_mount_SOURCES = cgroup-mount.c

if IS_BIONIC
unmount_namespace_SOURCES += \
	../src/include/lxcmntent.c ../src/include/lxcmntent.h
endif

EXTRA_DIST=$(hooks_SCRIPTS)

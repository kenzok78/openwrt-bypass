#
# Copyright (C) 2025 Yannick Chabanois (Ycarus) for OpenMPTCProuter
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

#
# Copyright (C) 2024 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

#
# Copyright (C) 2024 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bpftune
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/oracle/bpftune.git
PKG_SOURCE_VERSION:=HEAD
PKG_MIRROR_HASH:=skip

PKG_MAINTAINER:=Ycarus
PKG_LICENSE:=GPL-2.0-only WITH Linux-syscall-note
PKG_LICENSE_FILES:=LICENSE.txt

PKG_BUILD_PARALLEL:=
PKG_INSTALL:=1
PKG_BUILD_DEPENDS:=bpftool/host

include $(INCLUDE_DIR)/package.mk

define Package/bpftune
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=BPF-based auto-tuning for Linux systems
  URL:=https://github.com/oracle/bpftune
  DEPENDS:=+libbpf +libcap +libnl +kmod-sched-bpf @KERNEL_BPF_EVENTS @KERNEL_DEBUG_INFO_BTF
  DEPENDS+=+PACKAGE_bpftune:bpftool
endef

define Package/bpftune/description
  bpftune uses BPF to auto-tune Linux system parameters.
  It provides lightweight, always-on auto-tuning of system behaviour
  by using BPF observability features to continuously monitor and
  adjust system parameters like TCP buffer sizes, congestion control,
  neighbour tables, and more.
endef

define Package/bpftune/config
  config BPFTUNE_MINIMAL
    bool "Build minimal version (without documentation)"
    depends on PACKAGE_bpftune
    default y
    help
	Build bpftune without documentation to reduce build dependencies.
endef

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/libnl3
TARGET_LDFLAGS += -lbpf -lcap -lnl-3 -lnl-route-3

MAKE_FLAGS += \
	V=1 \
	CC="$(TARGET_CC)" \
	CFLAGS="$(TARGET_CFLAGS) -fPIC -std=gnu99 -D_POSIX_C_SOURCE=200809L -I$(PKG_BUILD_DIR)/include -I$(PKG_BUILD_DIR)/src -I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/usr/include/libnl3 -I$(PKG_BUILD_DIR)/include/uapi" \
	LDFLAGS="$(TARGET_LDFLAGS) -L$(PKG_BUILD_DIR)/src" \
	CLANG="clang" \
	LLC="llc" \
	BPFTOOL="$(STAGING_DIR_HOST)/usr/sbin/bpftool" \
	GCC_BPF="" \
	OPATH="" \
    prefix=/usr \
    sbindir=/usr/sbin \
    libdir=/usr/lib

ifeq ($(CONFIG_BPFTUNE_MINIMAL),y)
MAKE_FLAGS += NO_DOCS=1
endif

define Build/Configure
	# bpftune uses a simple Makefile, no configure needed
endef

define Build/Compile
	+$(MAKE_VARS) $(MAKE) -C $(PKG_BUILD_DIR) \
	$(MAKE_FLAGS) \
	all
endef

define Build/Install
	+$(MAKE_VARS) $(MAKE) -C $(PKG_BUILD_DIR) \
	$(MAKE_FLAGS) \
	DESTDIR="$(PKG_INSTALL_DIR)" \
	install
endef

define Package/bpftune/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/bpftune $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/usr/lib/bpftune
	$(CP) $(PKG_BUILD_DIR)/src/libbpftune.so* $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/src/*.so $(1)/usr/lib/bpftune/
	$(CP) ./files/* $(1)/
endef

define Package/bpftune/conffiles
/etc/config/bpftune
endef

define Package/bpftune/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
    echo "Enabling bpftune service..."
    /etc/init.d/bpftune enable
    echo "To start bpftune, run: /etc/init.d/bpftune start"
}
exit 0
endef

define Package/bpftune/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
    echo "Stopping bpftune service..."
    /etc/init.d/bpftune stop
    /etc/init.d/bpftune disable
}
exit 0
endef

$(eval $(call BuildPackage,bpftune))
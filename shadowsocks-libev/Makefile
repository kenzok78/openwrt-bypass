#
# Copyright (C) 2017-2018 Yousong Zhou <yszhou4tech@gmail.com>
# Copyright (C) 2018-2021 Ycarus (Yannick Chabanois) <ycarus@zugaina.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

# Checklist when bumping versions
#
# - update cipher list by checking src/crypto.c:crypto_init()
# - check if default mode has changed from being tcp_only
#
PKG_NAME:=shadowsocks-libev
PKG_RELEASE:=11
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/Ysurac/shadowsocks-libev.git
PKG_SOURCE_VERSION:=410950d87d8cdf8502d8f59a79dc0ff4c7677543
PKG_VERSION:=3.3.5

PKG_MAINTAINER:=Ycarus (Yannick Chabanois) <ycarus@zugaina.org>

PKG_LICENSE:=GPL-3.0+
PKG_LICENSE_FILES:=LICENSE

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1
PKG_USE_MIPS16:=0
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/shadowsocks-libev-config
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=shadowsocks-libev config scripts
  URL:=https://github.com/shadowsocks/shadowsocks-libev
endef

define Package/shadowsocks-libev-config/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/shadowsocks-libev.config $(1)/etc/config/shadowsocks-libev
endef


define Package/shadowsocks-libev/Default
  define Package/shadowsocks-libev-$(1)
    SECTION:=net
    CATEGORY:=Network
    SUBMENU:=Web Servers/Proxies
    TITLE:=shadowsocks-libev $(1)
    URL:=https://github.com/shadowsocks/shadowsocks-libev
    DEPENDS:=+libcares +libev +libmbedtls +libpcre2 +libpthread +libsodium +shadowsocks-libev-config +zlib +libpcap +libcap +libstdcpp +libelf
  endef

  define Package/shadowsocks-libev-$(1)/install
	$$(INSTALL_DIR) $$(1)/usr/bin
	$$(INSTALL_BIN) $$(PKG_INSTALL_DIR)/usr/bin/$(1) $$(1)/usr/bin
  endef

endef

SHADOWSOCKS_COMPONENTS:=ss-local ss-redir ss-tunnel ss-server
define shadowsocks-libev/templates
  $(foreach component,$(SHADOWSOCKS_COMPONENTS),
    $(call Package/shadowsocks-libev/Default,$(component))
  )
endef
$(eval $(call shadowsocks-libev/templates))


define Package/shadowsocks-libev-ss-rules
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=shadowsocks-libev ss-rules
  URL:=https://github.com/shadowsocks/shadowsocks-libev
  DEPENDS:=+ip +ipset +iptables-mod-tproxy +resolveip +shadowsocks-libev-ss-redir +shadowsocks-libev-config
endef

define Package/shadowsocks-libev-ss-rules/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/ss-rules $(1)/usr/bin
	$(INSTALL_BIN) ./files/ss-rules6 $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) ./files/firewall.ss-rules $(1)/etc
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/ss-rules.defaults $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/shadowsocks-libev.init $(1)/etc/init.d/shadowsocks-libev

#	$(INSTALL_DIR) $(1)/etc/sysctl.d
#	$(INSTALL_DATA) ./files/shadowsocks.conf $(1)/etc/sysctl.d
#	$(INSTALL_DIR) $(1)/usr/lib/shadowsocks-libev
#	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/*.ebpf $(1)/usr/lib/shadowsocks-libev
endef

define Package/shadowsocks-libev-ss-rules/prerm
#!/bin/sh
s=firewall.ss_rules
uci get "$$s" >/dev/null || exit 0
uci batch <<-EOF
	delete $$s
	commit firewall
EOF
endef

define Package/shadowsocks-libev-ss-rules-nft
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=shadowsocks-libev ss-rules NFT
  URL:=https://github.com/shadowsocks/shadowsocks-libev
  DEPENDS:=+firewall4 \
       +ip \
       +resolveip \
       +ucode \
       +ucode-mod-fs \
       +shadowsocks-libev-ss-redir \
       +shadowsocks-libev-config \
       +kmod-nft-tproxy \
       @!LINUX_5_4
endef


define Package/shadowsocks-libev-ss-rules-nft/install
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/ss-rules.defaults $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/shadowsocks-libev.init-nft $(1)/etc/init.d/shadowsocks-libev
	$(INSTALL_DIR) $(1)/usr/share/ss-rules
	$(INSTALL_DATA) ./files/nft-rules/* $(1)/usr/share/ss-rules/
endef


define Build/Prepare
	$(call Build/Prepare/Default)
	$(FIND) $(PKG_BUILD_DIR) \
			   -name '*.o' \
			-o -name '*.lo' \
			-o -name '.deps' \
			-o -name '.libs' \
		| $(XARGS) rm -rvf
endef

CONFIGURE_ARGS += \
	--disable-documentation \
	--disable-silent-rules \
	--disable-assert \
	--disable-ssp \

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include

$(eval $(call BuildPackage,shadowsocks-libev-config))
$(eval $(call BuildPackage,shadowsocks-libev-ss-rules))
$(eval $(call BuildPackage,shadowsocks-libev-ss-rules-nft))
$(foreach component,$(SHADOWSOCKS_COMPONENTS), \
  $(eval $(call BuildPackage,shadowsocks-libev-$(component))) \
)

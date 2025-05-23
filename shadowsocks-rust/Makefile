# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2017-2020 Yousong Zhou <yszhou4tech@gmail.com>
# Copyright (C) 2021-2023 ImmortalWrt.org
# Copyright (C) 2023-2025 Yannick Chabanois (Ycarus) for OpenMPTCProuter

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=shadowsocks-rust
PKG_VERSION:=1.23.4
PKG_HASH:=8a91836256989e3a56409d0e83da6549ecf727e2d6642cd4e707993d9c8a23d3
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/shadowsocks/shadowsocks-rust/tar.gz/v$(PKG_VERSION)?

PKG_MAINTAINER:=Yannick Chabanois <contact@openmptcprouter.com>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DEPENDS:=rust/host

RUST_PKG_FEATURES:=local-redir

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/openmptcprouter/rust/rust-package.mk
ifeq ($(ARCH),i386)
    RUSTC_LDFLAGS+=-C target-feature=+sse2
endif

define Package/shadowsocks-rust/Default
  define Package/shadowsocks-rust-$(1)
    SECTION:=net
    CATEGORY:=Network
    SUBMENU:=Web Servers/Proxies
    TITLE:=shadowsocks-rust $(1)
    URL:=https://github.com/shadowsocks/shadowsocks-rust
    DEPENDS:=$$(RUST_ARCH_DEPENDS)
  endef

  define Package/shadowsocks-rust-$(1)/install
	$$(INSTALL_DIR) $$(1)/usr/bin
	$$(INSTALL_BIN) $$(PKG_INSTALL_DIR)/bin/$(1) $$(1)/usr/bin/
  endef
endef

define Package/shadowsocks-rust-config
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=shadowsocks-rust config
  URL:=https://github.com/shadowsocks/shadowsocks-rust
endef


define Package/shadowsocks-rust-config/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/ssr-rules $(1)/usr/bin
	$(INSTALL_BIN) ./files/ssr-rules6 $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_DATA) ./files/firewall.ssr-rules $(1)/etc
	$(INSTALL_BIN) ./files/ssr-rules.defaults $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/shadowsocks-rust.config $(1)/etc/config/shadowsocks-rust
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/shadowsocks-rust.init $(1)/etc/init.d/shadowsocks-rust
endef

define Package/shadowsocks-rust-config-nft
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=shadowsocks-rust config
  URL:=https://github.com/shadowsocks/shadowsocks-rust
  DEPENDS:=+firewall4 \
       +ip \
       +resolveip \
       +ucode \
       +ucode-mod-fs \
       +kmod-nft-tproxy \
       @!LINUX_5_4
endef


define Package/shadowsocks-rust-config-nft/install
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/ssr-rules.defaults $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/shadowsocks-rust.config $(1)/etc/config/shadowsocks-rust
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/shadowsocks-rust.init-nft $(1)/etc/init.d/shadowsocks-rust
	$(INSTALL_DIR) $(1)/usr/share/ssr-rules
	$(INSTALL_DATA) ./files/nft-rules/* $(1)/usr/share/ssr-rules/
endef



SHADOWSOCKS_COMPONENTS:=sslocal ssmanager ssserver ssurl ssservice
define shadowsocks-rust/templates
  $(foreach component,$(SHADOWSOCKS_COMPONENTS),
    $(call Package/shadowsocks-rust/Default,$(component))
  )
endef
$(eval $(call shadowsocks-rust/templates))

$(eval $(call BuildPackage,shadowsocks-rust-config))
$(eval $(call BuildPackage,shadowsocks-rust-config-nft))
$(foreach component,$(SHADOWSOCKS_COMPONENTS), \
  $(eval $(call BuildPackage,shadowsocks-rust-$(component))) \
)

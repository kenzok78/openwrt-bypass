# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2021-2022 ImmortalWrt.org
# Copyright (C) 2022-2025 Ycarus (Yannick Chabanois) for OpenMPTCProuter.com (contact@openmptcprouter.com)

include $(TOPDIR)/rules.mk

PKG_NAME:=v2ray-core
PKG_VERSION:=5.32.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/v2fly/v2ray-core.git
PKG_SOURCE_VERSION:=a4f28a2f6f01e871916fef06f2919b41880da78b

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Tianling Shen <cnsztl@immortalwrt.org>

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
♯PKG_USE_MIPS16:=0
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/v2fly/v2ray-core/v5
GO_PKG_BUILD_PKG:=$(GO_PKG)/main
GO_PKG_LDFLAGS_X:= \
	$(GO_PKG).build=OpenWrt \
	$(GO_PKG).version=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/openmptcprouter/golang/golang-package.mk

define Package/v2ray/template
  TITLE:=A platform for building proxies to bypass network restrictions
  SECTION:=net
  CATEGORY:=Network
  URL:=https://www.v2fly.org
endef

define Package/v2ray-core
  $(call Package/v2ray/template)
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
endef

define Package/v2ray-example
  $(call Package/v2ray/template)
  TITLE+= (example configs)
  DEPENDS:=v2ray-core
  PKGARCH:=all
endef

define Package/v2ray-extra
  $(call Package/v2ray/template)
  TITLE+= (extra resources)
  DEPENDS:=v2ray-core
  PKGARCH:=all
endef

define Package/v2ray-config
  $(call Package/v2ray/template)
  TITLE+= (init script)
  DEPENDS:=v2ray-core
  PKGARCH:=all
endef

define Package/v2ray-config-nft
  $(call Package/v2ray/template)
  TITLE+= (init script with nft)
  DEPENDS:=v2ray-core
  PKGARCH:=all
endef

define Package/v2ray/description
  Project V is a set of network tools that help you to build your own computer network.
  It secures your network connections and thus protects your privacy.
endef

define Package/v2ray-core/description
  $(call Package/v2ray/description)
endef

define Package/v2ray-example/description
  $(call Package/v2ray/description)

  This includes example configuration files for v2ray-core.
endef

define Package/v2ray-extra/description
  $(call Package/v2ray/description)

  This includes extra resources for v2ray-core.
endef

define Package/v2ray-config/description
  $(call Package/v2ray/description)

  This includes init script
endef

define Package/v2ray-config-nft/description
  $(call Package/v2ray/description)

  This includes init script with nftables support
endef

define Package/v2ray-core/conffiles
/etc/config/v2ray
/etc/v2ray/
endef

define Package/v2ray-core/install
	$(call GoPackage/Package/Install/Bin,$(PKG_INSTALL_DIR))
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/main $(1)/usr/bin/v2ray

	$(INSTALL_DIR) $(1)/etc/v2ray/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/release/config/config.json $(1)/etc/v2ray/
endef


define Package/v2ray-config/install
	$(CP) ./files/* $(1)/
	rm $(1)/etc/init.d/v2ray-nft
endef

define Package/v2ray-config-nft/install
	$(CP) ./files/* $(1)/
	mv $(1)/etc/init.d/v2ray-nft $(1)/etc/init.d/v2ray
endef

define Package/v2ray-example/install
	$(INSTALL_DIR) $(1)/etc/v2ray/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/release/config/vpoint_socks_vmess.json $(1)/etc/v2ray/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/release/config/vpoint_vmess_freedom.json $(1)/etc/v2ray/
endef

define Package/v2ray-extra/install
	$(INSTALL_DIR) $(1)/usr/share/v2ray/
	$(CP) $(PKG_BUILD_DIR)/release/extra/* $(1)/usr/share/v2ray/
endef

$(eval $(call BuildPackage,v2ray-core))
$(eval $(call BuildPackage,v2ray-config))
$(eval $(call BuildPackage,v2ray-config-nft))
$(eval $(call BuildPackage,v2ray-example))
$(eval $(call BuildPackage,v2ray-extra))

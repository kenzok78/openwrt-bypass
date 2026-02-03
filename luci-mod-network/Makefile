#
# Copyright (C) 2008-2014 The LuCI Team <luci@lists.subsignal.org>
# Copyright (C) 2020-2021 Ycarus (Yannick Chabanois) <ycarus@zugaina.org> for OpenMPTCProuter
#
# This is free software, licensed under the Apache License, Version 2.0 .
#
# From https://github.com/openwrt/luci/commit/bc2d7b5b1ae2f70aacca4d9a7597bef5ef75c8f1

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI Network Administration
LUCI_DEPENDS:=+luci-base +libiwinfo-lua +rpcd-mod-iwinfo +luci-lib-uqr

PKG_LICENSE:=Apache-2.0

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature


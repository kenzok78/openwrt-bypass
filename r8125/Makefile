# Attribution: https://gist.github.com/lenew/9b41ba901c3393047ede0766760f9d55

#Put this source to 'package/lean/r8125' folder of OpenWRT/LEDE SDK
#Build(make menuconfig, make defconfig, make)

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=r8125
PKG_VERSION:=9.013.02-2
PKG_RELEASE:=$(AUTORELEASE)


PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/awesometic/realtek-r8125-dkms/tar.gz/$(PKG_VERSION)?
PKG_HASH:=eae10100680de13e8119602c50a1748b8a0669eccd61d9a4515b4c846deb3960
PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/realtek-$(PKG_NAME)-dkms-$(PKG_VERSION)
PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define KernelPackage/r8125
  TITLE:=Driver for Realtek r8125 chipsets
  SUBMENU:=Network Devices
  VERSION:=$(LINUX_VERSION)+$(PKG_VERSION)-$(BOARD)-$(PKG_RELEASE)
  FILES:= $(PKG_BUILD_DIR)/src/r8125.ko
  DEPENDS:=@!LINUX_6_10
  AUTOLOAD:=$(call AutoProbe,r8125)
endef

define Package/r8125/description
  This package contains a driver for Realtek r8125 chipsets.
endef

define Build/Compile
	+$(KERNEL_MAKE) M=$(PKG_BUILD_DIR)/src modules
endef

$(eval $(call KernelPackage,r8125))

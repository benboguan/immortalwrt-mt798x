#
# Copyright (C) hanwckf <hanwckf@vip.qq.com>
#
# This is free software, licensed under the GNU General Public License v2.
#

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for wifi-mtk
LUCI_DEPENDS:=+wifi-script +iwinfo @!PACKAGE_luci-app-mtk @!PACKAGE_wifi-profile @!PACKAGE_mtwifi-cfg
LUCI_PKGARCH:=all

PKG_VERSION:=1

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature

#
# hua.shao@mediatek.com
#
# MTK Property Software.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=8021xd
PKG_VERSION:=efe26f34
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/8021xd
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  TITLE:=802.1X Daemon
  SUBMENU:=Applications
endef

define Package/8021xd/description
  802.1X Daemon
endef

TARGET_CFLAGS += -DCONFIG_SUPPORT_OPENWRT
MAKE_FLAGS += CONFIG_SUPPORT_OPENWRT=y
MAKE_FLAGS += \
	CFLAGS="$(TARGET_CFLAGS)"

define Package/8021xd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/8021xd $(1)/usr/sbin
endef

$(eval $(call BuildPackage,8021xd))

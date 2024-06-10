#
# hua.shao@mediatek.com
#
# MTK Property Software.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wpa-supplicant-2.10
PKG_REVISION:=cff80b4f
PKG_SOURCE:=$(PKG_NAME)-$(PKG_REVISION).tar.xz
PKG_VERSION:=2.10
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

PKG_CONFIG_DEPENDS:=$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)))

LOCAL_TYPE=$(strip \
		$(if $(findstring supplicant,$(BUILD_VARIANT)),supplicant, \
		hostapd \
		))

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

STAMP_CONFIGURED:=$(STAMP_CONFIGURED)_$(CONFIG_WPA_MSG_MIN_PRIORITY)

#ifeq ($(LOCAL_TYPE),supplicant)
    #DRIVER_MAKEOPTS += CONFIG_AP=y
#endif

define Package/wpa-supplicant-2.10
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  TITLE:=WPA Supplicant V2.10
  SUBMENU:=Applications
  DEPENDS:=+libnl-tiny +libopenssl +libubus +libubox
endef

define Package/wpa-supplicant-2.10/description
  WPA Supplicant V2.10
endef

ifneq ($(wildcard $(PKG_BUILD_DIR)/.config_*),$(subst .configured_,.config_,$(STAMP_CONFIGURED)))
  define Build/Configure/rebuild
	$(FIND) $(PKG_BUILD_DIR) -name \*.o -or -name \*.a | $(XARGS) rm -f
	rm -f $(PKG_BUILD_DIR)/wpa_supplicant/wpa_supplicant
	rm -f $(PKG_BUILD_DIR)/wpa_supplican/t.config_*
	touch $(subst .configured_,.config_,$(STAMP_CONFIGURED))
  endef
endif

define Build/Configure
	$(Build/Configure/rebuild)
	$(CP) ./files/wpa_supplicant-mini.config $(PKG_BUILD_DIR)/wpa_supplicant/.config
endef

DRIVER_MAKEOPTS= \
    CONFIG_DRIVER_NL80211=y \
    CONFIG_IEEE80211N=$(HOSTAPD_IEEE80211N) \
    CONFIG_TLS=openssl

TARGET_CPPFLAGS := \
	-I$(STAGING_DIR)/usr/include/libnl-tiny \
	-I$(PKG_BUILD_DIR)/src/crypto \
	$(TARGET_CPPFLAGS) \
	-DCONFIG_LIBNL20 \
	-D_GNU_SOURCE \
	$(if $(CONFIG_WPA_MSG_MIN_PRIORITY),-DCONFIG_MSG_MIN_PRIORITY=$(CONFIG_WPA_MSG_MIN_PRIORITY))

TARGET_CFLAGS += \
	-ffunction-sections \
	-fdata-sections \
	-flto \
	-DNO_TIMESTAMP_CHECK \
	-DHOSTAPD_MAPR3_SUPPORT \
	-DCONFIG_NAT

TARGET_LDFLAGS += -Wl,--gc-sections -lnl-tiny -lcrypto -lssl -lubox -lubus
TARGET_CONFIGURE_OPTS += CONFIG_P2P=y CONFIG_INTERNAL_LIBTOMMATH=y RTCONFIG_MT798X=y

TARGET_CFLAGS += -DCONFIG_SUPPORT_OPENWRT
MAKE_FLAGS += CONFIG_SUPPORT_OPENWRT=y

CFLAGS="$(TARGET_CFLAGS)"

define Build/RunMake
	CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS)" \
	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/$(1) \
		$(TARGET_CONFIGURE_OPTS) \
		$(DRIVER_MAKEOPTS) \
		LIBS="$(TARGET_LDFLAGS)" \
		LIBS_c="$(TARGET_LDFLAGS_C)" \
		AR="$(TARGET_CROSS)gcc-ar" \
		BCHECK= \
		$(if $(findstring s,$(OPENWRT_VERBOSE)),V=1) \
		$(2)
endef

define Build/Compile/wpad
	echo ` \
		$(call Build/RunMake,hostapd,-s MULTICALL=1 dump_cflags); \
		$(call Build/RunMake,wpa_supplicant,-s MULTICALL=1 dump_cflags) | \
		sed -e 's,-n ,,g' -e 's^$(TARGET_CFLAGS)^^' \
	` > $(PKG_BUILD_DIR)/.cflags
	sed -i 's/"/\\"/g' $(PKG_BUILD_DIR)/.cflags
	+$(call Build/RunMake,hostapd, \
		CFLAGS="$$$$(cat $(PKG_BUILD_DIR)/.cflags)" \
		MULTICALL=1 \
		hostapd_cli hostapd_multi.a \
	)
	+$(call Build/RunMake,wpa_supplicant, \
		CFLAGS="$$$$(cat $(PKG_BUILD_DIR)/.cflags)" \
		MULTICALL=1 \
		wpa_cli wpa_supplicant_multi.a \
	)
	+export MAKEFLAGS="$(MAKE_JOBSERVER)"; $(TARGET_CC) -o $(PKG_BUILD_DIR)/wpad \
		$(TARGET_CFLAGS) \
		./files/multicall.c \
		$(PKG_BUILD_DIR)/hostapd/hostapd_multi.a \
		$(PKG_BUILD_DIR)/wpa_supplicant/wpa_supplicant_multi.a \
		$(TARGET_LDFLAGS)
endef


define Build/Compile
	$(call Build/RunMake,wpa_supplicant, \
		wpa_cli wpa_supplicant \
	)
endef

define Package/wpa-supplicant-2.10/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wpa_supplicant/wpa_supplicant $(1)/usr/sbin
	$(CP) $(PKG_BUILD_DIR)/wpa_supplicant/wpa_supplicant $(1)/usr/sbin/
	$(CP) $(PKG_BUILD_DIR)/wpa_supplicant/wpa_cli $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc
	$(CP) files/wpa_supplicant.logrotate.conf $(1)/etc/
	$(CP) files/wpa_supplicant_common.conf $(1)/etc/
	$(CP) files/wpa_supplicant.conf $(1)/etc/
	$(CP) files/p2p_dev.conf $(1)/etc/
	$(CP) files/p2p_dhcpd.conf $(1)/etc/
	$(CP) ./files/wpa_supplicant_generate.sh $(1)/usr/bin
	# $(CP) files/hostapd_sta.sh $(1)/usr/sbin

endef

$(eval $(call BuildPackage,wpa-supplicant-2.10))

#
# hua.shao@mediatek.com
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=hostapd-2.10
PKG_REVISION:=cff80b4f
PKG_SOURCE:=$(PKG_NAME)-$(PKG_REVISION).tar.xz
PKG_VERSION:=2.10
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

PKG_CONFIG_DEPENDS:=$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)))

PKG_CONFIG_DEPENDS:= \
	CONFIG_PACKAGE_kmod-cfg80211 \
	CONFIG_PACKAGE_hostapd \
	CONFIG_WPA_RFKILL_SUPPORT \
	CONFIG_DRIVER_WEXT_SUPPORT \
	CONFIG_DRIVER_11N_SUPPORT \
	CONFIG_DRIVER_11AC_SUPPORT \
	CONFIG_DRIVER_11AX_SUPPORT \
	CONFIG_WPA_ENABLE_WEP

PKG_BUILD_FLAGS:=gc-sections lto

SUPPLICANT_PROVIDERS:=
HOSTAPD_PROVIDERS:=

#TARGET_CFLAGS += -I$(LINUX_DIR)/include/uapi/linux/mtk_nl80211_inc

LOCAL_TYPE=$(strip \
		# $(if $(findstring wpad,$(BUILD_VARIANT)),wpad, \
		$(if $(findstring supplicant,$(BUILD_VARIANT)),supplicant, \
		hostapd \
		)))

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk


ifneq ($(CONFIG_DRIVER_11N_SUPPORT),)
  HOSTAPD_IEEE80211N:=y
endif

ifneq ($(CONFIG_DRIVER_11AC_SUPPORT),)
  HOSTAPD_IEEE80211AC:=y
endif

ifneq ($(CONFIG_DRIVER_11AX_SUPPORT),)
  HOSTAPD_IEEE80211AX:=y
endif

DRIVER_MAKEOPTS= \
	CONFIG_ACS=$(CONFIG_PACKAGE_kmod-cfg80211) \
	CONFIG_DRIVER_NL80211=$(CONFIG_PACKAGE_kmod-cfg80211) \
	CONFIG_IEEE80211N=$(HOSTAPD_IEEE80211N) \
	CONFIG_IEEE80211AC=$(HOSTAPD_IEEE80211AC) \
	CONFIG_IEEE80211AX=$(HOSTAPD_IEEE80211AX) \
	CONFIG_DRIVER_WEXT=$(CONFIG_DRIVER_WEXT_SUPPORT)
ifneq ($(LOCAL_TYPE),hostapd)
  ifdef CONFIG_WPA_RFKILL_SUPPORT
    DRIVER_MAKEOPTS += NEED_RFKILL=y
  endif
endif

ifeq ($(LOCAL_TYPE),supplicant)
    DRIVER_MAKEOPTS += CONFIG_AP=y
endif

DRV_DEPENDS:=+PACKAGE_kmod-cfg80211:libnl-tiny


define Package/hostapd-2.10
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=WirelessAPD
  TITLE:=IEEE 802.1x Authenticator
  URL:=http://hostap.epitest.fi/
  USERID:=network=101:network=101
  PROVIDES:=hostapd
  CONFLICTS:=$(HOSTAPD_PROVIDERS)
  HOSTAPD_PROVIDERS+=$(1)
  DEPENDS:=$(DRV_DEPENDS) +libnl-tiny +libopenssl +libubus
  VARIANT:=hostapd
endef

define Package/hostapd-2.10/description
  WPA hostapd MTK V2.10
endef

# define Package/wpad-2.10
  # SECTION:=net
  # CATEGORY:=Network
  # SUBMENU:=WirelessAPD
  # TITLE:=IEEE 802.1x Auth/Supplicant
  # USERID:=network=101:network=101
  # URL:=http://hostap.epitest.fi/
  # PROVIDES:=hostapd wpa-supplicant
  # CONFLICTS:=$(HOSTAPD_PROVIDERS) $(SUPPLICANT_PROVIDERS)
  # HOSTAPD_PROVIDERS+=$(1)
  # DEPENDS:=$(DRV_DEPENDS) +libnl-tiny +libopenssl +libubus +libubox
  # VARIANT:=wpad
# endef

# define Package/wpad-2.10/description
 # This package contains a full featured IEEE 802.1x/WPA/EAP/RADIUS
 # Authenticator and Supplicant
# endef

define Package/wpa-supplicant-2.10
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=WirelessAPD
  TITLE:=WPA Supplicant
  URL:=http://hostap.epitest.fi/wpa_supplicant/
  USERID:=network=101:network=101
  PROVIDES:=wpa-supplicant
  CONFLICTS:=$(SUPPLICANT_PROVIDERS)
  SUPPLICANT_PROVIDERS+=$(1)
  DEPENDS:=$(DRV_DEPENDS) +libnl-tiny +libopenssl +libubus
  VARIANT:=supplicant
endef

define Package/wpa-supplicant-2.10/config
	source "$(SOURCE)/Config.in"
endef

ifneq ($(wildcard $(PKG_BUILD_DIR)/.config_*),$(subst .configured_,.config_,$(STAMP_CONFIGURED)))
  define Build/Configure/rebuild
	$(FIND) $(PKG_BUILD_DIR) -name \*.o -or -name \*.a | $(XARGS) rm -f
	rm -f $(PKG_BUILD_DIR)/hostapd/hostapd
	rm -f $(PKG_BUILD_DIR)/hostapd/t.config_*
	rm -f $(PKG_BUILD_DIR)/wpa_supplicant/wpa_supplicant
	rm -f $(PKG_BUILD_DIR)/wpa_supplican/t.config_*
	touch $(subst .configured_,.config_,$(STAMP_CONFIGURED))
  endef
endif

DRIVER_MAKEOPTS= \
    CONFIG_DRIVER_NL80211=y \
    CONFIG_TLS=openssl

TARGET_CPPFLAGS := \
	-I$(STAGING_DIR)/usr/include/libnl-tiny \
	-I$(PKG_BUILD_DIR)/src/crypto \
	$(TARGET_CPPFLAGS) \
	-DCONFIG_LIBNL20 \
	-D_GNU_SOURCE \
	-DCONFIG_MSG_MIN_PRIORITY=0

TARGET_CFLAGS += \
	-ffunction-sections \
	-fdata-sections \
	-flto \
	-DNO_TIMESTAMP_CHECK \
	-DHOSTAPD_MAPR3_SUPPORT \
	-DCONFIG_NAT

TARGET_LDFLAGS += -Wl,--gc-sections -lnl-tiny -lcrypto -lssl -lubox -lubus
TARGET_CONFIGURE_OPTS += CONFIG_P2P=y CONFIG_INTERNAL_LIBTOMMATH=y RTCONFIG_MT798X=y


CFLAGS="$(TARGET_CFLAGS)"

define Build/Configure
	$(Build/Configure/rebuild)
	$(CP) ./files/hostapd-mini.config $(PKG_BUILD_DIR)/hostapd/.config
	$(CP) ./files/wpa_supplicant-mini.config $(PKG_BUILD_DIR)/wpa_supplicant/.config
endef

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

# define Build/Compile/wpad
	# echo ` \
		# $(call Build/RunMake,hostapd,-s MULTICALL=1 dump_cflags); \
		# $(call Build/RunMake,wpa_supplicant,-s MULTICALL=1 dump_cflags) | \
		# sed -e 's,-n ,,g' -e 's^$(TARGET_CFLAGS)^^' \
	# ` > $(PKG_BUILD_DIR)/.cflags
	# sed -i 's/"/\\"/g' $(PKG_BUILD_DIR)/.cflags
	# +$(call Build/RunMake,hostapd, \
		# CFLAGS="$$$$(cat $(PKG_BUILD_DIR)/.cflags)" \
		# MULTICALL=1 \
		# hostapd_cli hostapd_multi.a \
	# )
	# +$(call Build/RunMake,wpa_supplicant, \
		# CFLAGS="$$$$(cat $(PKG_BUILD_DIR)/.cflags)" \
		# MULTICALL=1 \
		# wpa_cli wpa_supplicant_multi.a \
	# )
	# +export MAKEFLAGS="$(MAKE_JOBSERVER)"; $(TARGET_CC) -o $(PKG_BUILD_DIR)/wpad \
		# $(TARGET_CFLAGS) \
		# ./files/multicall.c \
		# $(PKG_BUILD_DIR)/hostapd/hostapd_multi.a \
		# $(PKG_BUILD_DIR)/wpa_supplicant/wpa_supplicant_multi.a \
		# $(TARGET_LDFLAGS)
# endef

define Build/Compile/hostapd
	+$(call Build/RunMake,hostapd, \
		hostapd hostapd_cli \
	)
endef

define Build/Compile/supplicant
	+$(call Build/RunMake,wpa_supplicant, \
		wpa_cli wpa_supplicant \
	)
endef

define Build/Compile
	$(Build/Compile/$(LOCAL_TYPE))
	$(Build/Compile/$(BUILD_VARIANT))
endef

define Package/hostapd-2.10/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/capabilities $(1)/etc/rc.button $(1)/etc/hotplug.d/ieee80211 $(1)/etc/init.d $(1)/lib/netifd  $(1)/usr/share/acl.d
	$(INSTALL_BIN) ./files/dhcp-get-server.sh $(1)/lib/netifd/dhcp-get-server.sh
	$(INSTALL_DATA) ./files/hostapd.sh $(1)/lib/netifd/hostapd.sh
	$(INSTALL_BIN) ./files/wpad.init $(1)/etc/init.d/wpad
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/wpad.config $(1)/etc/config/wpad
	$(INSTALL_BIN) ./files/wps-hotplug.sh $(1)/etc/rc.button/wps
	$(INSTALL_DATA) ./files/wpad_acl.json $(1)/usr/share/acl.d
	$(INSTALL_DATA) ./files/wpad.json $(1)/etc/capabilities
	$(CP) files/hostapd_conf_generate.sh $(1)/usr/sbin/
#	$(CP) $(PKG_BUILD_DIR)/hostapd/hostapd $(PKG_BUILD_DIR)/hostapd/hostapd-2.10
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hostapd/hostapd $(1)/usr/sbin/
	$(CP) $(PKG_BUILD_DIR)/hostapd/hostapd  $(1)/usr/sbin/
	$(CP) $(PKG_BUILD_DIR)/hostapd/hostapd_cli $(1)/usr/sbin/
#	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wpa_supplicant/wpa_supplicant $(1)/usr/sbin/
#	$(CP) $(PKG_BUILD_DIR)/wpa_supplicant/wpa_supplicant  $(1)/usr/sbin/
#	$(CP) $(PKG_BUILD_DIR)/wpa_supplicant/wpa_cli $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc
	$(CP) files/hostapd.conf $(1)/etc/
#	$(CP) files/hostapd_ra0_open.conf $(1)/etc/
#	$(CP) files/hostapd_rai0_open.conf $(1)/etc/
#	$(CP) files/hostapd_ra0_wpa2psk.conf $(1)/etc/
#	$(CP) files/hostapd_rai0_wpa2psk.conf $(1)/etc/
	$(CP) files/hostapd_ra0_map.conf $(1)/etc/
	$(CP) files/hostapd_ra1_map.conf $(1)/etc/
	$(CP) files/hostapd_ra2_map.conf $(1)/etc/
	$(CP) files/hostapd_ra3_map.conf $(1)/etc/
	$(CP) files/hostapd_rax0_map.conf $(1)/etc/
	$(CP) files/hostapd_rax1_map.conf $(1)/etc/
	$(CP) files/hostapd_rax2_map.conf $(1)/etc/
	$(CP) files/hostapd_rax3_map.conf $(1)/etc/
#	$(CP) files/hostapd-wpa3  $(1)/usr/sbin/
#	$(CP) files/hostapd-wpa3_cli $(1)/usr/sbin/
#	$(CP) files/hostapd_ra0_sae.conf $(1)/etc/
#	$(CP) files/hostapd_rai0_sae.conf $(1)/etc/
	$(CP) files/hostapd_ra0_owe.conf $(1)/etc/
	$(CP) files/hostapd_rai0_owe.conf $(1)/etc/
	$(CP) files/hostapd_ra0_wpa3.conf $(1)/etc/
	$(CP) files/hostapd_rai0_wpa3.conf $(1)/etc/
	$(CP) files/hostapd_ra0_owe_sigma.conf $(1)/etc/
	$(CP) files/hostapd_rai0_owe_sigma.conf $(1)/etc/
	$(CP) files/hostapd_rax0_owe_sigma.conf $(1)/etc/
	$(CP) files/hostapd_rax1_owe_sigma.conf $(1)/etc/
	$(CP) files/hostapd_rax0_wpa3_r2_sigma.conf $(1)/etc/
	$(CP) files/hostapd_ra0_wpa3_r2_sigma.conf $(1)/etc/
	$(CP) files/hostapd_ra0_wpa3_sigma.conf $(1)/etc/
	$(CP) files/hostapd_rax0_wpa3_sigma.conf $(1)/etc/
	$(CP) files/hostapd_rax0.conf $(1)/etc/
	$(CP) files/hostapd_ra0.conf $(1)/etc/
	$(CP) files/hostapd_rax0_sae.conf $(1)/etc/
	$(CP) files/hostapd_rax0_owe.conf $(1)/etc/
	$(CP) files/hostapd_ra0_sae.conf $(1)/etc/
	$(CP) files/hostapd_ra0_hs_sigma.conf $(1)/etc/
	$(CP) files/hostapd_ra0_sigma.conf $(1)/etc/
	$(CP) files/hostapd_ra1_sigma.conf $(1)/etc/
	$(CP) files/hostapd_rax0_hs_sigma.conf $(1)/etc/
	$(CP) files/hostapd_rax0_sigma.conf $(1)/etc/
	$(CP) files/hostapd_rax1_sigma.conf $(1)/etc/
	$(CP) files/hostapd_common.conf $(1)/etc/
	$(CP) -f files/*.png $(1)/etc/
	$(CP) -f files/*.ico $(1)/etc/
	$(CP) files/hostapd_generate.sh $(1)/usr/sbin
	$(CP) files/hostapd_ap.sh $(1)/usr/sbin
	$(CP) files/hostapd_app.sh $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(CP) files/hostapd_init $(1)/etc/init.d
	$(CP) files/hostapd_ap_11r.sh $(1)/usr/sbin
	$(CP) files/hostapd_rai0_AP_11r.conf $(1)/etc/
	$(CP) files/hostapd_stop.sh $(1)/usr/sbin
#	$(CP) files/wpa_supplicant_common.conf $(1)/etc/
#	$(CP) files/wpa_supplicant_generate.sh $(1)/usr/sbin
#	$(CP) files/hostapd_sta.sh $(1)/usr/sbin
endef

# define Package/wpad-2.10/install
	# $(INSTALL_DIR) $(1)/usr/sbin
	# $(INSTALL_BIN) ./files/wpad $(1)/usr/sbin/
	# $(LN) wpad $(1)/usr/sbin/hostapd
	# $(LN) wpad $(1)/usr/sbin/wpa_supplicant
# endef

define Package/wpa-supplicant-2.10/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wpa_supplicant/wpa_supplicant $(1)/usr/sbin/
	$(CP) $(PKG_BUILD_DIR)/wpa_supplicant/wpa_supplicant  $(1)/usr/sbin/
	$(CP) $(PKG_BUILD_DIR)/wpa_supplicant/wpa_cli $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc
	$(CP) files/wpa_supplicant_common.conf $(1)/etc/
	$(CP) files/wpa_supplicant_generate.sh $(1)/usr/sbin
	$(CP) files/hostapd_sta.sh $(1)/usr/sbin
endef

$(eval $(call BuildPackage,hostapd-2.10))
# $(eval $(call BuildPackage,wpad-2.10))
$(eval $(call BuildPackage,wpa-supplicant-2.10))

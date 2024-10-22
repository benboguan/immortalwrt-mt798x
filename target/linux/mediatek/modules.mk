define KernelPackage/sound-soc-mt79xx
  TITLE:=MT79xx SoC sound support
  KCONFIG:=\
	CONFIG_SND_SOC_MEDIATEK \
	CONFIG_SND_SOC_MT79XX \
	CONFIG_SND_SOC_MT79XX_WM8960
  FILES:= \
	$(LINUX_DIR)/sound/soc/mediatek/common/snd-soc-mtk-common.ko \
	$(LINUX_DIR)/sound/soc/mediatek/mt79xx/mt79xx-wm8960.ko \
	$(LINUX_DIR)/sound/soc/mediatek/mt79xx/snd-soc-mt79xx-afe.ko \
	$(LINUX_DIR)/sound/soc/codecs/snd-soc-wm8960.ko
  AUTOLOAD:=$(call AutoLoad,57,regmap-i2c snd-soc-wm8960 snd-soc-mtk-common snd-soc-mt79xx-afe)
  DEPENDS:=@TARGET_mediatek +kmod-regmap-i2c +kmod-sound-soc-core
  $(call AddDepends/sound,+kmod-regmap-i2c)
endef

define KernelPackage/sound-soc-mt79xx/description
 Support for MT79xx Platform sound
endef

$(eval $(call KernelPackage,sound-soc-mt79xx))

define KernelPackage/mediatek_hnat
  SUBMENU:=Network Devices
  TITLE:=Mediatek HNAT module
  DEPENDS:=@TARGET_mediatek +kmod-nf-conntrack
  AUTOLOAD:=$(call AutoLoad,20,mtkhnat)
  MODPARAMS.mtkhnat:=ppe_cnt=2
  KCONFIG:= \
	CONFIG_BRIDGE_NETFILTER=y \
	CONFIG_NETFILTER_FAMILY_BRIDGE=y \
	CONFIG_NET_MEDIATEK_HNAT
  FILES:= \
        $(LINUX_DIR)/drivers/net/ethernet/mediatek/mtk_hnat/mtkhnat.ko
endef

define KernelPackage/mediatek_hnat/description
  Kernel modules for MediaTek HW NAT offloading
endef

$(eval $(call KernelPackage,mediatek_hnat))

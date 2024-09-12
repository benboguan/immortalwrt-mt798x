#!/bin/sh
#
# Copyright (c) 2014 OpenWrt
# Copyright (c) 2013-2015 D-Team Technology Co.,Ltd. ShenZhen
# Copyright (c) 2005-2015, lintel <lintel.huang@gmail.com>
# Copyright (c) 2013, Hoowa <hoowa.sun@gmail.com>
# Copyright (c) 2015-2017, GuoGuo <gch981213@gmail.com>
# Copyright (c) 2022-2024, nanchuci <nanchuci023@gmail.com>
#
# 	Detect script for MT7615/MT7915/MT798X DBDC mode
#
# 	嘿，对着屏幕的哥们,为了表示对原作者辛苦工作的尊重，任何引用跟借用都不允许你抹去所有作者的信息,请保留这段话。
#

append DRIVERS "mtk"

. /lib/functions.sh
. /lib/functions/system.sh


is_11ax_dbdc_dev()
{
  [ -n "$(cat /etc/wireless/l1profile.dat |grep INDEX0 |grep MT7915D)" ] && echo yes;
  [ -n "$(cat /etc/wireless/l1profile.dat |grep INDEX0 |grep MT7981)" ] && echo yes;
  [ -n "$(cat /etc/wireless/l1profile.dat |grep INDEX0 |grep MT7986)" ] && echo yes;

  return 0;
}

is_11ac_dbdc_dev()
{
  [ -n "$(cat /etc/wireless/l1profile.dat |grep INDEX0 |grep MT7615D)" ] && echo yes;

  return 0;
}

is_support_11ax_ht160_dev()
{
  [ -n "$(cat /etc/wireless/l1profile.dat |grep INDEX0 |grep MT7981)" ] && echo yes;
  [ -n "$(cat /etc/wireless/l1profile.dat |grep INDEX0 |grep MT7986)" ] && echo yes;

  return 0;
}

detect_mtk() {
	local base_mac
	hostname=$(uci -q get system.@system[-1].hostname)
	config_load wireless

	[ -n "$(is_11ax_dbdc_dev)" -o -n "$(is_11ac_dbdc_dev)" ] || return 0

	[ -d /sys/module/mt_wifi ] && {
		for phyname in ra0 rax0; do
			config_get type "$phyname" type

			base_mac=$(cat /sys/class/net/eth0/address)

			[ "$type" == "mtk" ] || {
				case $phyname in
					ra0)
						band="2g"
						hwmode="11g"
						noscan="1"
						[ -n "$(is_11ax_dbdc_dev)" ] && htmode=HE40 || htmode=HT40
						[ -z "$hostname" ] && {
							ssid="OpenWRT-2.4G-$(echo $base_mac | awk -F ":" '{print $5""$6 }'| tr a-z A-Z)"
						} || {
							ssid="$hostname-2.4G"
						}
						;;
					rax0)
						band="5g"
						hwmode="11a"
#						noscan="1"
						[ -n "$(is_support_11ax_ht160_dev)" ] && htmode=HE160 || htmode=VHT160 || {
							[ -n "$(is_11ax_dbdc_dev)" ] && htmode=HE80 || htmode=VHT80
						}
						[ -z "$hostname" ] && {
							ssid="OpenWRT-5G-$(echo $base_mac | awk -F ":" '{print $5""$6 }'| tr a-z A-Z)"
						} || {
							ssid="$hostname-5G"
						}
						;;
				esac

				uci -q batch <<-EOF
					set wireless.${phyname}=wifi-device
					set wireless.${phyname}.type=mtk
					set wireless.${phyname}.hwmode=$hwmode
					set wireless.${phyname}.band=$band
					set wireless.${phyname}.channel=auto
					set wireless.${phyname}.country=CN
					set wireless.${phyname}.txburst=1
					set wireless.${phyname}.txpower=100
					set wireless.${phyname}.htmode=$htmode
					set wireless.${phyname}.noscan=$noscan

					set wireless.default_${phyname}=wifi-iface
					set wireless.default_${phyname}.device=${phyname}
					set wireless.default_${phyname}.network=lan
					set wireless.default_${phyname}.mode=ap
					set wireless.default_${phyname}.ieee80211k=0
					set wireless.default_${phyname}.ieee80211v=0
					set wireless.default_${phyname}.ieee80211w=0
					set wireless.default_${phyname}.ieee80211r=0
					set wireless.default_${phyname}.ssid=${ssid}
					set wireless.default_${phyname}.encryption=none
EOF
				uci -q commit wireless
			}
		done
	}

	return 0;
}

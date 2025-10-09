#!/bin/sh
#
# Copyright (c) 2013-2015 D-Team Technology Co.,Ltd. ShenZhen
# Copyright (c) 2005-2015, lintel <lintel.huang@gmail.com>
# Copyright (c) 2013, Hoowa <hoowa.sun@gmail.com>
# Copyright (c) 2015-2017, GuoGuo <gch981213@gmail.com>
# Copyright (c) 2020,2023, jjm2473 <jjm2473@gmail.com>
# Copyright (c) 2022-2025, nanchuci <nanchuci023@gmail.com>
#
# 	netifd config script for MT7615/MT7915/MT7916/MT798X DBDC mode.
#
# 	嘿，对着屏幕的哥们,为了表示对原作者辛苦工作的尊重，任何引用跟借用都不允许你抹去所有作者的信息,请保留这段话。
#
. /lib/netifd/netifd-wireless.sh
. /lib/netifd/hostapd.sh
. /lib/functions/system.sh

init_wireless_driver "$@"

#Default configurations
MTWIFI_PROFILE_DIR="/etc/wireless/mediatek/"
MTWIFI_PROFILE_PATH=""
MTWIFI_CMD_PATH=""
MTWIFI_CMD_OPATH=""
APCLI_IF=""
MESH_IF=""
WIFI_OP_LOCK=$MTWIFI_PROFILE_DIR"mtk.lock"
MTWIFI_IFPREFIX=""
MTWIFI_DEF_BAND=""
MTWIFI_FORCE_HT=0
MTWIFI_WDS_MAX_BSSID=4
MTWIFI_DEF_MAX_BSSID=16
hostname=$(uci -q get system.@system[-1].hostname)

mt_cmd() {
	echo "$@" >> $MTWIFI_CMD_PATH
}

# 优化的驱动清理函数 - 保持功能但减少等待时间
drv_mtk_cleanup() {
	echo "Starting optimized driver cleanup..."
	
	# 并行卸载模块但保持原有逻辑
	for mod in mt_wifi; do
		if ls /lib/modules/*/$mod.ko 2>/dev/null | grep -q .; then
			rmmod $mod 2>/dev/null &
		fi
	done
	wait
	
	# 减少等待时间但保持稳定性
	sleep 1

	# 并行加载模块
	for mod in mt_wifi; do
		if ls /lib/modules/*/$mod.ko 2>/dev/null | grep -q .; then
			modprobe $mod &
		fi
	done
	wait
	
	sleep 1
	echo "Driver cleanup completed"
	return 0
}

# 简化锁机制
mtk_try_lock() {
	if lock -n $WIFI_OP_LOCK; then
		return 0
	else
		echo "Warning: WiFi operation locked, skip to speed up response"
		return 1
	fi
}

#读取device相关设置项并写入json
drv_mtk_init_device_config() {
	config_add_string path channel hwmode htmode country 'macaddr:macaddr' twt
	config_add_string txburst cell_density
	config_add_string distance
	config_add_int beacon_int chanbw vendor_vht vht_1024 mu_beamformer whnat mlr
	config_add_int rxantenna txantenna antenna_gain txpower min_tx_power noscan
	config_add_int num_global_macaddr multiple_bssid legacy_rates
	config_add_boolean greenap diversity noscan ht_coex acs_exclude_dfs background_radar
	config_add_int powersave doth
	config_add_int maxassoc
	config_add_boolean hidessid bndstrg isolate dfs bandsteering band
	config_add_array channels
	config_add_array scan_list
}

#读取iface相关设置项并写入json
drv_mtk_init_iface_config() {
	config_add_boolean disabled wds mwds
	config_add_string mode ifname 'macaddr:macaddr' bssid 'ssid:string' encryption
	config_add_string auth_server auth_port auth_secret acct_secret own_ip_addr own_radius_port
	config_add_boolean hidden isolate isolate_mb br_isolate_mode ieee80211k ieee80211v ieee80211r
	config_add_boolean powersave enable coloring ldpc lofdm mesh_fwding wnm_notify
	config_add_string key key1 key2 key3 key4 steeringthresold
	config_add_string wds_bridge wps_pushbutton pin mesh_id mapmode mesh_rssi_threshold
	config_add_string macfilter 'macfile:file' nasid mobility_domain r1_key_holder r0_key_lifetime reassociation_deadline ft_over_ds
	config_add_array 'maclist:list(macaddr)' 'steeringbssid:list(macaddr)' r0kh r1kh

	config_add_boolean wmm wnm_sleep_mode bss_transition proxy_arp mbo rrm_neighbor_report rrm_beacon_report ft_psk_generate_local pmk_r1_push
	config_add_int frag rts dtim_period apclipe short_preamble wpa_group_rekey rsn_preauth ocv
	config_add_int max_listen_int ieee80211w time_advertisement 'port:port'
	config_add_int disassoc_low_ack kicklow assocthres
	config_add_string wdsenctype wdskey wdsphymode macaddr time_zone
	config_add_int wdsen mumimo_dl mumimo_ul ofdma_dl ofdma_ul
	config_add_int start_disabled
}

get_wep_key_type() {
	local KeyLen=$(expr length "$1")
	if [ $KeyLen -eq 10 ] || [ $KeyLen -eq 26 ] || [ $KeyLen -eq 32 ]; then
		echo 0
	else
		echo 1
	fi	
}

mtk_ap_vif_pre_config() {
	local name="$1"

	json_select config
	json_get_vars disabled encryption auth_secret acct_secret auth_server auth_port acct_server \
		acct_port key key1 key2 key3 key4 wmm own_ip_addr own_radius_port macaddr wpa_group_rekey \
		bssid ssid mode wps_pushbutton pin pbc isolate hidden disassoc_low_ack kicklow assocthres rsn_preauth \
		short_preamble ieee80211k ieee80211v ieee80211r ieee80211w macfilter nasid mobility_domain r1_key_holder \
		r0_key_lifetime reassociation_deadline r0kh r1kh ft_over_ds ft_psk_generate_local pmk_r1_push rrm_neighbor_report \
		rrm_beacon_report wnm_sleep_mode bss_transition proxy_arp frag rts dtim_period mumimo_dl mumimo_ul ofdma_dl ofdma_ul \
		ocv wnm_notify steeringthresold mwds
	json_get_values maclist maclist
	json_select ..

	[[ "$disabled" = "1" ]] && return
	[ $ApBssidNum -gt $MTWIFI_DEF_MAX_BSSID ] && return 

	echo "Generating ap config for interface ra${MTWIFI_IFPREFIX}${ApBssidNum}"
	ifname="ra${MTWIFI_IFPREFIX}${ApBssidNum}"

	# 计算配置索引（从MacAddress开始使用索引1）
	local config_index=$((ApBssidNum + 1))

	# 快速接口配置
	json_add_object data
	json_add_string ifname "$ifname"
	json_close_object

	#MAC过滤方式和自定义MAC地址相关设定 由于编号问题......扔在这了...... - 使用索引0
	ra_maclist="${maclist// /;};"
	case "$macfilter" in
		allow) echo "AccessPolicy${ApBssidNum}=1;AccessControlList${ApBssidNum}=${ra_maclist}" >> $MTWIFI_PROFILE_PATH ;;
		deny)  echo "AccessPolicy${ApBssidNum}=2;AccessControlList${ApBssidNum}=${ra_maclist}" >> $MTWIFI_PROFILE_PATH ;;
	esac

	# 批量配置生成
	{
		[ "$ApBssidNum" = "0" ] && echo "MacAddress=${macaddr}" || echo "MacAddress${config_index}=${macaddr}"
		echo "SSID${config_index}=${ssid}"
	} >> $MTWIFI_PROFILE_PATH

	# 快速加密配置
	case "$encryption" in
		wpa*|psk*|WPA*|sae*|*SAE*|owe*|*8021x*|*eap*|Mixed|mixed)
			local enc crypto
			case "$encryption" in
				Mixed|mixed|psk+psk2|psk-mixed*) enc=WPAPSKWPA2PSK ;;
				psk2*) enc=WPA2PSK ;;
				psk*) enc=WPAPSK ;;
				SAE*|psk3|sae) enc=WPA3PSK ;;
				psk2+psk3|psk3-mixed*|sae-mixed*) enc=WPA2PSKWPA3PSK ;;
				8021x*|eap|wpa) enc=WPA ;;
				8021x*|eap2|wpa2) enc=WPA2 ;;
				8021x*|eap+eap2|wpa-mixed) enc=WPA1WPA2 ;;
				8021x*|wpa3) enc=WPA3 ;;
				8021x*|wpa3-mixed*) enc=WPA3WPA2 ;;
				8021x*|eap192*|wpa3-192*) enc=WPA3-192 ;;
				OWE*|owe) enc=OWE ;;
			esac
			crypto="AES"
			case "$encryption" in
				*tkipaes*|*tkip+ccmp*|*tkip+aes*|*aes+tkip*|*ccmp+tkip*) crypto="TKIPAES" ;;
				*gcmp256*) crypto="GCMP256" ;;
				*ccmp256*) crypto="CCMP256" ;;
				*aes+gcmp256*|*ccmp128+gcmp256*) crypto="AES_GCMP256" ;;
				*gcmp*|*gcmp128*) crypto="GCMP128" ;;
				*aes*|*ccmp*|*ccmp128*) crypto="AES" ;;
				*tkip*) crypto="TKIP" ;;
			esac

			if [ "$encryption" = "wpa3-192" ]; then
				ApAuthMode="${ApAuthMode}${enc};"
				ApEncrypType="${ApEncrypType}GCMP256;"
			else
				ApAuthMode="${ApAuthMode}${enc};"
				ApEncrypType="${ApEncrypType}${crypto};"
			fi
			ApDefKId="${ApDefKId}2;"
			echo "WPAPSK${config_index}=${key}" >> $MTWIFI_PROFILE_PATH
			;;
		WEP|wep|wep-open|wep-shared)
			[ "$encryption" = "wep-shared" ] && ApAuthMode="${ApAuthMode}SHARED;" || ApAuthMode="${ApAuthMode}OPEN;"
			ApEncrypType="${ApEncrypType}WEP;"

			K1Tp=$(get_wep_key_type "$key1")
			K2Tp=$(get_wep_key_type "$key2")
			K3Tp=$(get_wep_key_type "$key3")
			K4Tp=$(get_wep_key_type "$key4")

			[ $K1Tp -eq 1 ] && key1=$(echo $key1 | cut -d ':' -f 2-)
			[ $K2Tp -eq 1 ] && key2=$(echo $key2 | cut -d ':' -f 2-)
			[ $K3Tp -eq 1 ] && key3=$(echo $key3 | cut -d ':' -f 2-)
			[ $K4Tp -eq 1 ] && key4=$(echo $key4 | cut -d ':' -f 2-)

			echo "Key1Str${config_index}=${key1}" >> $MTWIFI_PROFILE_PATH
			echo "Key2Str${config_index}=${key2}" >> $MTWIFI_PROFILE_PATH
			echo "Key3Str${config_index}=${key3}" >> $MTWIFI_PROFILE_PATH
			echo "Key4Str${config_index}=${key4}" >> $MTWIFI_PROFILE_PATH
			ApDefKId="${ApDefKId}${key};"
			;;
		none|open)
			ApAuthMode="${ApAuthMode}OPEN;"
			ApEncrypType="${ApEncrypType}NONE;"
			ApDefKId="${ApDefKId}1;"
			;;
	esac

	# 批量配置累加
	ApRekeyMethod="${ApRekeyMethod}$([ "$encryption" = "open" -o "$encryption" = "owe" ] && echo "DISABLE;" || echo "TIME;")"

	if [ "$encryption" = "wpa" -o "$encryption" = "wpa-mixed" -o "$encryption" = "wpa2" -o "$encryption" = "wpa3" \
		-o "$encryption" = "wpa3-mixed" -o "$encryption" = "wpa3-192" ]; then
		{
			echo "NasId${config_index}=${nasid}"
			echo "RADIUS_Key${config_index}=${auth_secret:-0}"
			echo "RADIUS_Acct_Key${config_index}=${acct_secret:-0}"
		} >> $MTWIFI_PROFILE_PATH
	else
		echo "FtR0khId${config_index}=${nasid}" >> $MTWIFI_PROFILE_PATH
	fi

	ApK1Tp="${ApK1Tp}${K1Tp:-0};"
	ApK2Tp="${ApK2Tp}${K2Tp:-0};"
	ApK3Tp="${ApK3Tp}${K3Tp:-0};"
	ApK4Tp="${ApK4Tp}${K4Tp:-0};"
	ApMWDS="${ApMWDS}${mwds:-0};"
	ApHideESSID="${ApHideESSID}${hidden:-0};"
	ApWmmCapable="${ApWmmCapable}${wmm:-1};"
	ApRADIUSServer="${ApRADIUSServer}${auth_server:-0};"
	ApRADIUSPort="${ApRADIUSPort}${auth_port:-1812};"
	ApRADIUSAcctServer="${ApRADIUSAcctServer}${acct_server:-0};"
	ApRADIUSAcctPort="${ApRADIUSAcctPort}${acct_port:-1813};"
	Apown_ip_addr="${Apown_ip_addr}${own_ip_addr};"
	Apown_radius_port="${Apown_radius_port}${own_radius_port};"
	ApPreAuth="${ApPreAuth}${rsn_preauth:-0};"
	ApNoForwarding="${ApNoForwarding}${isolate:-0};"
	ApRekeyInterval="${ApRekeyInterval}${wpa_group_rekey:-3600};"
	ApRRMEnable="${ApRRMEnable}${ieee80211k:-0};"
	ApRRMNeighbor="${ApRRMNeighbor}${rrm_neighbor_report:-0};"
	ApWNMEnable="${ApWNMEnable}${bss_transition:-0};"
	ApWNMNotifyEnable="${ApWNMNotifyEnable}${wnm_notify:-0};"
	ApARP="${ApARP}${proxy_arp:-0};"
	ApFtSupport="${ApFtSupport}${ieee80211r:-0};"
	ApFtOtd="${ApFtOtd}${ft_over_ds:-0};"
	ApFtOnly="${ApFtOnly}${ft_psk_generate_local:-0};"
	ApFrag="${ApFrag}${frag:-2346};"
	ApRts="${ApRts}${rts:-2347};"
	ApDtim="${ApDtim}${dtim_period:-1};"
	Apmumimodl="${Apmumimodl}${mumimo_dl:-0};"
	Apmumimoul="${Apmumimoul}${mumimo_ul:-0};"
	Apofdmadl="${Apofdmadl}${ofdma_dl:-1};"
	Apofdmaul="${Apofdmaul}${ofdma_ul:-1};"
	Apamsdu="${Apamsdu}${amsdu:-1};"
	Apautoba="${Apautoba}${autoba:-1};"
	Apuapsd="${Apuapsd}${uapsd:-1};"
	Apocv="${Apocv}${ocv:-0};"
	
	{
		echo "FtMdId${config_index}=${mobility_domain:-4f57}"
		echo "FtR1khId${config_index}=${r1_key_holder:-00004f577274}" 
		echo "R0KeyLifeTime${config_index}=${r0_key_lifetime:-10000}"
		echo "AssocDeadLine${config_index}=${reassociation_deadline:-100}"
	} >> $MTWIFI_PROFILE_PATH

	mt_cmd ifconfig $ifname up
	mt_cmd echo "Interface $ifname now up."
	if [ "$ieee80211w" = "1" ] || [ "$encryption" = "sae-mixed" -o "$encryption" = "wpa3-mixed" ]; then
		ApPMFMFPC="${ApPMFMFPC}1;"
		ApPMFMFPR="${ApPMFMFPR}0;"
	elif [ "$ieee80211w" = "2" ] || [ "$encryption" = "sae" -o "$encryption" = "owe" -o "$encryption" = "wpa3-192" ]; then
		ApPMFMFPC="${ApPMFMFPC}1;"
		ApPMFMFPR="${ApPMFMFPR}1;"
	else
		ApPMFMFPC="${ApPMFMFPC}0;"
		ApPMFMFPR="${ApPMFMFPR}0;"
	fi

	if [ "$wps_pushbutton" = "1" ] && [ "$encryption" != "none" ]; then
		mt_cmd echo "Enable WPS PIN for ${ifname}."
		ApWscConfMode="${ApWscConfMode}7;"
		ApWscConfStatus="${ApWscConfStatus}1;"
		pin="${pin:-}"
		pin_length=${#pin}
		if [ "$pin_length" -lt 4 ]; then
			ApWsc4digitPinCode="${ApWsc4digitPinCode}1;"
		else
			ApWsc4digitPinCode="${ApWsc4digitPinCode}0;"
		fi
		ApWscVendorPinCode="${ApWscVendorPinCode}${pin};"
	elif [ "$wps_pushbutton" = "2" ] && [ "$encryption" != "none" ]; then
		mt_cmd echo "Enable WPS PBC for ${ifname}."
		ApWscConfMode="${ApWscConfMode}7;"
		ApWscConfStatus="${ApWscConfStatus}2;"
	else
		mt_cmd echo "Disabled WPS for ${ifname}."
		ApWscConfMode="${ApWscConfMode}0;"
		ApWscConfStatus="${ApWscConfStatus}1;"
	fi

	mt_cmd echo "Other settings for ${ifname}."
	[ -n "$disassoc_low_ack" ] && [ "$disassoc_low_ack" != "0" ] && {
		mt_cmd iwpriv $ifname set KickStaRssiLow=$kicklow
		mt_cmd iwpriv $ifname set AssocReqRssiThres=$assocthres
	}

	# PMF(802.11W) should be disabled if you want your device to support both iPhone and Android STAs
	[ -n "$ieee80211r" ] && [ "$ieee80211r" != "0" ] && {
		mt_cmd iwpriv $ifname set ftenable=1
		mt_cmd iwpriv $ifname set PMFMFPC=0
		mt_cmd iwpriv $ifname set PMFMFPR=0
	}
	ApBssidNum=$((ApBssidNum + 1))
}

mtk_wds_vif_pre_config() {
	local name="$1"

	json_select config
	json_get_vars disabled encryption key key1 wds bssid wdsmode wdsphymode macaddr
	json_select ..

	[[ "$disabled" = "1" ]] && return
	[ $WDSBssidNum -gt $MTWIFI_WDS_MAX_BSSID ] && return

	echo "Generating WDS config for interface wds${MTWIFI_IFPREFIX}${WDSBssidNum}"
	ifname="wds${MTWIFI_IFPREFIX}${WDSBssidNum}"

	json_add_object data
	json_add_string ifname "$ifname"
	json_close_object

	case "$encryption" in
		psk*|psk2*|psk3*|sae*|*SAE*)
			local enc crypto
			case "$encryption" in
				psk2*) enc=WPA2PSK ;;
				psk*) enc=WPAPSK ;;
				SAE*|psk3*|sae) enc=WPA3PSK ;;
			esac
			crypto="AES"
			case "$encryption" in
				*tkipaes*|*tkip+ccmp*|*tkip+aes*|*aes+tkip*|*ccmp+tkip*) crypto="TKIPAES" ;;
				*gcmp256*) crypto="GCMP256" ;;
				*ccmp256*) crypto="CCMP256" ;;
				*gcmp*|*gcmp128*) crypto="GCMP128" ;;
				*aes*|*ccmp*|*ccmp128*) crypto="AES" ;;
				*tkip*) crypto="TKIP" ;;
			esac
			WDSAuthMode="${WDSAuthMode}${enc};"
			WDSEncType="${WDSEncType}${crypto};"
			WDSDefKeyID="${WDSDefKeyID}2;"
			;;
		WEP|wep|wep-open|wep-shared)
			[ "$encryption" == "wep-shared" ] && WDSAuthMode="${WDSAuthMode}SHARED;" || WDSAuthMode="${WDSAuthMode}OPEN;"
			WDSEncType="${WDSEncType}WEP;"
			WDSK1Tp=$(get_wep_key_type "$key1")
			[ $WDSK1Tp -eq 1 ] && key1=$(echo $key1 | cut -d ':' -f 2-)
			WDSDefKeyID="${WDSDefKeyID}1;"
			;;
		none|open)
			WDSAuthMode="${WDSAuthMode}OPEN;"
			WDSEncType="${WDSEncType}NONE;"
			WDSDefKeyID="${WDSDefKeyID}1;"
			;;
	esac
	if [ "$encryption" == "wep-open" -o "$encryption" == "wep-shared" ]; then
		echo "Wds${WDSBssidNum}Key=${key1}" >> $MTWIFI_PROFILE_PATH #WDS Key
	else
		echo "Wds${WDSBssidNum}Key=${key}" >> $MTWIFI_PROFILE_PATH #WDS Key
	fi

	WWDSEnable="${WWDSEnable}$([ "$wdsmode" != "0" -o "$wds" == "1" ] && echo "1;" || echo "0;")"
	WDS_Enable="${WDS_Enable}${wdsmode:-0};"
	WDSPhyMode="${WDSPhyMode}${wdsphymode:-HE};"
	WDSList="${WDSList}$(echo $bssid | tr 'A-Z' 'a-z');"
	WWdsMac="${WWdsMac}${macaddr};"

	mt_cmd ifconfig $ifname up
	mt_cmd echo "WDS interface $ifname now up."
	WDSBssidNum=$((WDSBssidNum + 1))
}

mtk_sta_vif_pre_config() {
	local name="$1"
	hwmode=${hwmode##11}

	json_select config
	json_get_vars disabled band encryption key key1 key2 key3 key4 ssid mode bssid wps_pushbutton pin pbc ieee80211w macaddr \
		apclipe mumimo_dl mumimo_ul ofdma_dl ofdma_ul ocv mwds
	json_select ..

	[ $stacount -gt 1 ] && return
	[[ "$disabled" = "1" ]] && return

	json_add_object data
	json_add_string ifname "$APCLI_IF"
	json_close_object

	case "$encryption" in
		psk*|sae*|*SAE*|owe*|Mixed|mixed)
			local enc crypto
			case "$encryption" in
				Mixed|mixed|psk+psk2|psk-mixed*) enc=WPAPSKWPA2PSK ;;
				psk2*) enc=WPA2PSK ;;
				psk*) enc=WPAPSK ;;
				SAE*|psk3*|sae) enc=WPA3PSK ;;
				SAE*|psk2+psk3|sae-mixed*) enc=WPA2PSKWPA3PSK ;;
				OWE*|owe) enc=OWE ;;
			esac
			crypto="AES"
			case "$encryption" in
				*tkipaes*|*tkip+ccmp*|*tkip+aes*|*aes+tkip*|*ccmp+tkip*) crypto="TKIPAES" ;;
				*gcmp256*) crypto="GCMP256" ;;
				*ccmp256*) crypto="CCMP256" ;;
				*gcmp*|*gcmp128*) crypto="GCMP128" ;;
				*aes*|*ccmp*|*ccmp128*) crypto="AES" ;;
				*tkip*) crypto="TKIP" ;;
			esac
			ApCliAuthMode="${enc}"
			ApCliEncrypType="${crypto}"
			ApCliDefKId="2"
			[ -n "$key" ] && ApCliWPAPSK="${key}"
			;;
		WEP|wep|wep-open|wep-shared)
			[ "$encryption" = "wep-shared" ] && ApCliAuthMode="SHARED" || ApCliAuthMode="OPEN"
			ApCliEncrypType="WEP"
			K1Tp=$(get_wep_key_type "$key1")
			K2Tp=$(get_wep_key_type "$key2")
			K3Tp=$(get_wep_key_type "$key3")
			K4Tp=$(get_wep_key_type "$key4")

			[ $K1Tp -eq 1 ] && key1=$(echo $key1 | cut -d ':' -f 2-)
			[ $K2Tp -eq 1 ] && key2=$(echo $key2 | cut -d ':' -f 2-)
			[ $K3Tp -eq 1 ] && key3=$(echo $key3 | cut -d ':' -f 2-)
			[ $K4Tp -eq 1 ] && key4=$(echo $key4 | cut -d ':' -f 2-)
			ApCliDefKId="${key}"
			;;
		none|open)
			ApCliAuthMode="OPEN"
			ApCliEncrypType="NONE"
			ApCliDefKId="1"
			;;
	esac
	ApCliK1Tp="${K1Tp:-0}"
	ApCliK2Tp="${K2Tp:-0}"
	ApCliK3Tp="${K3Tp:-0}"
	ApCliK4Tp="${K4Tp:-0}"

	mt_cmd ifconfig $APCLI_IF up
	mt_cmd echo "Interface $APCLI_IF now up."
	mt_cmd iwpriv $APCLI_IF set ApCliEnable=1
	mt_cmd iwpriv $APCLI_IF set ApCliAutoConnect=3
	mt_cmd iwpriv $APCLI_IF set ApCliAuthMode=${ApCliAuthMode}
	mt_cmd iwpriv $APCLI_IF set ApCliEncrypType=${ApCliEncrypType}
	if [[ "${ApCliEncrypType}" = "WEP" ]]; then
		mt_cmd iwpriv $APCLI_IF set ApCliDefaultKeyID=${ApCliDefKId}
		# mt_cmd iwpriv $APCLI_IF set ApCliKey1Type=1 # 0:hex, 1:ascii
		mt_cmd iwpriv $APCLI_IF set ApCliKey1Str=${key1##*:}
		# mt_cmd iwpriv $APCLI_IF set ApCliKey2Type=1
		mt_cmd iwpriv $APCLI_IF set ApCliKey2Str=${key2##*:}
		# mt_cmd iwpriv $APCLI_IF set ApCliKey3Type=1
		mt_cmd iwpriv $APCLI_IF set ApCliKey3Str=${key3##*:}
		# mt_cmd iwpriv $APCLI_IF set ApCliKey4Type=1
		mt_cmd iwpriv $APCLI_IF set ApCliKey4Str=${key4##*:}
	elif ! [[ "${ApCliEncrypType}" = "NONE" ]]; then
		mt_cmd iwpriv $APCLI_IF set ApCliWPAPSK=${key}
	fi
	if [[ "${ApCliAuthMode}" = "OWE" ]]; then
		mt_cmd iwpriv $APCLI_IF set ApCliOWETranIe=1
		echo "ApCliOWETranIe=${ApCliOWETranIe:-1}" >> $MTWIFI_PROFILE_PATH
	fi
	[ -z "$bssid" ] || mt_cmd iwpriv $APCLI_IF set ApCliBssid=$(echo $bssid | tr 'A-Z' 'a-z')
	[ -n "$bssid" ] && {
		mt_cmd iwpriv ra${MTWIFI_IFPREFIX}0 set MACRepeaterEn=1
		MACRepeaterEn=1
	}
	mt_cmd iwpriv $APCLI_IF set ApCliSsid=${ssid}
	mt_cmd iwpriv $APCLI_IF set ApCliDelPMKIDList=1
	if [ "$wps_pushbutton" == "1" ] && [ "${ApCliAuthMode}" != "none" ]; then
		mt_cmd echo "Enable WPS PIN for ${APCLI_IF}."
		mt_cmd iwpriv $APCLI_IF set WscConfMode=1
		mt_cmd iwpriv $APCLI_IF set WscMode=1
		mt_cmd iwpriv $APCLI_IF show WscPin
		[ -n "$ssid" ] && mt_cmd iwpriv $APCLI_IF set ApCliWscSsid="${ssid}"
		mt_cmd iwpriv $APCLI_IF set WscGetConf=1
		mt_cmd iwpriv $APCLI_IF set WscPinCode=$pin
	elif [ "$wps_pushbutton" == "2" ] && [ "${ApCliAuthMode}" != "none" ]; then
		mt_cmd echo "Enable WPS PBC for ${APCLI_IF}."
		mt_cmd iwpriv $APCLI_IF set WscConfMode=1
		mt_cmd iwpriv $APCLI_IF set WscMode=2
		mt_cmd iwpriv $APCLI_IF set WscGetConf=1
	elif [ "$ACTION" = "released" -o "$ACTION" = "pressed" ] && [ "$BUTTON" = "wps" -o "$BUTTON" = "mesh" ]; then
		mt_cmd iwpriv ra${MTWIFI_IFPREFIX}0 set ConWpsApcliPreferlface=1
		mt_cmd iwpriv $APCLI_IF set ConWpsApcliPreferlface=0
		mt_cmd iwpriv ra${MTWIFI_IFPREFIX}0 set WscConfMode=5
	else
		mt_cmd echo "Disabled WPS for ${APCLI_IF}."
		mt_cmd iwpriv $APCLI_IF set WscConfMode=0
	fi
	if [[ "$ieee80211w" = "1" ]] || [ "$encryption" == "sae-mixed" ]; then
		ApCliPMFMFPC="${ApCliPMFMFPC:-1}"
		ApCliPMFMFPR="${ApCliPMFMFPR:-0}"
	elif [[ "$ieee80211w" = "2" ]] || [ "$encryption" == "sae" -o "$encryption" == "owe" ]; then
		ApCliPMFMFPC="${ApCliPMFMFPC:-1}"
		ApCliPMFMFPR="${ApCliPMFMFPR:-1}"
	else
		ApCliPMFMFPC="${ApCliPMFMFPC:-0}"
		ApCliPMFMFPR="${ApCliPMFMFPR:-0}"
	fi

	if [ "$hwmode" == "a" -o "$band" == "5g" ]; then
		echo "ApCliMacAddress1=${macaddr}" >> $MTWIFI_PROFILE_PATH
	else
		echo "ApCliMacAddress=${macaddr}" >> $MTWIFI_PROFILE_PATH
	fi

	ApCliMWDS="${mwds:-0}"
	ApCliMuMimoDlEnable="${mumimo_dl:-0}"
	ApCliMuMimoUlEnable="${mumimo_ul:-0}"
	ApCliMuOfdmaDlEnable="${ofdma_dl:-1}"
	ApCliMuOfdmaUlEnable="${ofdma_ul:-1}"
	ApCliOCVSupport="${ocv:-0}"
	ApCliEnable="${ApCliEnable:-1}"
	ApCliSsid="${ssid}"
	ApCliBssid="$(echo $bssid | tr 'A-Z' 'a-z')"
	ApCliPESupport="${apclipe:-0}"
	stacount=$((stacount + 1))
}

mtk_mesh_vif_pre_config() {
	local name="$1"

	json_select config
	json_get_vars disabled encryption key key1 mesh_id mapmode ssid mcast_rate mode bssid wps_pushbutton pin pbc mesh_fwding mesh_rssi_threshold
	json_select ..

	[ $meshcount -gt 1 ] && return

	[[ "$disabled" = "1" ]] && return

	json_add_object data
	json_add_string ifname "$MESH_IF"
	json_close_object

	# local MeshAuthMode=${MeshAuthMode} MeshEncrypType=${MeshEncrypType}
	case "$encryption" in #加密方式
	sae*|*SAE*|Mixed|mixed)
		local enc
		local crypto
		case "$encryption" in
			psk*)
				enc=WPAPSK
			;;
			psk2*)
				enc=WPA2PSK
			;;
			SAE*|psk3*|sae)
				enc=WPA3PSK
			;;
			SAE*|psk2+psk3|sae-mixed)
				enc=WPA2PSKWPA3PSK
			;;
		esac
			crypto="AES"
		case "$encryption" in
			*tkipaes*|*tkip+ccmp*|*tkip+aes*|*aes+tkip*|*ccmp+tkip*)
				crypto="TKIPAES"
			;;
			*aes*|*ccmp*|*ccmp128*)
				crypto="AES"
			;;
			*tkip*)
				crypto="TKIP"
			;;
		esac
			MeshAuthMode="${enc}"
			MeshEncrypType="${crypto}"
			MeshDefKId="2"
	;;
	WEP|wep|wep-open|wep-shared)
		if [[ "$encryption" = "wep-shared" ]]; then
			MeshAuthMode="SHARED"
		else
			MeshAuthMode="OPEN"
		fi
		MeshK1Tp=$(get_wep_key_type "$key1")
		[ $MeshK1Tp -eq 1 ] && key1=$(echo $key1 | cut -d ':' -f 2- )
		MeshEncrypType="WEP"
		MeshDefKId="${key}"
		;;
	none|open)
		MeshAuthMode="OPEN"
		MeshEncrypType="NONE"
		MeshDefKId="1"
		;;
	esac

	mt_cmd ifconfig $MESH_IF up
	mt_cmd echo "Interface $MESH_IF now up."
	mt_cmd iwpriv ra${MTWIFI_IFPREFIX}0 set mapEnable=1
	mt_cmd iwpriv ra${MTWIFI_IFPREFIX}0 set mapR2Enable=1
	mt_cmd iwpriv ra${MTWIFI_IFPREFIX}0 set mapR3Enable=1
	# mt_cmd iwpriv ra${MTWIFI_IFPREFIX}0 set mapR4Enable=0
	mt_cmd iwpriv ra${MTWIFI_IFPREFIX}0 set mapTSEnable=1
	# MapMode="${mapmode}"
	# if [ "$mapmode" == "1" ]; then
	# 	SREnable="${SREnable:-0}"
	# 	SRMode="${SRMode:-0}"
	# else
	# 	SRMode="${SRMode:-0}"
	# fi

	MeshAutoLink="${MeshAutoLink:-1}"
	if [ "$encryption" == "wep-open" -o "$encryption" == "wep-shared" ]; then
		MeshWEPKEY="${key1}"
	else
		MeshWPAKEY="${key}"
	fi
	meshcount=$((meshcount + 1))
}

mtk_vif_post_config() {
	local name="$1"
	json_select config
	json_get_vars disabled
	json_select ..

	json_select data
	json_get_vars ifname
	json_select ..

	[ "$disabled" = "1" -o -z "$ifname" ] && return
	logger -t "mtk" "wireless_add_vif $name $ifname"
	wireless_add_vif "$name" "$ifname"
}

is_ax4200_dev() {
	[ -n "$(cat /etc/wireless/l1profile.dat |grep INDEX0_profile_path |grep mt7986-ax4200)" ] && echo yes;

	return 0
}

is_ax6000_dev() {
	[ -n "$(cat /etc/wireless/l1profile.dat |grep INDEX0_profile_path |grep mt7986-ax6000)" ] && echo yes;

	return 0
}

mtk_vif_down() {
	phy_name=${1}
	case "$phy_name" in
		rax0)
			for vif in ra0 ra1 ra2 ra3 ra4 ra5 ra6 ra7 ra8 ra9 ra10 \
				ra11 ra12 ra13 ra14 ra15 wds0 wds1 wds2 wds3 apcli0 mesh0; do
				[ -d "/sys/class/net/$vif" ] && ifconfig $vif down 2>/dev/null
			done
		;;
		ra0)
			for vif in rax0 rax1 rax2 rax3 rax4 rax5 rax6 rax7 rax8 rax9 rax10 \
				rax11 rax12 rax13 rax14 rax15 wdsx0 wdsx1 wdsx2 wdsx3 apclix0 meshx0; do
				[ -d "/sys/class/net/$vif" ] && ifconfig $vif down 2>/dev/null
			done
		;;
	esac
}

drv_mtk_teardown() {
	local phy_name=${1}
	case "$phy_name" in
		ra0)
			for vif in ra0 ra1 ra2 ra3 ra4 ra5 ra6 ra7 ra8 ra9 ra10 \
				ra11 ra12 ra13 ra14 ra15 wds0 wds1 wds2 wds3 apcli0 mesh0; do
				[ -d "/sys/class/net/$vif" ] && ifconfig $vif down 2>/dev/null
			done
		;;
		rax0)
			for vif in rax0 rax1 rax2 rax3 rax4 rax5 rax6 rax7 rax8 rax9 rax10 \
				rax11 rax12 rax13 rax14 rax15 wdsx0 wdsx1 wdsx2 wdsx3 apclix0 meshx0; do
				[ -d "/sys/class/net/$vif" ] && ifconfig $vif down 2>/dev/null
			done
		;;
	esac
}

#接口启动
drv_mtk_setup() {
	json_select config
	json_get_vars main_if phy_name mode hwmode htmode \
		txpower macfilter maclist greenap diversity \
		hidden ht_coex band #device所有配置项

	json_get_vars \
			channel:0 \
			country:CN \
			noscan:1 \
			ldpc:1 \
			txburst:1 \
			disabled:0 \
			doth:0 \
			whnat:1 \
			mlr:0 \
			bandsteering:0 \
			legacy_rates:0 \
			maxassoc:64 \
			distance:0 \
			beacon_int:100 \
			greenfield:0 \
			short_gi_20:1 \
			short_gi_40:1 \
			tx_stbc:1 \
			rx_stbc:3 \
			max_amsdu:1 \
			vendor_vht:1 \
			vht_1024:1 \
			dsss_cck_40:1
			
	json_get_vars \
			dfs:0 \
			rxldpc:1 \
			short_gi_80:1 \
			short_gi_160:1 \
			tx_stbc_2by1:1 \
			su_beamformer:1 \
			su_beamformee:1 \
			mu_beamformer:1 \
			mu_beamformee:1 \
			vht_txop_ps:1 \
			htc_vht:1 \
			beamformee_antennas:4 \
			beamformer_antennas:4 \
			rx_antenna_pattern:1 \
			tx_antenna_pattern:1 \
			vht_max_a_mpdu_len_exp:7 \
			vht_max_mpdu:11454 \
			rx_stbc:4 \
			vht_link_adapt:3 \
			vht160:2

	# 802.11ax
	json_get_vars \
			twt:0 \
			he_su_beamformer:1 \
			he_su_beamformee:1 \
			he_mu_beamformer:1 \
			he_twt_required:0 \
			he_twt_responder \
			he_spr_sr_control:3 \
			he_spr_psr_enabled:0 \
			he_spr_non_srg_obss_pd_max_offset:0 \
			he_bss_color \
			he_bss_color_enabled:1

	json_select ..

	local phy_name=${1}
	wireless_set_data phy=${phy_name}
	case "$phy_name" in
		ra0)
			WirelessMode=16
			APCLI_IF="apcli0"
			MESH_IF="mesh0"
			MTWIFI_IFPREFIX=""
			MTWIFI_DEF_BAND="2g"
			if [ -n "$(is_ax4200_dev)" ]; then
				MTWIFI_PROFILE_PATH="${MTWIFI_PROFILE_DIR}mt7986-ax4200.dbdc.b0.dat"
				MTWIFI_CMD_PATH="${MTWIFI_PROFILE_DIR}mt7986-ax4200.dbdc.cmd_b0.sh"
				MTWIFI_CMD_OPATH="${MTWIFI_PROFILE_DIR}mt7986-ax4200.dbdc.cmd_b1.sh"
			elif [ -n "$(is_ax6000_dev)" ]; then
				RddAntSel=0
				HT_RxStream=4
				HT_TxStream=4
				MTWIFI_PROFILE_PATH="${MTWIFI_PROFILE_DIR}mt7986-ax6000.dbdc.b0.dat"
				MTWIFI_CMD_PATH="${MTWIFI_PROFILE_DIR}mt7986-ax6000.dbdc.cmd_b0.sh"
				MTWIFI_CMD_OPATH="${MTWIFI_PROFILE_DIR}mt7986-ax6000.dbdc.cmd_b1.sh"
			else
				MTWIFI_PROFILE_PATH="${MTWIFI_PROFILE_DIR}mt7981.dbdc.b0.dat"
				MTWIFI_CMD_PATH="${MTWIFI_PROFILE_DIR}mt7981.dbdc.cmd_b0.sh"
				MTWIFI_CMD_OPATH="${MTWIFI_PROFILE_DIR}mt7981.dbdc.cmd_b1.sh"
			fi
		;;
		rax0)
			WirelessMode=17
			APCLI_IF="apclix0"
			MESH_IF="meshx0"
			MTWIFI_IFPREFIX="x"
			MTWIFI_DEF_BAND="5g"
			if [ -n "$(is_ax4200_dev)" ]; then
				HT_RxStream=3
				HT_TxStream=3
				MTWIFI_PROFILE_PATH="${MTWIFI_PROFILE_DIR}mt7986-ax4200.dbdc.b1.dat"
				MTWIFI_CMD_PATH="${MTWIFI_PROFILE_DIR}mt7986-ax4200.dbdc.cmd_b1.sh"
				MTWIFI_CMD_OPATH="${MTWIFI_PROFILE_DIR}mt7986-ax4200.dbdc.cmd_b0.sh"
			elif [ -n "$(is_ax6000_dev)" ]; then
				RddAntSel=2
				HT_RxStream=4
				HT_TxStream=4
				MTWIFI_PROFILE_PATH="${MTWIFI_PROFILE_DIR}mt7986-ax6000.dbdc.b1.dat"
				MTWIFI_CMD_PATH="${MTWIFI_PROFILE_DIR}mt7986-ax6000.dbdc.cmd_b1.sh"
				MTWIFI_CMD_OPATH="${MTWIFI_PROFILE_DIR}mt7986-ax6000.dbdc.cmd_b0.sh"
			else
				MTWIFI_PROFILE_PATH="${MTWIFI_PROFILE_DIR}mt7981.dbdc.b1.dat"
				MTWIFI_CMD_PATH="${MTWIFI_PROFILE_DIR}mt7981.dbdc.cmd_b1.sh"
				MTWIFI_CMD_OPATH="${MTWIFI_PROFILE_DIR}mt7981.dbdc.cmd_b0.sh"
			fi
		;;
		*)
			echo "Unknown phy:$phy_name"
			return 1
		;;
	esac

#检查配置文件目录是否存在，否则创建目录
	[ ! -d $MTWIFI_PROFILE_DIR ] && mkdir $MTWIFI_PROFILE_DIR
	echo > $MTWIFI_CMD_PATH

	ITxBfEn=1
	HT_HTC=1
	case "$band" in
		5g)
			case "$htmode" in
				HE160|HE80|HE40|HE20) WirelessMode=17; HT_BAWinSize=256 ;;
				VHT160|VHT80|VHT40|VHT20) WirelessMode=14; HT_BAWinSize=64 ;;
				HT40|HT20) WirelessMode=8; HT_BAWinSize=64 ;;
				*) WirelessMode=2; HT_BAWinSize=64 ;;
			esac
			;;
		2g)
			case "$htmode" in
				HE40|HE20) WirelessMode=16; HT_BAWinSize=256 ;;
				HT40|HT20) WirelessMode=9; HT_BAWinSize=64 ;;
				*) WirelessMode=0; HT_BAWinSize=64 ;;
			esac
			;;
		*)
			echo "Error: Unknown wireless band '$band'. Using default: ${MTWIFI_DEF_BAND:-2g}"
			band=${MTWIFI_DEF_BAND:-2g}
			;;
	esac

#HT默认模式设定
	HT_BW=1  #允许HT40
	HT_CE=1  #允许HT20/40共存
	HT_DisallowTKIP=0 #是否允许TKIP加密
	HT_GI=1 #HT_SHORT_GI
	VHT_SGI=1 #VHT_SHORT_GI
	#HT_MIMOPSMode用于省电模式设置
	#HT_MIMOPSMode=3

#HT/VHT/HE默认模式设定
	VHT_BW=1 #允许VHT
	VHT_DisallowNonVHT=0 #是否禁止非VHT客户端连接，VHT80 only

	[ "$short_gi_20" == "0" -o "$short_gi_40" == "0" ] && HT_GI=0
	[ "$short_gi_80" == "0" -o "$short_gi_160" == "0" ] && VHT_SGI=0

	case "$htmode" in
		HT20|VHT20|HE20) HT_BW=0; VHT_BW=0 ;;
		HT40|VHT40|HE40) HT_BW=1; VHT_BW=0 ;;
		VHT80|HE80) HT_BW=1; VHT_BW=1 ;;
		VHT160|HE160) HT_BW=1; VHT_BW=2 ;;
		VHT80_80|HE80_80) HT_BW=1; VHT_BW=3 ;;
		*) echo "Unknown HT Mode." ;;
	esac

#仅HT20以外才需要设置的参数
	[ "$htmode" != "HT20" ] && {
#强制HT40/VHT80
		[[ "$noscan" = "1" ]] && HT_CE=0 && MTWIFI_FORCE_HT=1
#HT HTC
		HT_HTC=1
	}

#TxPower功率设置
	[ "${txpower}" -lt "100" ] && PERCENTAGEenable=1 || PERCENTAGEenable=0

#BG保护功能设置
	# BGProtection=$([ "$legacy_rates" = "0" ] && echo 2 || echo 1)

#igmp_snooping功能设置
	igmp_snooping="$(uci -q get network.@device[0].igmp_snooping)"

#处理CountryRegion:指定信道
	[ "${country}" == "DB" ] && countryregion_a=7 && countryregion=5
	[ "${country}" == "AE" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "AL" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "DZ" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "AR" ] && countryregion_a=3 && countryregion=1
	[ "${country}" == "AM" ] && countryregion_a=2 && countryregion=1
	[ "${country}" == "AU" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "AT" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "AZ" ] && countryregion_a=2 && countryregion=1
	[ "${country}" == "BH" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "BY" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "BE" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "BZ" ] && countryregion_a=4 && countryregion=1
	[ "${country}" == "BO" ] && countryregion_a=4 && countryregion=1
	[ "${country}" == "BR" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "BN" ] && countryregion_a=4 && countryregion=1
	[ "${country}" == "BG" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "CA" ] && countryregion_a=0 && countryregion=0
	[ "${country}" == "CL" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "CN" ] && countryregion_a=0 && countryregion=1 && RDRegion=SRRC
	[ "${country}" == "CO" ] && countryregion_a=0 && countryregion=0
	[ "${country}" == "CR" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "HR" ] && countryregion_a=2 && countryregion=1
	[ "${country}" == "CY" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "CZ" ] && countryregion_a=2 && countryregion=1
	[ "${country}" == "DK" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "DO" ] && countryregion_a=0 && countryregion=0
	[ "${country}" == "EC" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "EG" ] && countryregion_a=2 && countryregion=1
	[ "${country}" == "SV" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "EE" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "FI" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "FR" ] && countryregion_a=2 && countryregion=1
	[ "${country}" == "GE" ] && countryregion_a=2 && countryregion=1
	[ "${country}" == "DE" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "GR" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "GT" ] && countryregion_a=0 && countryregion=0
	[ "${country}" == "HN" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "HK" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "HU" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "IS" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "IN" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "ID" ] && countryregion_a=4 && countryregion=1
	[ "${country}" == "IR" ] && countryregion_a=4 && countryregion=1
	[ "${country}" == "IE" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "IL" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "IT" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "JP" ] && countryregion_a=9 && countryregion=1 && RDRegion=JAP
	[ "${country}" == "JO" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "KZ" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "KP" ] && countryregion_a=5 && countryregion=1
	[ "${country}" == "KR" ] && countryregion_a=5 && countryregion=1 && RDRegion=KR
	[ "${country}" == "KW" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "LV" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "LB" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "LI" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "LT" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "LU" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "MO" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "MK" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "MY" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "MX" ] && countryregion_a=0 && countryregion=0
	[ "${country}" == "MC" ] && countryregion_a=2 && countryregion=1
	[ "${country}" == "MA" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "NL" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "NZ" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "NO" ] && countryregion_a=0 && countryregion=0
	[ "${country}" == "OM" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "PK" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "PA" ] && countryregion_a=0 && countryregion=0
	[ "${country}" == "PE" ] && countryregion_a=4 && countryregion=1
	[ "${country}" == "PH" ] && countryregion_a=4 && countryregion=1
	[ "${country}" == "PL" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "PT" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "PR" ] && countryregion_a=0 && countryregion=0
	[ "${country}" == "QA" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "RO" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "RU" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "SA" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "SG" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "SK" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "SI" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "ZA" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "ES" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "SE" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "CH" ] && countryregion_a=1 && countryregion=1
	[ "${country}" == "SY" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "TW" ] && countryregion_a=3 && countryregion=0
	[ "${country}" == "TH" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "TT" ] && countryregion_a=2 && countryregion=1
	[ "${country}" == "TN" ] && countryregion_a=2 && countryregion=1
	[ "${country}" == "TR" ] && countryregion_a=2 && countryregion=1
	[ "${country}" == "UA" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "AE" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "GB" ] && countryregion_a=1 && countryregion=1
	# [ "${country}" == "US" ] && countryregion_a=7 && countryregion=5 && RDRegion=FCC
	[ "${country}" == "UY" ] && countryregion_a=5 && countryregion=1
	[ "${country}" == "UZ" ] && countryregion_a=1 && countryregion=0
	[ "${country}" == "VE" ] && countryregion_a=5 && countryregion=1
	[ "${country}" == "VN" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "YE" ] && countryregion_a=0 && countryregion=1
	[ "${country}" == "ZW" ] && countryregion_a=0 && countryregion=1
	# [ "${country}" == "00" ] && countryregion_a=26 && countryregion=5 && RDRegion=CE

#其它相关
	case "$band" in
		5g)
			EXTCHA=1
			case "$channel" in
				40|48|56|64|104|112|120|128|136|144|153|161|169|177) EXTCHA=0;;
			esac
			[ "${channel}" == "auto" -o "${channel}" == "0" ] && {
				AutoChannelSelect=3
				channel=0
			}
			[ "${country}" == "US" ] && {
				countryregion_a=7 && RDRegion=FCC
				ACSSKIP="100;104;108;112;116;120;124;128;132;136;140;144;169;173;177"
			}
			[ "${country}" == "00" ] && {
				countryregion_a=26 && RDRegion=CE
				ACSSKIP="100;104;108;112;116;120;124;128;132;136;140;144;169;173;177"
			}
			PPEnable=1
			vht_1024=${vht_1024:-1}
			# ACSSKIP="100;104;108;112;116;120;124;128;132;136;140;144;169;173;177"
		;;
		2g)
			EXTCHA=$((channel < 7 ? 1 : 0))
			[ "${channel}" == "auto" -o "${channel}" == "0" ] && {
				AutoChannelSelect=3
				channel=0
				EXTCHA=1
			}
			[ "${country}" == "US" ] && {
				countryregion=5 && RDRegion=FCC
				ACSSKIP="14"
			}
			[ "${country}" == "00" ] && {
				countryregion=5 && RDRegion=CE
				ACSSKIP="14"
			}
			vht_1024=
			KernelRps=1
			PPEnable=0
			# ACSSKIP="14"
		;;
	esac

#设备配置文件生成
	cat > $MTWIFI_PROFILE_PATH <<EOF
#The word of "Default" must not be removed
Default
AckPolicy=0;0;0;0
AMSDU_NUM=8
APACM=0;0;0;0
APAifsn=3;7;1;1
ApCliPMFSHA256=0
ApCliTxMcs=33
APCwmax=6;10;4;3
APCwmin=4;4;3;2
ApProbeRspTimes=3
APSDCapable=1
APTxop=0;0;94;47
AutoChannelSelect=${AutoChannelSelect:-0}
AutoChannelSkipList=${ACSSKIP}
AutoProvisionEn=0
BandSteering=${bandsteering}
BasicRate=15
BeaconPeriod=${beacon_int:-100}
BFBACKOFFenable=0
BGMultiClient=${legacy_rates:-1}
BgndScanSkipCh=
BGProtection=${legacy_rates:-0}
BndStrgBssIdx=${bandsteering}
BSSACM=0;0;0;0
BSSAifsn=3;7;2;2
BSSCwmax=10;10;4;3
BSSCwmin=4;4;3;2
BssidNum=1
WdsNum=0
BSSTxop=0;0;94;47
BusyIdleFromCfg=0
BW_Enable=0
BW_Guarantee_Rate=
BW_Maximum_Rate=
BW_Priority=
BW_Root=0
CalCacheApply=0
CarrierDetect=0
Channel=${channel:-0}
ChannelGrp=0:0:0:0
CountryCode=${country:-CN}
CountryRegion=${countryregion:-1}
CountryRegionABand=${countryregion_a:-0}
CP_SUPPORT=2
CSPeriod=6
DBDC_MODE=1
WirelessMode=${WirelessMode}
ApCliWirelessMode=${WirelessMode}
DebugFlags=0
DfsCalibration=0
DfsEnable=${dfs:-0}
DfsFalseAlarmPrevent=1
DfsZeroWait=${dfs:-0}
DfsZeroWaitCacTime=255
DfsDedicatedZeroWait=0
DfsZeroWaitDefault=0
DisableOLBC=0
DLSCapable=0
Dot11vMbssid=0
DppEnable=1
DscpPriMapBss=
DscpPriMapEnable=1
E2pAccessMode=2
EAPifname=br-lan
EDCCAEnable=1
EDCCAThreshold=3:127
EDCCACfgMode=0
EthConvertMode=dongle
EtherTrafficBand=0
Ethifname=
ETxBfEnCond=1
ETxBfIncapable=0
FastConnect=1
FastRoaming=0
FineAGC=0
FixedTxMode=
ForceRoamSupport=
FQ_Enable=1
FreqDelta=0
GreenAP=${greenap:-0}
G_BAND_256QAM=${vendor_vht:-1}
HostapdDisabled=0
HT_AMSDU=1
HT_AutoBA=1
HT_BADecline=0
HT_BAWinSize=${HT_BAWinSize:-256}
HT_BSSCoexApCntThr=10
HT_BSSCoexistence=${HT_CE:-1}
HT_BW=${HT_BW:-1}
HT_DisallowTKIP=${HT_DisallowTKIP:-0}
HT_EXTCHA=${EXTCHA:-1}
HT_GI=${HT_GI:-1}
HT_HTC=${HT_HTC:-1}
HT_LDPC=${ldpc:-1}
HT_LinkAdapt=0
HT_MCS=33
HT_MIMOPSMode=3
HT_MpduDensity=4
HT_OpMode=${greenfield:-0}
HT_PROTECT=1
HT_RDG=0
HT_RxStream=${HT_RxStream:-2}
HT_STBC=${tx_stbc:-1}
HT_TxStream=${HT_TxStream:-2}
IcapMode=0
idle_timeout_interval=0
IdsEnable=0
IEEE80211H=${doth:-0}
IEEE8021X=0
IgmpSnEnable=${igmp_snooping:-0}
IsICAPFW=0
ITxBfEn=${ITxBfEn:-0}
ITxBfTimeout=0
KernelRps=${KernelRps}
LinkTestSupport=0
MACRepeaterOuiMode=2
MapEnable=0
MapAccept3Addr=1
MAP_Turnkey=0
MAP_Ext=0
MboSupport=1
MbssMaxStaNum=${maxassoc:-64}
MlmeMultiQEnable=1
MLREnable=${mlr:-0}
MultiIntr=1
MUTxRxEnable=${mu_beamformer:-1}
NoForwardingBTNBSSID=0
NoForwardingMBCast=0
NonTxBSSIndex=0
OCE_FD_FRAME=
OCE_FILS_CACHE=0
OCE_FILS_DhcpServer=
OCE_FILS_DhcpServerPort=
OCE_FILS_HLP=0
OCE_FILS_REALMS=
OCE_RNR_SUPPORT=
OCE_SUPPORT=1
OFDMA=1
PcieAspm=0
PERCENTAGEenable=${PERCENTAGEenable:-0}
PhyRateLimit=0
PktAggregate=1
PMFSHA256=0
PMKCachePeriod=10
PowerUpCckOfdm=0:0:0:0:0:0:0
PowerUpHT20=0:0:0:0:0:0:0
PowerUpHT40=0:0:0:0:0:0:0
PowerUpVHT160=0:0:0:0:0:0:0
PowerUpVHT20=0:0:0:0:0:0:0
PowerUpVHT40=0:0:0:0:0:0:0
PowerUpVHT80=0:0:0:0:0:0:0
PPDUTxType=4
PPEnable=${PPEnable}
PreAntSwitch=
PreAuthifname=br-lan
RadioLinkSelection=0
RadioOn=1
RDRegion=${RDRegion}
RED_Enable=1
RegDomain=Global
ScsEnable=0
SCSEnable=1
session_timeout_interval=0
quiet_interval=0
radius_acct_authentic=1
acct_interim_interval=0
acct_enable=1
SlotTime=9
ShortSlot=1
SkuTableIdx=0
SKUenable=0
SREnable=1
SRMode=0
SRDPDEnable=0
SRSDEnable=1
SSID=
StationKeepAlive=0
StreamMode=0
StreamModeMac0=
StreamModeMac1=
StreamModeMac2=
StreamModeMac3=
TGnWifiTest=0
Thermal=100
ThermalRecal=0
CCKTxStream=4
TurboRate=0
TxBurst=${txburst:-1}
TxPower=${txpower:-100}
TxRate=0
UAPSDCapable=1
VHT_BW=${VHT_BW:-2}
VHT_BW_SIGNAL=0
VHT_DisallowNonVHT=${VHT_DisallowNonVHT:-0}
VHT_LDPC=${ldpc:-1}
VHT_Sec80_Channel=0
VHT_SGI=${VHT_SGI:-1}
VHT_STBC=${tx_stbc:-1}
VLANID=0
VLANPriority=0
VLANTag=0
VOW_Airtime_Ctrl_En=
VOW_Airtime_Fairness_En=1
VOW_BW_Ctrl=0
VOW_Group_Backlog=
VOW_Group_DWRR_Max_Wait_Time=
VOW_Group_DWRR_Quantum=
VOW_Group_Max_Airtime_Bucket_Size=
VOW_Group_Max_Rate=
VOW_Group_Max_Rate_Bucket_Size=
VOW_Group_Max_Ratio=
VOW_Group_Max_Wait_Time=
VOW_Group_Min_Airtime_Bucket_Size=
VOW_Group_Min_Rate=
VOW_Group_Min_Rate_Bucket_Size=
VOW_Group_Min_Ratio=
VOW_Rate_Ctrl_En=
VOW_Refill_Period=
VOW_RX_En=1
VOW_Sta_BE_DWRR_Quantum=
VOW_Sta_BK_DWRR_Quantum=
VOW_Sta_DWRR_Max_Wait_Time=
VOW_Sta_VI_DWRR_Quantum=
VOW_Sta_VO_DWRR_Quantum=
VOW_WATF_Enable=
VOW_WATF_MAC_LV0=
VOW_WATF_MAC_LV1=
VOW_WATF_MAC_LV2=
VOW_WATF_MAC_LV3=
VOW_WATF_Q_LV0=
VOW_WATF_Q_LV1=
VOW_WATF_Q_LV2=
VOW_WATF_Q_LV3=
VOW_WMM_Search_Rule_Band0=
VOW_WMM_Search_Rule_Band1=
WapiAsCertPath=
WapiAsIpAddr=
WapiAsPort=
Wapiifname=
WapiPsk1=
WapiPsk10=
WapiPsk11=
WapiPsk12=
WapiPsk13=
WapiPsk14=
WapiPsk15=
WapiPsk16=
WapiPsk2=
WapiPsk3=
WapiPsk4=
WapiPsk5=
WapiPsk6=
WapiPsk7=
WapiPsk8=
WapiPsk9=
WapiPskType=
WapiUserCertPath=
WCNTest=0
WdsTxMcs=33
WHNAT=${whnat:-1}
WifiCert=1
WiFiTest=0
WirelessEvent=1
WscModelName=${hostname}
BSSColorValue=255
QoSR1Enable=1
QoSMgmtCapa=0
QuickChannelSwitch=1
BcnProt=0
ApCliBcnProt=0
WEP1Type1=0
WEP4Type1=0
WEP3Type1=0
WEP2Type1=0
EOF

#for 11ax
[ "$htmode" == "HE20" -o "$htmode" == "HE40" -o "$htmode" == "HE80" -o "$htmode" == "HE160" ] && {
	cat >> $MTWIFI_PROFILE_PATH <<EOF
ApCliUAPSDCapable=1
Disable160RuMu=0x38
HeDynSmps=1
HeErSuRxDisable=0
HeLdpc=1
HeOmiUlMuDataDisableRx=0
HeraStbcPriority=0
HE_TXOP_RTS_THLD=1023
MuEdcaOverride=1
TWTSupport=${twt:-0}
TWTInfoFrame=${twt:-0}
TxCmdMode=1
Vht1024QamSupport=${vht_1024}
WDS_VLANID=
DynWmmEnable=0
SRMeshUlMode=0
EnableCNInfo=0
ZeroLossEnable=1
FgiFltf=0
EOF
}

#for 11be
[ "$htmode" == "EHT*" ] && {
	cat >> $MTWIFI_PROFILE_PATH <<EOF
AutoChannelSkipList6G=
He6gIobMode=
He6gIobTu=
He6gIobType=
He6gOob=
PSC_ACS=
Wifi6gCap=1
EOF
}

#接口配置生成
#AP模式
#统一设置的内容:
	ApBssidNum=0
	ApAuthMode=""
	ApEncrypType=""
	ApRADIUSServer=""
	ApRADIUSPort=""
	ApRADIUSAcctServer=""
	ApRADIUSAcctPort=""
	Apown_ip_addr=""
	Apown_radius_port=""
	ApPreAuth=""
	ApRekeyMethod=""
	ApDefKId=""
	ApK1Tp=""
	ApK2Tp=""
	ApK3Tp=""
	ApK4Tp=""
	ApMWDS=""
	ApHideESSID=""
	ApWmmCapable=""
	ApRRMEnable=""
	ApRRMNeighbor=""
	Apsteeringthresold=""
	ApFtSupport=""
	ApNoForwarding=""
	ApRekeyInterval=""
	ApPMFMFPC=""
	ApPMFMFPR=""
	ApWNMEnable=""
	ApWNMNotifyEnable=""
	ApARP=""
	ApFtOtd=""
	ApFtOnly=""
	ApFtRic=""
	ApFrag=""
	ApRts=""
	ApDtim=""
	Apmumimodl=""
	Apmumimoul=""
	Apofdmadl=""
	Apofdmaul=""
	Apamsdu=""
	Apautoba=""
	Apuapsd=""
	Apocv=""
	ApWscConfMode=""
	ApWscConfStatus=""
	ApWsc4digitPinCode=""
	ApWscVendorPinCode=""
	for_each_interface "ap" mtk_ap_vif_pre_config

#For DBDC profile merging......
	BssidNum=${ApBssidNum:-1}
	sed -i "s/BssidNum=.*/BssidNum=${BssidNum}/g" $MTWIFI_PROFILE_PATH
	{
		echo "ApMWDS=${ApMWDS%?}"
		echo "HideSSID=${ApHideESSID%?}"
		echo "WmmCapable=${ApWmmCapable%?}"
		echo "AuthMode=${ApAuthMode%?}"
		echo "EncrypType=${ApEncrypType%?}"
		echo "RADIUS_Server=${ApRADIUSServer%?}"
		echo "own_ip_addr=${Apown_ip_addr%?}"
		echo "own_radius_port=${Apown_radius_port%?}"
		echo "RADIUS_Port=${ApRADIUSPort%?}"
		echo "RADIUS_Acct_Server=${ApRADIUSAcctServer%?}"
		echo "RADIUS_Acct_Port=${ApRADIUSAcctPort%?}"
		echo "PreAuth=${ApPreAuth%?}"
		echo "DefaultKeyID=${ApDefKId%?}"
		echo "Key1Type=${ApK1Tp%?}"
		echo "Key2Type=${ApK2Tp%?}"
		echo "Key3Type=${ApK3Tp%?}"
		echo "Key4Type=${ApK4Tp%?}"
		echo "RekeyMethod=${ApRekeyMethod%?}"
		echo "WNMEnable=${ApWNMEnable%?}"
		echo "WNMNotifyEnable=${ApWNMNotifyEnable%?}"
		echo "ProxyARPEnable=${ApARP%?}"
		echo "RRMEnable=${ApRRMEnable%?}"
		echo "RRMNeighbor=${ApRRMNeighbor%?}"
		echo "Steeringthresold=${Apsteeringthresold%?}"
		echo "FtSupport=${ApFtSupport%?}"
		echo "FtOtd=${ApFtOtd%?}"
		echo "FtOnly=${ApFtOnly%?}"
		echo "MuMimoDlEnable=${Apmumimodl%?}"
		echo "MuMimoUlEnable=${Apmumimoul%?}"
		echo "MuOfdmaDlEnable=${Apofdmadl%?}"
		echo "MuOfdmaUlEnable=${Apofdmaul%?}"
		echo "HT_AMSDU=${Apamsdu%?}"
		echo "HT_AutoBA=${Apautoba%?}"
		echo "APSDCapable=${Apuapsd%?}"
		echo "OCVSupport=${Apocv%?}"
		echo "PMFMFPC=${ApPMFMFPC%?}"
		echo "PMFMFPR=${ApPMFMFPR%?}"
		echo "NoForwarding=${ApNoForwarding%?}"
		echo "RekeyInterval=${ApRekeyInterval%?}"
		echo "FragThreshold=${ApFrag%?}"
		echo "RTSThreshold=${ApRts%?}"
		echo "DtimPeriod=${ApDtim%?}"
		echo "TxPreamble=${short_preamble}"
		echo "KickStaRssiLow=${kicklow}"
		echo "AssocReqRssiThres=${assocthres}"
		echo "WscConfMode=${ApWscConfMode%?}"
		echo "WscConfStatus=${ApWscConfStatus%?}"
		echo "Wsc4digitPinCode=${ApWsc4digitPinCode%?}"
		echo "WscVendorPinCode=${ApWscVendorPinCode%?}"
	} >> $MTWIFI_PROFILE_PATH

#WDS接口
	WDSBssidNum=0
	WWDSEnable=""
	WWdsMac=""
	WDS_Enable=""
	WDSList=""
	WDSAuthMode=""
	WDSEncType=""
	WDSDefKeyID=""
	WDSPhyMode=""
	for_each_interface "wds" mtk_wds_vif_pre_config

#For WDS profile merging......
	WdsNum=${WDSBssidNum:-0}
	sed -i "s/WdsNum=.*/WdsNum=${WdsNum}/g" $MTWIFI_PROFILE_PATH
	{
		echo "WDSEnable=${WWDSEnable%?}"
		echo "WdsEnable=${WDS_Enable%?}"
		echo "WdsMac=${WWdsMac%?}"
		echo "WdsList=${WDSList%?}"
		echo "WdsAuthMode=${WDSAuthMode%?}"
		echo "WdsEncrypType=${WDSEncType%?}"
		echo "WdsDefaultKeyID=${WDSDefKeyID%?}"
		echo "WdsPhyMode=${WDSPhyMode%?}"
	} >> $MTWIFI_PROFILE_PATH

#STA模式
	stacount=0
	MACRepeaterEn=""
	ApCliAuthMode=""
	ApCliEncrypType=""
	ApCliSsid=""
	ApCliBssid=""
	ApCliDefKId=""
	ApCliWPAPSK=""
	ApCliKey1Str=""
	ApCliKey2Str=""
	ApCliKey3Str=""
	ApCliKey4Str=""
	ApCliK1Tp=""
	ApCliK2Tp=""
	ApCliK3Tp=""
	ApCliK4Tp=""
	ApCliPMFMFPC=""
	ApCliPMFMFPC=""
	ApCliMWDS=""
	ApCliPESupport=""
	ApCliMuMimoDlEnable=""
	ApCliMuMimoUlEnable=""
	ApCliMuOfdmaDlEnable=""
	ApCliMuOfdmaUlEnable=""
	ApCliOCVSupport=""
	for_each_interface "sta" mtk_sta_vif_pre_config

#For STA profile merging......
	{
		echo "ApCliEnable=${ApCliEnable:-0}"
		echo "MACRepeaterEn=${MACRepeaterEn:-0}"
		echo "ApCliSsid=${ApCliSsid}"
		echo "ApCliBssid=${ApCliBssid}"
		echo "ApCliMWDS=${ApCliMWDS:-0}"
		echo "ApCliAuthMode=${ApCliAuthMode:-OPEN}"
		echo "ApCliEncrypType=${ApCliEncrypType:-NONE}"
		echo "ApCliDefaultKeyID=${ApCliDefKId:-0}"
		echo "ApCliWPAPSK=${ApCliWPAPSK}"
		echo "ApCliKey1Str=${ApCliKey1Str}"
		echo "ApCliKey2Str=${ApCliKey2Str}"
		echo "ApCliKey3Str=${ApCliKey3Str}"
		echo "ApCliKey4Str=${ApCliKey4Str}"
		echo "ApCliKey1Type=${ApCliK1Tp:-0}"
		echo "ApCliKey2Type=${ApCliK2Tp:-0}"
		echo "ApCliKey3Type=${ApCliK3Tp:-0}"
		echo "ApCliKey4Type=${ApCliK4Tp:-0}"
		echo "ApCliPMFMFPC=${ApCliPMFMFPC:-0}"
		echo "ApCliPMFMFPR=${ApCliPMFMFPR:-0}"
		echo "ApCliPESupport=${ApCliPESupport:-0}"
		echo "ApCliMuMimoDlEnable=${ApCliMuMimoDlEnable:-0}"
		echo "ApCliMuMimoUlEnable=${ApCliMuMimoUlEnable:-0}"
		echo "ApCliMuOfdmaDlEnable=${ApCliMuOfdmaDlEnable:-1}"
		echo "ApCliMuOfdmaUlEnable=${ApCliMuOfdmaUlEnable:-1}"
		echo "ApCliOCVSupport=${ApCliOCVSupport:-0}"
	} >> $MTWIFI_PROFILE_PATH

#MESH模式
	meshcount=0
	MeshAutoLink=""
	MeshAuthMode=""
	MeshEncrypType=""
	MeshDefKId=""
	MeshWEPKEY=""
	MeshWPAKEY=""
	for_each_interface "mesh" mtk_mesh_vif_pre_config

#For MESH profile merging......
	{
		echo "MapMode=${mapmode:-0}"
		echo "MeshAutoLink=${MeshAutoLink:-0}"
		echo "MeshId=${mesh_id}"
		echo "MeshAuthMode=${MeshAuthMode}"
		echo "MeshEncrypType=${MeshEncrypType}"
		echo "MeshDefaultKeyID=${MeshDefKId}"
		echo "MeshWEPKEY=${MeshWEPKEY}"
		echo "MeshWPAKEY=${MeshWPAKEY}"
		echo "MeshForward=${mesh_fwding}"
		echo "MeshRssiThreshold=${mesh_rssi_threshold}"
	} >> $MTWIFI_PROFILE_PATH

#接口上线
#加锁
	echo "MTK Interfaces Pending..."
#停用wapp
	# startwapp.sh stop
	
	if mtk_try_lock; then
		echo "Reloading WiFi with optimized settings..."
		drv_mtk_teardown $phy_name
		mtk_vif_down $phy_name
		
		# 使用优化的驱动清理
		drv_mtk_cleanup
		
#Start root device
		[ "$phy_name" == "rax0" ] && ifconfig ra0 up
#restore interfaces
		if [[ "$phy_name" = "ra0" ]]; then
			[ -f "$MTWIFI_CMD_OPATH" ] && sh $MTWIFI_CMD_OPATH
			[ -f "$MTWIFI_CMD_PATH" ] && sh $MTWIFI_CMD_PATH
		else
			[ -f "$MTWIFI_CMD_PATH" ] && sh $MTWIFI_CMD_PATH
			[ -f "$MTWIFI_CMD_OPATH" ] && sh $MTWIFI_CMD_OPATH
		fi
	else
		echo "Wait other process reload wifi"
		lock $WIFI_OP_LOCK
	fi

#AP模式
	for_each_interface "ap" mtk_vif_post_config
#WDS接口
	for_each_interface "wds" mtk_vif_post_config
#STA模式
	for_each_interface "sta" mtk_vif_post_config
#MESH模式
	for_each_interface "mesh" mtk_vif_post_config

#重启HWNAT - 只在必要时重启
	[ -d /sys/module/mtkhnat ] && {
		# 检查whnat是否改变
		local old_whnat=$(grep "WHNAT=" $MTWIFI_PROFILE_PATH 2>/dev/null | head -1 | cut -d= -f2)
		if [ "$old_whnat" != "$whnat" ]; then
			echo "WHNAT changed, restarting turboacc"
			/etc/init.d/turboacc restart
		else
			echo "WHNAT unchanged, skipping turboacc restart"
		fi
	}

#设置无线上线
	wireless_set_up

#启动wapp
	# startwapp.sh start
	
#解锁
	lock -u $WIFI_OP_LOCK
	echo "WiFi reload completed successfully"
}

add_driver mtk

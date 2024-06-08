#!/bin/sh
#
# Copyright (c) 2013-2015 D-Team Technology Co.,Ltd. ShenZhen
# Copyright (c) 2005-2015, lintel <lintel.huang@gmail.com>
# Copyright (c) 2013, Hoowa <hoowa.sun@gmail.com>
# Copyright (c) 2015-2017, GuoGuo <gch981213@gmail.com>
# Copyright (c) 2020,2023, jjm2473 <jjm2473@gmail.com>
# Copyright (c) 2022,2023, nanchuci <nanchuci023@gmail.com>
#
# 	netifd config script for MT7615/MT7915/MT798X DBDC mode.
#
# 	嘿，对着屏幕的哥们,为了表示对原作者辛苦工作的尊重，任何引用跟借用都不允许你抹去所有作者的信息,请保留这段话。
#
. /lib/netifd/netifd-wireless.sh

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

mt_cmd() {
	echo "$@" >> $MTWIFI_CMD_PATH
	#eval $@
}

#读取device相关设置项并写入json
drv_mtk_init_device_config() {
	config_add_string path channel hwmode htmode country 'macaddr:macaddr' twt
	config_add_string txburst cell_density
	config_add_string distance
	config_add_int beacon_int chanbw frag rts dtim_period vendor_vht vht_1024 mu_beamformer whnat
	config_add_int rxantenna txantenna antenna_gain txpower min_tx_power noscan
	config_add_int num_global_macaddr multiple_bssid legacy_rates
	config_add_boolean greenap diversity noscan ht_coex acs_exclude_dfs background_radar
	config_add_int powersave doth
	config_add_int maxassoc
	config_add_boolean hidessid bndstrg isolate dfs
	config_add_array channels
	config_add_array scan_list
}

#读取iface相关设置项并写入json
drv_mtk_init_iface_config() {
	config_add_boolean disabled
	config_add_string mode ifname 'macaddr:macaddr' bssid 'ssid:string' encryption
	config_add_string auth_server auth_port auth_secret acct_secret own_ip_addr own_radius_port
	config_add_boolean hidden isolate isolate_mb br_isolate_mode ieee80211k ieee80211v ieee80211r
	config_add_boolean powersave enable coloring ldpc lofdm mesh_fwding
	config_add_string key key1 key2 key3 key4
	config_add_string wds_bridge wps_pushbutton pin mesh_id mapmode mesh_rssi_threshold
	config_add_string macfilter 'macfile:file' nasid mobility_domain r1_key_holder reassociation_deadline ft_over_ds
	config_add_array 'maclist:list(macaddr)' r0kh r1kh

	config_add_boolean wds wmm wnm_sleep_mode bss_transition mbo rrm_neighbor_report rrm_beacon_report ft_psk_generate_local pmk_r1_push
	config_add_int apclipe short_preamble wpa_group_rekey rsn_preauth
	config_add_int max_listen_int ieee80211w time_advertisement 'port:port'
	config_add_int disassoc_low_ack kicklow assocthres
	config_add_string wdsenctype wdskey wdsphymode macaddr time_zone
	config_add_int wdsen mumimo_dl mumimo_ul ofdma_dl ofdma_ul
	config_add_int start_disabled
}

get_wep_key_type() {
	local KeyLen=$(expr length "$1")
	if [ $KeyLen -eq 10 ] || [ $KeyLen -eq 26 ] || [ $KeyLen -eq 32 ]
	then
		echo 0
	else
		echo 1
	fi	
}

mtk_ap_vif_pre_config() {
	local name="$1"

	json_select config
	json_get_vars disabled encryption auth_secret acct_secret auth_server auth_port acct_server \
		acct_port key key1 key2 key3 key4 wmm own_ip_addr own_radius_port macaddr short_preamble wpa_group_rekey \
		ssid mode wps_pushbutton pin pbc isolate hidden disassoc_low_ack kicklow assocthres rsn_preauth \
		ieee80211k ieee80211v ieee80211r ieee80211w macfilter nasid mobility_domain r1_key_holder reassociation_deadline r0kh r1kh \
		ft_over_ds ft_psk_generate_local pmk_r1_push rrm_neighbor_report rrm_beacon_report wnm_sleep_mode bss_transition \
		mumimo_dl mumimo_ul ofdma_dl ofdma_ul
	json_get_values maclist maclist
	set_default wmm 1
	set_default isolate 0
	set_default short_preamble 1
	set_default wpa_group_rekey 3600
	set_default disassoc_low_ack 0
	set_default kicklow 0
	set_default assocthres 0
	set_default ieee80211k 0
	set_default ieee80211v 0
	set_default ieee80211r 0
	set_default mumimo_dl 0
	set_default mumimo_ul 0
	set_default ofdma_dl 0
	set_default ofdma_ul 0
	set_default auth_port 1812
	set_default acct_port 1813
	json_select ..

	[[ "$disabled" = "1" ]] && return
	[ ${ApBssidNum} -gt ${MTWIFI_DEF_MAX_BSSID} ] && return 

	echo "Generating ap config for interface ra${MTWIFI_IFPREFIX}${ApBssidNum}"
	ifname="ra${MTWIFI_IFPREFIX}${ApBssidNum}"

	json_add_object data
	json_add_string ifname "$ifname"
	json_close_object

	#MAC过滤方式和自定义MAC地址相关设定 由于编号问题......扔在这了......
	ra_maclist="${maclist// /;};"
	case "$macfilter" in
	allow)
		echo "Interface ${ifname} has Macfilter.Allow list:${ra_maclist}"
		echo "AccessPolicy${ApBssidNum}=1" >> $MTWIFI_PROFILE_PATH
		echo "AccessControlList${ApBssidNum}=${ra_maclist}" >> $MTWIFI_PROFILE_PATH
	;;
	deny)
		echo "Interface ${ifname} has Macfilter.Deny list:${ra_maclist}"
		echo "AccessPolicy${ApBssidNum}=2" >> $MTWIFI_PROFILE_PATH
		echo "AccessControlList${ApBssidNum}=${ra_maclist}" >> $MTWIFI_PROFILE_PATH
	;;
	esac
	if [ "$ApBssidNum" == "0" ]; then
		echo "MacAddress=${macaddr}" >> $MTWIFI_PROFILE_PATH
	else
		echo "MacAddress${ApBssidNum}=${macaddr}" >> $MTWIFI_PROFILE_PATH
	fi

	let ApBssidNum+=1
	echo "SSID${ApBssidNum}=${ssid}" >> $MTWIFI_PROFILE_PATH #SSID
	case "$encryption" in #加密方式
	wpa*|psk*|WPA*|sae*|*SAE*|owe*|*8021x*|*eap*|Mixed|mixed)
		local enc
		local crypto
		case "$encryption" in
			Mixed|mixed|psk+psk2|psk-mixed*)
				enc=WPAPSKWPA2PSK
			;;
			psk2*)
				enc=WPA2PSK
			;;
			psk*)
				enc=WPAPSK
			;;
			SAE*|psk3*|sae)
				enc=WPA3PSK
			;;
			SAE*|psk2+psk3|sae-mixed)
				enc=WPA2PSKWPA3PSK
			;;
			8021x*|eap*|wpa)
				enc=WPA
			;;
			8021x*|eap2*|wpa2)
				enc=WPA2
			;;
			8021x*|eap+eap2|wpa-mixed)
				enc=WPA1WPA2
			;;
			8021x*|eap3*|wpa3)
				enc=WPA3
			;;
			8021x*|eap2+eap3|wpa3-mixed)
				enc=WPA2WPA3
			;;
			8021x*|eap192*|wpa3-192)
				enc=WPA3-192
			;;
			OWE*|owe)
				enc=OWE
			;;
		esac
			crypto="AES"
		case "$encryption" in
			*tkipaes*|*tkip+ccmp*|*tkip+aes*|*aes+tkip*|*ccmp+tkip*)
				crypto="TKIPAES"
			;;
			*gcmp256*)
				crypto="GCMP256"
			;;
			*ccmp256*)
				crypto="CCMP256"
			;;
			*gcmp*|*gcmp128*)
				crypto="GCMP"
			;;
			*aes*|*ccmp*|*ccmp128*)
				crypto="AES"
			;;
			*tkip*) 
				crypto="TKIP"
				echo "Warning!!! TKIP is not support in 802.11n 40Mhz!!!"
			;;
		esac
			if [ "$encryption" == "wpa3-192" ]; then
				ApAuthMode="${ApAuthMode}${enc};"
				ApEncrypType="${ApEncrypType}GCMP256;"
			else
				ApAuthMode="${ApAuthMode}${enc};"
				ApEncrypType="${ApEncrypType}${crypto};"
			fi
			ApDefKId="${ApDefKId}2;"
			echo "WPAPSK${ApBssidNum}=${key}" >> $MTWIFI_PROFILE_PATH
			echo "RADIUS_Key${ApBssidNum}=${auth_secret}" >> $MTWIFI_PROFILE_PATH
	;;
	WEP|wep|wep-open|wep-shared)
		if [ "$encryption" == "wep-shared" ]; then
			ApAuthMode="${ApAuthMode}SHARED;"
		else
			ApAuthMode="${ApAuthMode}OPEN;"
		fi
		ApEncrypType="${ApEncrypType}WEP;"
		K1Tp=$(get_wep_key_type "$key1")
		K2Tp=$(get_wep_key_type "$key2")
		K3Tp=$(get_wep_key_type "$key3")
		K4Tp=$(get_wep_key_type "$key4")

		[ $K1Tp -eq 1 ] && key1=$(echo $key1 | cut -d ':' -f 2- )
		[ $K2Tp -eq 1 ] && key2=$(echo $key2 | cut -d ':' -f 2- )
		[ $K3Tp -eq 1 ] && key3=$(echo $key3 | cut -d ':' -f 2- )
		[ $K4Tp -eq 1 ] && key4=$(echo $key4 | cut -d ':' -f 2- )
		echo "Key1Str${ApBssidNum}=${key1}" >> $MTWIFI_PROFILE_PATH
		echo "Key2Str${ApBssidNum}=${key2}" >> $MTWIFI_PROFILE_PATH
		echo "Key3Str${ApBssidNum}=${key3}" >> $MTWIFI_PROFILE_PATH
		echo "Key4Str${ApBssidNum}=${key4}" >> $MTWIFI_PROFILE_PATH
		ApDefKId="${ApDefKId}${key};"
	;;
	none|open)
		ApAuthMode="${ApAuthMode}OPEN;"
		ApEncrypType="${ApEncrypType}NONE;"
		ApDefKId="${ApDefKId}1;"
	;;
	esac
	if [ "$encryption" == "open" -o "$encryption" == "owe" ]; then
		ApRekeyMethod="${ApRekeyMethod}DISABLE;"
	else
		ApRekeyMethod="${ApRekeyMethod}TIME;"
	fi
	ApK1Tp="${ApK1Tp}${K1Tp:-0};"
	ApK2Tp="${ApK2Tp}${K2Tp:-0};"
	ApK3Tp="${ApK3Tp}${K3Tp:-0};"
	ApK4Tp="${ApK4Tp}${K4Tp:-0};"
	ApHideESSID="${ApHideESSID}${hidden:-0};"
	ApRADIUSServer="${ApRADIUSServer}${auth_server};"
	ApRADIUSPort="${ApRADIUSPort}${auth_port};"
	ApRADIUSAcctServer="${ApRADIUSAcctServer}${acct_server};"
	ApRADIUSAcctPort="${ApRADIUSAcctPort}${acct_port};"
	ApRADIUSAcctKey="${ApRADIUSAcctKey}${acct_secret};"
	ApPreAuth="${ApPreAuth}${rsn_preauth:-0};"
	ApRRMEnable="${ApRRMEnable}${ieee80211k};"
	ApFtSupport="${ApFtSupport}${ieee80211r};"
	ApNoForwarding="${ApNoForwarding}${isolate};"
	ApRekeyInterval="${ApRekeyInterval}${wpa_group_rekey};"
	ApFtOtd="${ApFtOtd}${ft_over_ds:-0};"
	ApFtOnly="${ApFtOnly}${ft_psk_generate_local:-0};"
	ApFtRic="${ApFtRic}${pmk_r1_push:-0};"
	Apmumimodl="${Apmumimodl}${mumimo_dl};"
	Apmumimoul="${Apmumimoul}${mumimo_ul};"
	Apofdmadl="${Apofdmadl}${ofdma_dl};"
	Apofdmaul="${Apofdmaul}${ofdma_ul};"
	echo "FtMdId${ApBssidNum}=${mobility_domain}" >> $MTWIFI_PROFILE_PATH
	echo "FtR0khId${ApBssidNum}=${nasid}" >> $MTWIFI_PROFILE_PATH
	echo "FtR1khId${ApBssidNum}=${r1_key_holder}" >> $MTWIFI_PROFILE_PATH
	echo "AssocDeadLine${ApBssidNum}=${reassociation_deadline}" >> $MTWIFI_PROFILE_PATH

	mt_cmd ifconfig $ifname up
	mt_cmd echo "Interface $ifname now up."
	# mt_cmd iwpriv ra${MTWIFI_IFPREFIX}0 set PartialScanNumOfCh=4
	if [ "$ieee80211w" == "1" ] || [ "$encryption" == "sae-mixed" -o "$encryption" == "wpa3-mixed" ]; then
		ApPMFMFPC="${ApPMFMFPC}${PMFMFPC:-1};"
		ApPMFMFPR="${ApPMFMFPR}${PMFMFPR:-0};"
	elif [ "$ieee80211w" == "2" ] || [ "$encryption" == "sae" -o "$encryption" == "owe" -o "$encryption" == "wpa3" -o "$encryption" == "wpa3-192" ]; then
		ApPMFMFPC="${ApPMFMFPC}${PMFMFPC:-1};"
		ApPMFMFPR="${ApPMFMFPR}${PMFMFPR:-1};"
	else
		ApPMFMFPC="${ApPMFMFPC}${PMFMFPC:-0};"
		ApPMFMFPR="${ApPMFMFPR}${PMFMFPR:-0};"
	fi
	# if [ "$wps" = "pbc" -o \( "$wps" = "pin" -a "$encryption" != "none" \) ]; then
	if [ "$wps_pushbutton" == "1" ] && [ "$encryption" != "none" ]; then
		mt_cmd echo "Enable WPS PIN for ${ifname}."
		mt_cmd iwpriv $ifname set WscConfMode=4
		mt_cmd iwpriv $ifname set WscConfStatus=2
		mt_cmd iwpriv $ifname set WscMode=1
		mt_cmd iwpriv $ifname set WscGetConf=1
		mt_cmd iwpriv $ifname set WscGenPinCode=1
		mt_cmd iwpriv $ifname set WscV2Support=1
		mt_cmd iwpriv $ifname set WscPinCode=$pin
	elif [ "$wps_pushbutton" == "2" ] && [ "$encryption" != "none" ]; then
		mt_cmd echo "Enable WPS PBC for ${ifname}."
		mt_cmd iwpriv $ifname set WscConfMode=4
		mt_cmd iwpriv $ifname set WscConfStatus=2
		mt_cmd iwpriv $ifname set WscMode=2
		mt_cmd iwpriv $ifname set WscGetConf=1
		mt_cmd iwpriv $ifname set WscV2Support=1
	else
		mt_cmd echo "Disabled WPS for ${ifname}."
		mt_cmd iwpriv $ifname set WscConfMode=0
	fi
	mt_cmd echo "Other settings for ${ifname}."
	[ -n "$disassoc_low_ack" ] && [ "$disassoc_low_ack" != "0" ] && {
		mt_cmd iwpriv $ifname set KickStaRssiLow=$kicklow
		mt_cmd iwpriv $ifname set AssocReqRssiThres=$assocthres
	}
	[ -n "$ieee80211k" ] && [ "$ieee80211k" != "0" ] && mt_cmd iwpriv $ifname set rrmenable=1
	# [ -n "$ieee80211v" ] && [ "$ieee80211v" != "0" ] && mt_cmd iwpriv $ifname set wnmenable=1
	[ -n "$ieee80211r" ] && [ "$ieee80211r" != "0" ] && mt_cmd iwpriv $ifname set ftenable=1
	# [ -n "$ieee80211w" ] && [ "$ieee80211w" != "0" ] && mt_cmd iwpriv $ifname set pmfenable=1
}

mtk_wds_vif_pre_config() {
	local name="$1"

	json_select config
	json_get_vars disabled encryption key key1 key2 key3 key4 mode bssid wdsen wdsenctype wdskey wdswepid wdsphymode wdstxmcs
	set_default wdsen 3
	set_default wdsphymode "GREENFIELD"
	json_select ..

	[[ "$disabled" = "1" ]] && return
	[ ${WDSBssidNum} -gt ${MTWIFI_WDS_MAX_BSSID} ] && return

	echo "Generating WDS config for interface wds${MTWIFI_IFPREFIX}${WDSBssidNum}"
	ifname="wds${MTWIFI_IFPREFIX}${WDSBssidNum}"

	json_add_object data
	json_add_string ifname "$ifname"
	json_close_object

	case "$encryption" in #加密方式
	psk*|psk2*|psk3*|sae*|*SAE*)
		local enc
		local crypto
		case "$encryption" in
			psk2*)
				enc=WPA2PSK
			;;
			psk*)
				enc=WPAPSK
			;;
			SAE*|psk3*|sae)
				enc=WPA3PSK
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
				echo "Warning!!! TKIP is not support in 802.11n 40Mhz!!!"
			;;
		esac
			WdsEncrypType="${WdsEncrypType}${crypto};"
			WdsDefKId="${WdsDefKId}2;"
			# echo "Wds${WDSBssidNum}Key=${key}" >> $MTWIFI_PROFILE_PATH #WDS Key
			;;
	WEP|wep|wep-open|wep-shared)
		WdsEncrypType="${WdsEncrypType}WEP;"
		WdsK1Tp=$(get_wep_key_type "$key1")
		[ $WdsK1Tp -eq 1 ] && key1=$(echo $key1 | cut -d ':' -f 2- )
		WdsDefKId="${WdsDefKId}1;"
		;;
	none|open)
		WdsEncrypType="${WdsEncrypType}NONE;"
		WdsDefKId="${WdsDefKId}1;"
		;;
	esac

	if [ ! -z "$bssid" ] && [ "$wdsen" -eq 3 ] || [ "$wdsen" -eq 4 ]; then
		WdsList="${WdsList}$(echo $bssid | tr 'A-Z' 'a-z');"
	elif [ "$wdsen" -eq 2 ]; then
		WdsList="${WdsList}${bssid};"
	fi

	if [ "$encryption" == "wep-open" -o "$encryption" == "wep-shared" ]; then
		echo "Wds${WDSBssidNum}Key=${key1}" >> $MTWIFI_PROFILE_PATH #WDS Key
	else
		echo "Wds${WDSBssidNum}Key=${key}" >> $MTWIFI_PROFILE_PATH #WDS Key
	fi

	# Wdsen="${Wdsen}${wdsen};"
	WdsPhyMode="${WdsPhyMode}${wdsphymode};"

	mt_cmd ifconfig $ifname up
	mt_cmd echo "WDS interface $ifname now up."
	let WDSBssidNum+=1
}

mtk_sta_vif_pre_config() {
	local name="$1"

	json_select config
	json_get_vars disabled encryption key key1 key2 key3 key4 ssid mode bssid wps_pushbutton pin pbc ieee80211w macaddr \
		apclipe mumimo_dl mumimo_ul ofdma_dl ofdma_ul	
	json_select ..

	[ $stacount -gt 1 ] && {
		return
	}

	[[ "$disabled" = "1" ]] && return

	json_add_object data
	json_add_string ifname "$APCLI_IF"
	json_close_object

	# local ApCliAuthMode=${ApCliAuthMode} ApCliEncrypType=${ApCliEncrypType}
	case "$encryption" in #加密方式
	psk*|sae*|*SAE*|owe*|Mixed|mixed)
		local enc
		local crypto
		case "$encryption" in
			Mixed|mixed|psk+psk2|psk-mixed*)
				enc=WPAPSKWPA2PSK
			;;
			psk2*)
				enc=WPA2PSK
			;;
			psk*)
				enc=WPAPSK
			;;
			SAE*|psk3*|sae)
				enc=WPA3PSK
			;;
			SAE*|psk2+psk3|sae-mixed)
				enc=WPA2PSKWPA3PSK
			;;
			OWE*|owe)
				enc=OWE
			;;
		esac
			crypto="AES"
		case "$encryption" in
			*tkipaes*|*tkip+ccmp*|*tkip+aes*|*aes+tkip*|*ccmp+tkip*)
				crypto="TKIPAES"
			;;
			*gcmp256*)
				crypto="GCMP256"
			;;
			*ccmp256*)
				crypto="CCMP256"
			;;
			*gcmp*|*gcmp128*)
				crypto="GCMP"
			;;
			*aes*|*ccmp*|*ccmp128*)
				crypto="AES"
			;;
			*tkip*)
				crypto="TKIP"
				echo "Warning!!! TKIP is not support in 802.11n 40Mhz!!!"
			;;
		esac
			ApCliAuthMode="${enc}"
			ApCliEncrypType="${crypto}"
			ApCliDefKId="2"
			ApCliWPAPSK="${key}"
	;;
	WEP|wep|wep-open|wep-shared)
		if [[ "$encryption" = "wep-shared" ]]; then
			ApCliAuthMode="SHARED"
		else
			ApCliAuthMode="OPEN"
		fi
		ApCliEncrypType="WEP"
		K1Tp=$(get_wep_key_type "$key1")
		K2Tp=$(get_wep_key_type "$key2")
		K3Tp=$(get_wep_key_type "$key3")
		K4Tp=$(get_wep_key_type "$key4")

		[ $K1Tp -eq 1 ] && key1=$(echo $key1 | cut -d ':' -f 2- )
		[ $K2Tp -eq 1 ] && key2=$(echo $key2 | cut -d ':' -f 2- )
		[ $K3Tp -eq 1 ] && key3=$(echo $key3 | cut -d ':' -f 2- )
		[ $K4Tp -eq 1 ] && key4=$(echo $key4 | cut -d ':' -f 2- )
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
		echo "MACRepeaterEn=1" >> $MTWIFI_PROFILE_PATH
	}
	mt_cmd iwpriv $APCLI_IF set ApCliSsid=${ssid}
	mt_cmd iwpriv $APCLI_IF set ApCliDelPMKIDList=1
	if [ "$wps_pushbutton" == "1" ] && [ "${ApCliAuthMode}" != "none" ]; then
		mt_cmd echo "Enable WPS PIN for ${APCLI_IF}."
		mt_cmd iwpriv $APCLI_IF set WscConfMode=1
		mt_cmd iwpriv $APCLI_IF set WscMode=1
		mt_cmd iwpriv $APCLI_IF show WscPin
		# mt_cmd iwpriv $APCLI_IF set ApCliWscSsid=$ssid
		mt_cmd iwpriv $APCLI_IF set WscGetConf=1
		mt_cmd iwpriv $APCLI_IF set WscPinCode=$pin
		# echo "ApCliWscSsid=${ssid}" >> $MTWIFI_PROFILE_PATH
	elif [ "$wps_pushbutton" == "2" ] && [ "${ApCliAuthMode}" != "none" ]; then
		mt_cmd echo "Enable WPS PBC for ${APCLI_IF}."
		mt_cmd iwpriv $APCLI_IF set WscConfMode=1
		mt_cmd iwpriv $APCLI_IF set WscMode=2
		mt_cmd iwpriv $APCLI_IF set WscGetConf=1
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

	ApCliMuMimoDlEnable="${mumimo_dl:-0}"
	ApCliMuMimoUlEnable="${mumimo_ul:-0}"
	ApCliMuOfdmaDlEnable="${ofdma_dl:-0}"
	ApCliMuOfdmaUlEnable="${ofdma_ul:-0}"
	# ApCliMacAddress="${macaddr}"
	ApCliEnable="${ApCliEnable:-1}"
	ApCliSsid="${ssid}"
	ApCliBssid="$(echo $bssid | tr 'A-Z' 'a-z')"
	ApCliPESupport="${apclipe}"
	let stacount+=1
}

mtk_mesh_vif_pre_config() {
	local name="$1"

	json_select config
	json_get_vars disabled encryption key key1 mesh_id mapmode ssid mcast_rate mode bssid wps_pushbutton pin pbc mesh_fwding mesh_rssi_threshold
	json_select ..

	[ $meshcount -gt 1 ] && {
		return
	}

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
	mt_cmd iwpriv ra${MTWIFI_IFPREFIX}0 set mapEnable=0
	mt_cmd iwpriv ra${MTWIFI_IFPREFIX}0 set mapR2Enable=1
	mt_cmd iwpriv ra${MTWIFI_IFPREFIX}0 set mapR3Enable=1
	# mt_cmd iwpriv ra${MTWIFI_IFPREFIX}0 set mapR4Enable=1
	mt_cmd iwpriv ra${MTWIFI_IFPREFIX}0 set mapTSEnable=1

	MeshAutoLink="${MeshAutoLink:-1}"
	if [ "$encryption" == "wep-open" -o "$encryption" == "wep-shared" ]; then
		MeshWEPKEY="${key1}"
	else
		MeshWPAKEY="${key}"
	fi
	let meshcount+=1
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

mtk_vif_down() {
	phy_name=${1}
	case "$phy_name" in
		rax0)
			for vif in ra0 ra1 ra2 ra3 ra4 ra5 ra6 ra7 ra8 ra9 ra10 \
				ra11 ra12 ra13 ra14 ra15 wds0 wds1 wds2 wds3 apcli0 mesh0; do
				[ -d "/sys/class/net/$vif" ] && ifconfig $vif down
			done
		;;
		ra0)
			for vif in rax0 rax1 rax2 rax3 rax4 rax5 rax6 rax7 rax8 rax9 rax10 \
				rax11 rax12 rax13 rax14 rax15 wdsx0 wdsx1 wdsx2 wdsx3 apclix0 meshx0; do
				[ -d "/sys/class/net/$vif" ] && ifconfig $vif down
			done
		;;
	esac
}

drv_mtk_cleanup() {
	return
}

drv_mtk_teardown() {
	phy_name=${1}
	case "$phy_name" in
		ra0)
			for vif in ra0 ra1 ra2 ra3 ra4 ra5 ra6 ra7 ra8 ra9 ra10 \
				ra11 ra12 ra13 ra14 ra15 wds0 wds1 wds2 wds3 apcli0 mesh0; do
				# iwpriv $vif set DisConnectAllSta=1
				[ -d "/sys/class/net/$vif" ] && ifconfig $vif down
			done
		;;
		rax0)
			for vif in rax0 rax1 rax2 rax3 rax4 rax5 rax6 rax7 rax8 rax9 rax10 \
				rax11 rax12 rax13 rax14 rax15 wdsx0 wdsx1 wdsx2 wdsx3 apclix0 meshx0; do
				# iwpriv $vif set DisConnectAllSta=1
				[ -d "/sys/class/net/$vif" ] && ifconfig $vif down
			done
		;;
	esac
}

#接口启动
drv_mtk_setup() {
	json_select config
	json_get_vars main_if phy_name macaddr channel mode hwmode htmode \
		txpower country macfilter maclist greenap diversity frag \
		rts hidden disabled ht_coex #device所有配置项
		
	json_get_vars \
			noscan:1 \
			ldpc:1 \
			txburst:1 \
			twt:0 \
			doth:0 \
			whnat:1 \
			legacy_rates:0 \
			maxassoc:64 \
			frag:2346 \
			rts:2347 \
			dtim_period:1 \
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
			mu_beamformer:0 \
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
			he_su_beamformer:1 \
			he_su_beamformee:1 \
			he_mu_beamformer:1

	json_select ..

	phy_name=${1}
	wireless_set_data phy=${phy_name}
	case "$phy_name" in
		ra0)
			WirelessMode=16
			APCLI_IF="apcli0"
			MESH_IF="mesh0"
			MTWIFI_IFPREFIX=""
			MTWIFI_DEF_BAND="g"
			MTWIFI_PROFILE_PATH="${MTWIFI_PROFILE_DIR}mt7981.dbdc.b0.dat"
			MTWIFI_CMD_PATH="${MTWIFI_PROFILE_DIR}mt7981.dbdc.cmd_b0.sh"
			MTWIFI_CMD_OPATH="${MTWIFI_PROFILE_DIR}mt7981.dbdc.cmd_b1.sh"
		;;
		rax0)
			WirelessMode=17
			APCLI_IF="apclix0"
			MESH_IF="meshx0"
			MTWIFI_IFPREFIX="x"
			MTWIFI_DEF_BAND="a"
			MTWIFI_PROFILE_PATH="${MTWIFI_PROFILE_DIR}mt7981.dbdc.b1.dat"
			MTWIFI_CMD_PATH="${MTWIFI_PROFILE_DIR}mt7981.dbdc.cmd_b1.sh"
			MTWIFI_CMD_OPATH="${MTWIFI_PROFILE_DIR}mt7981.dbdc.cmd_b0.sh"
		;;
		*)
			echo "Unknown phy:$phy_name"
			return 1
	esac

#检查配置文件目录是否存在，否则创建目录
	[ ! -d $MTWIFI_PROFILE_DIR ] && mkdir $MTWIFI_PROFILE_DIR
	echo > $MTWIFI_CMD_PATH

	hwmode=${hwmode##11}
	case "$hwmode" in
		a)
			WirelessMode=17
			ITxBfEn=1
			HT_HTC=1
		;;
		g)
			WirelessMode=16
			ITxBfEn=1
			HT_HTC=1
		;;
		*)
			echo "Unknown wireless mode.Use default value:${WirelessMode}"
			hwmode=${MTWIFI_DEF_BAND}
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
		HT20 |\
		VHT20 |\
		HE20)
			HT_BW=0
			VHT_BW=0
		;;
		HT40 |\
		VHT40 |\
		HE40)
			HT_BW=1
			VHT_BW=0
			VHT_DisallowNonVHT=0
		;;
		VHT80 |\
		HE80)
			HT_BW=1
			VHT_BW=1
		;;
		VHT160 |\
		HE160)
			HT_BW=1
			VHT_BW=2
		;;
		VHT80_80 |\
		HE80_80)
			HT_BW=1
			VHT_BW=3
		;;
		*) 
		echo "Unknown HT Mode."
		;;
	esac

#仅HT20以外才需要设置的参数
	[ "$htmode" != "HT20" ] && {
#强制HT40/VHT80
		[[ "$noscan" = "1" ]] && HT_CE=0 && MTWIFI_FORCE_HT=1
#HT HTC
		HT_HTC=1
	}

#TxPower功率设置
	[ "${txpower}" -lt "100" ] && {
		PERCENTAGEenable=1
		txpower=${txpower}
	}
#或者
	[ "${txpower}" -eq "100" ] && {
		PERCENTAGEenable=0
		txpower=100
	}

#BG保护功能设置
	[ "${legacy_rates}" == "0" ] && {
		BGProtection=2
	}
#或者
	[ "${legacy_rates}" == "1" ] && {
		BGProtection=1
	}

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
	[ "${country}" == "CN" ] && countryregion_a=0 && countryregion=1
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

#其它相关
	case "$hwmode" in
		a)
			EXTCHA=1
			[ "${channel}" != "auto" ] && [ "${channel}" != "0" ] && [ "$(( (${channel} / 4) % 2 ))" == "0" ] && EXTCHA=0
			# [ "${channel}" == "165" ] && EXTCHA=0
			[ "${channel}" == "auto" -o "${channel}" == "0" ] && {
				AutoChannelSelect=3
				channel=0
			}
			[ "${country}" == "US" ] && {
				countryregion_a=7 && RDRegion=FCC
				ACSSKIP="100;104;108;112;116;120;124;128;132;136;140;144;169;173;177"
			}
			PPEnable=1
			# ACSSKIP="100;104;108;112;116;120;124;128;132;136;140;144;169;173;177"
		;;
		g)
			EXTCHA=0
			[ "${channel}" != "auto" ] && [ "${channel}" != "0" ] && [ "${channel}" -lt "7" ] && EXTCHA=1
			[ "${channel}" == "auto" -o "${channel}" == "0" ] && {
				AutoChannelSelect=3
				channel=0
				EXTCHA=1
			}
			[ "${country}" == "US" ] && {
				countryregion=5 && RDRegion=FCC
				ACSSKIP="14"
			}
			vht_1024=${Vht1024QamSupport:-0}
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
AntCtrl=
APACM=0;0;0;0
APAifsn=3;7;1;1
ApCliNum=2
ApCliPMFSHA256=0
ApCliTxMcs=33
ApCliWirelessMode=
APCwmax=6;10;4;3
APCwmin=4;4;3;2
ApMWDS=1
ApCliMWDS=1
ApProbeRspTimes=3
APSDCapable=1
APTxop=0;0;94;47
AutoChannelSelect=${AutoChannelSelect:-0}
AutoChannelSkipList=${ACSSKIP}
AutoProvisionEn=0
BandSteering=0
BasicRate=15
BeaconPeriod=${beacon_int:-100}
BFBACKOFFenable=0
BfSmthIntlBbypass=1
BGMultiClient=${legacy_rates}
BgndScanSkipCh=
BGProtection=${BGProtection:-0}
BndStrgBssIdx=
BSSACM=0;0;0;0
BSSAifsn=3;7;2;2
BSSCwmax=10;10;4;3
BSSCwmin=4;4;3;2
BssidNum=1
BSSTxop=0;0;94;47
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
DbdcBandSupport=0
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
DtimPeriod=${dtim_period:-1}
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
FineAGC=0
FixedTxMode=
ForceRoamSupport=
FQ_Enable=1
FragThreshold=${frag:-2346}
FreqDelta=0
GreenAP=${greenap:-0}
G_BAND_256QAM=${vendor_vht:-1}
HT_AMSDU=1
AMSDU_NUM=8
HT_AutoBA=1
HT_BADecline=0
HT_BAWinSize=256
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
HT_RDG=1
HT_RxStream=2
HT_STBC=${tx_stbc:-1}
HT_TxStream=2
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
MapEnable=1
MapAccept3Addr=1
MAP_Turnkey=1
MAP_Ext=0
MaxStaNum=${maxassoc:-64}
MboSupport=1
MbssMaxStaNum=${maxassoc:-64}
MlmeMultiQEnable=1
MultiIntr=1
MUTxRxEnable=${mu_beamformer:-0}
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
RTSThreshold=${rts:-2347}
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
ThermalRecal=0
CCKTxStream=4
TurboRate=0
TxBurst=${txburst:-1}
TxPower=${txpower:-100}
TxRate=0
UAPSDCapable=1
UseVhtRateFor2g=${vendor_vht}
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
WirelessMode=${WirelessMode}
WNMBTMEnable=1
WscConfMode=0
WscConfStatus=2
MboSupport=1
BSSColorValue=255
QoSR1Enable=1
ScsEnable=1
QoSMgmtCapa=0
BcnProt=0
ApCliBcnProt=0
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
MuEdcaOverride=1;1
QuickChannelSwitch=1
TWTSupport=${twt:-0}
TWTInfoFrame=${twt:-0}
TxCmdMode=1
Vht1024QamSupport=${vht_1024}
WDS_VLANID=
DynWmmEnable=0
SRMeshUlMode=1
EnableCNInfo=0
ZeroLossEnable=1
FgiFltf=1
WdsMac=
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
	ApRADIUSAcctKey=""
	ApPreAuth=""
	ApRekeyMethod=""
	ApDefKId=""
	ApK1Tp=""
	ApK2Tp=""
	ApK3Tp=""
	ApK4Tp=""
	ApHideESSID=""
	ApRRMEnable=""
	ApFtSupport=""
	ApNoForwarding=""
	ApRekeyInterval=""
	ApPMFMFPC=""
	ApPMFMFPR=""
	ApFtOtd=""
	ApFtOnly=""
	ApFtRic=""
	Apmumimodl=""
	Apmumimoul=""
	Apofdmadl=""
	Apofdmaul=""
	for_each_interface "ap" mtk_ap_vif_pre_config

#For DBDC profile merging......
	BssidNum=${ApBssidNum:-1}
	sed -i "s/BssidNum=1/BssidNum=${BssidNum}/g" $MTWIFI_PROFILE_PATH
	# eval sed -i 's/BssidNum=1/BssidNum=${BssidNum}/g' $MTWIFI_PROFILE_PATH
	# echo "BssidNum=${ApBssidNum:-1}" >> $MTWIFI_PROFILE_PATH
	echo "HideSSID=${ApHideESSID%?}" >> $MTWIFI_PROFILE_PATH
	echo "WmmCapable=${wmm}" >> $MTWIFI_PROFILE_PATH
	echo "AuthMode=${ApAuthMode%?}" >> $MTWIFI_PROFILE_PATH
	echo "EncrypType=${ApEncrypType%?}" >> $MTWIFI_PROFILE_PATH
	echo "RADIUS_Server=${ApRADIUSServer%?}" >> $MTWIFI_PROFILE_PATH
	echo "own_ip_addr=${own_ip_addr}" >> $MTWIFI_PROFILE_PATH
	echo "own_radius_port=${own_radius_port}" >> $MTWIFI_PROFILE_PATH
	echo "RADIUS_Port=${ApRADIUSPort%?}" >> $MTWIFI_PROFILE_PATH
	echo "RADIUS_Acct_Server=${ApRADIUSAcctServer%?}" >> $MTWIFI_PROFILE_PATH
	echo "RADIUS_Acct_Key=${ApRADIUSAcctKey%?}" >> $MTWIFI_PROFILE_PATH
	echo "RADIUS_Acct_Port=${ApRADIUSAcctPort%?}" >> $MTWIFI_PROFILE_PATH
	echo "PreAuth=${ApPreAuth%?}" >> $MTWIFI_PROFILE_PATH
	echo "DefaultKeyID=${ApDefKId%?}" >> $MTWIFI_PROFILE_PATH
	echo "Key1Type=${ApK1Tp%?}" >> $MTWIFI_PROFILE_PATH
	echo "Key2Type=${ApK2Tp%?}" >> $MTWIFI_PROFILE_PATH
	echo "Key3Type=${ApK3Tp%?}" >> $MTWIFI_PROFILE_PATH
	echo "Key4Type=${ApK4Tp%?}" >> $MTWIFI_PROFILE_PATH
	echo "RekeyMethod=${ApRekeyMethod%?}" >> $MTWIFI_PROFILE_PATH
	echo "RRMEnable=${ApRRMEnable%?}" >> $MTWIFI_PROFILE_PATH
	echo "FtSupport=${ApFtSupport%?}" >> $MTWIFI_PROFILE_PATH
	echo "FtOtd=${ApFtOtd%?}" >> $MTWIFI_PROFILE_PATH
	echo "FtOnly=${ApFtOnly%?}" >> $MTWIFI_PROFILE_PATH
	echo "FtRic=${ApFtRic%?}" >> $MTWIFI_PROFILE_PATH
	echo "MuMimoDlEnable=${Apmumimodl%?}" >> $MTWIFI_PROFILE_PATH
	echo "MuMimoUlEnable=${Apmumimoul%?}" >> $MTWIFI_PROFILE_PATH
	echo "MuOfdmaDlEnable=${Apofdmadl%?}" >> $MTWIFI_PROFILE_PATH
	echo "MuOfdmaUlEnable=${Apofdmaul%?}" >> $MTWIFI_PROFILE_PATH
	echo "PMFMFPC=${ApPMFMFPC%?}" >> $MTWIFI_PROFILE_PATH
	echo "PMFMFPR=${ApPMFMFPR%?}" >> $MTWIFI_PROFILE_PATH
	echo "NoForwarding=${ApNoForwarding%?}" >> $MTWIFI_PROFILE_PATH
	echo "RekeyInterval=${ApRekeyInterval%?}" >> $MTWIFI_PROFILE_PATH
	echo "TxPreamble=${short_preamble}" >> $MTWIFI_PROFILE_PATH
	echo "KickStaRssiLow=${kicklow}" >> $MTWIFI_PROFILE_PATH
	echo "AssocReqRssiThres=${assocthres}" >> $MTWIFI_PROFILE_PATH

#WDS接口
	WDSBssidNum=0
	WdsList=""
	WdsEncrypType=""
	WdsDefKId=""
	WdsPhyMode=""
	for_each_interface "wds" mtk_wds_vif_pre_config

#For WDS profile merging......
	echo "WdsNum=${WDSBssidNum:-0}" >> $MTWIFI_PROFILE_PATH
	echo "WdsEnable=${wdsen:-0}" >> $MTWIFI_PROFILE_PATH
	echo "WdsList=${WdsList%?}" >> $MTWIFI_PROFILE_PATH
	echo "WdsEncrypType=${WdsEncrypType%?}" >> $MTWIFI_PROFILE_PATH
	echo "WdsDefaultKeyID=${WdsDefKId%?}" >> $MTWIFI_PROFILE_PATH
	echo "WdsPhyMode=${WdsPhyMode%?}" >> $MTWIFI_PROFILE_PATH

#STA模式
	stacount=0
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
	# ApCliMacAddress=""
	ApCliPESupport=""
	ApCliMuMimoDlEnable=""
	ApCliMuMimoUlEnable=""
	ApCliMuOfdmaDlEnable=""
	ApCliMuOfdmaUlEnable=""
	for_each_interface "sta" mtk_sta_vif_pre_config

#For STA profile merging......
	echo "ApCliEnable=${ApCliEnable:-0}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliSsid=${ApCliSsid}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliBssid=${ApCliBssid}" >> $MTWIFI_PROFILE_PATH
	# echo "ApCliMacAddress=${ApCliMacAddress}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliAuthMode=${ApCliAuthMode}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliEncrypType=${ApCliEncrypType}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliDefaultKeyID=${ApCliDefKId:-0}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliWPAPSK=${ApCliWPAPSK}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliKey1Str=${ApCliKey1Str}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliKey2Str=${ApCliKey2Str}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliKey3Str=${ApCliKey3Str}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliKey4Str=${ApCliKey4Str}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliKey1Type=${ApCliK1Tp:-0}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliKey2Type=${ApCliK2Tp:-0}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliKey3Type=${ApCliK3Tp:-0}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliKey4Type=${ApCliK4Tp:-0}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliPMFMFPC=${ApCliPMFMFPC:-0}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliPMFMFPR=${ApCliPMFMFPR:-0}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliPESupport=${ApCliPESupport:-0}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliMuMimoDlEnable=${ApCliMuMimoDlEnable:-0}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliMuMimoUlEnable=${ApCliMuMimoUlEnable:-0}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliMuOfdmaDlEnable=${ApCliMuOfdmaDlEnable:-0}" >> $MTWIFI_PROFILE_PATH
	echo "ApCliMuOfdmaUlEnable=${ApCliMuOfdmaUlEnable:-0}" >> $MTWIFI_PROFILE_PATH

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
	echo "MapMode=${mapmode:-0}" >> $MTWIFI_PROFILE_PATH
	echo "MeshAutoLink=${MeshAutoLink:-0}" >> $MTWIFI_PROFILE_PATH
	echo "MeshId=${mesh_id}" >> $MTWIFI_PROFILE_PATH
	echo "MeshAuthMode=${MeshAuthMode}" >> $MTWIFI_PROFILE_PATH
	echo "MeshEncrypType=${MeshEncrypType}" >> $MTWIFI_PROFILE_PATH
	echo "MeshDefaultKeyID=${MeshDefKId}" >> $MTWIFI_PROFILE_PATH
	echo "MeshWEPKEY=${MeshWEPKEY}" >> $MTWIFI_PROFILE_PATH
	echo "MeshWPAKEY=${MeshWPAKEY}" >> $MTWIFI_PROFILE_PATH
	echo "MeshForwarding=${mesh_fwding}" >> $MTWIFI_PROFILE_PATH
	echo "MeshRssiThreshold=${mesh_rssi_threshold}" >> $MTWIFI_PROFILE_PATH

#接口上线
#加锁
	echo "MTK Interfaces Pending..."
	if lock -z $WIFI_OP_LOCK; then
		sleep 2
		drv_mtk_teardown $phy_name
		mtk_vif_down $phy_name
#Start root device
		ifconfig ra0 up
#restore interfaces
		if [[ "$phy_name" = "ra0" ]]; then
			sh $MTWIFI_CMD_OPATH
			sh $MTWIFI_CMD_PATH
		else
			sh $MTWIFI_CMD_PATH
			sh $MTWIFI_CMD_OPATH
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

	[ "$phy_name" == "rax0" ] && [ "$ApBssidNum" == "0" ] && ifconfig ra0 down

#重启HWNAT
	[ -d /sys/module/mtkhnat ] && {
		echo "Wait restart turboacc"
		/etc/init.d/turboacc restart
	}
#设置无线上线
	wireless_set_up
#解锁
	lock -u $WIFI_OP_LOCK
}

add_driver mtk

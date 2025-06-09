killall bs20
killall wapp
sleep 2
br0_mac=$(cat /sys/class/net/br-lan/address)
ctrlr_al_mac=$br0_mac
agent_al_mac=$br0_mac
ra0=0
rax0=0
sed -i "s/map_controller_alid=.*/map_controller_alid=${ctrlr_al_mac}/g" /etc/map/1905d.cfg
sed -i "s/map_agent_alid=.*/map_agent_alid=${agent_al_mac}/g" /etc/map/1905d.cfg

ra0_798x="$(uci -q get wireless.ra0.bandsteering)"
if [ "$ra0_798x" -eq "1" ]; then
	ra0=1
	rax0=1
fi
    
ra0_798x="$(uci -q get wireless.ra0.ieee80211r)"
if [ "$ra0_798x" -eq "1" ]; then
	ra0=1
fi
    
ra0_798x="$(uci -q get wireless.default_rax0.steeringthresold)"
if [ "$ra0_798x" -lt "0" ]; then
	ra0=1
fi
        
ra0_798x="$(uci -q get wireless.default_ra0.disabled)"
if [ "$ra0_798x" -eq "1" ]; then
	ra0=0
	rax0=0
fi
    
rax0_798x="$(uci -q get wireless.rax0.ieee80211r)"
if [ "$rax0_798x" -eq "1" ]; then
	rax0=1
fi
   
rax0_798x="$(uci -q get wireless.default_rax0.steeringthresold)"
if [ "$rax0_798x" -lt "0" ]; then
	rax0=1
fi
    
rax0_798x="$(uci -q get wireless.default_rax0.disabled)"
if [ "$rax0_798x" -eq "1" ]; then
	rax0=0
fi

if [ "$rax0" -eq "1" ] && [ "$ra0" -eq "1" ]; then
	wapp -d1 -v2 -cra0 -crax0 > /dev/null&
elif [ "$ra0" -eq "1" ] && [ "$rax0" -eq "0" ]; then
	wapp -d1 -v2 -cra0 > /dev/null&
elif [ "$rax0" -eq "1" ] && [ "$ra0" -eq "0" ]; then
	wapp -d1 -v2 -crax0 > /dev/null
fi
sleep 1
if [ "$rax0" -eq "1" ] || [ "$ra0" -eq "1" ]; then
	iwpriv ra0 set mapR2Enable=0
	iwpriv ra0 set mapTSEnable=0
	iwpriv ra0 set mapR3Enable=0
	iwpriv ra0 set DppEnable=0
	iwpriv rax0 set mapR2Enable=0
	iwpriv rax0 set mapTSEnable=0
	iwpriv rax0 set mapR3Enable=0
	iwpriv rax0 set DppEnable=0
	iwpriv ra0 set mapEnable=2
	iwpriv rax0 set mapEnable=2
	bs20 &
	wappctrl rax0 mbo reset_default
	wappctrl ra0  mbo reset_default
	rax0_798x="$(uci -q get wireless.default_rax0.steeringbssid)"
	if [ $rax0_798x ]; then
		bash setbssid rax0 "$rax0_798x"
	fi

	ra0_798x="$(uci -q get wireless.default_ra0.steeringbssid)"
	bash setbssid ra0 "$ra0_798x"
	if [ $ra0_798x ]; then
		bash setbssid ra0 "$ra0_798x"
	fi

fi

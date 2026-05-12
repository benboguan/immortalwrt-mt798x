module("luci.controller.kicksta", package.seeall)

function index()
	entry({"admin", "kicksta"}, call("action_kicksta"), nil, 99)
end

function action_kicksta()
	local ifname = luci.http.formvalue("ifname")
	local mac = luci.http.formvalue("mac")
	if not ifname or not mac then
		luci.http.write("err: missing args")
		return
	end
	os.execute(string.format("iwpriv %s set DisConnectSta=%s", ifname, mac))
	luci.http.write("debug: ifname=" .. tostring(ifname) .. " mac=" .. tostring(mac))
end

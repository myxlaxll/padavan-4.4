#!/bin/sh
#copyright by hiboy
#source /etc/storage/init.sh
#ACTION=$1
export PATH='/etc/storage/bin:/tmp/script:/etc/storage/script:/opt/usr/sbin:/opt/usr/bin:/opt/sbin:/opt/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin'
export LD_LIBRARY_PATH=/lib:/opt/lib
ACTION=$1
scriptfilepath=$(cd "$(dirname "$0")"; pwd)/$(basename $0)
#echo $scriptfilepath
scriptpath=$(cd "$(dirname "$0")"; pwd)
#echo $scriptpath
scriptname=$(basename $0)

aliddns_enable=`nvram get aliddns_enable`
[ -z $aliddns_enable ] && aliddns_enable=0 && nvram set aliddns_enable=0
if [ "$aliddns_enable" != "0" ] ; then
#nvramshow=`nvram showall | grep '=' | grep aliddns | awk '{print gensub(/'"'"'/,"'"'"'\"'"'"'\"'"'"'","g",$0);}'| awk '{print gensub(/=/,"='\''",1,$0)"'\'';";}'` && eval $nvramshow

aliddns_interval=`nvram get aliddns_interval`
aliddns_ak=`nvram get aliddns_ak`
aliddns_sk=`nvram get aliddns_sk`
aliddns_domain=`nvram get aliddns_domain`
aliddns_name=`nvram get aliddns_name`
aliddns_domain2=`nvram get aliddns_domain2`
aliddns_name2=`nvram get aliddns_name2`
aliddns_domain6=`nvram get aliddns_domain6`
aliddns_name6=`nvram get aliddns_name6`
aliddns_ttl=`nvram get aliddns_ttl`

if [ "$aliddns_domain"x != "x" ] && [ "$aliddns_name"x = "x" ] ; then
	aliddns_name="www"
	nvram set aliddns_name="www"
fi
if [ "$aliddns_domain2"x != "x" ] && [ "$aliddns_name2"x = "x" ] ; then
	aliddns_name2="www"
	nvram set aliddns_name2="www"
fi
if [ "$aliddns_domain6"x != "x" ] && [ "$aliddns_name6"x = "x" ] ; then
	aliddns_name6="www"
	nvram set aliddns_name6="www"
fi

IPv6=0
domain_type=""
hostIP=""
domain=""
name=""
name1=""
timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
aliddns_record_id=""
[ -z $aliddns_interval ] && aliddns_interval=600 && nvram set aliddns_interval=$aliddns_interval
[ -z $aliddns_ttl ] && aliddns_ttl=600 && nvram set aliddns_ttl=$aliddns_ttl
aliddns_renum=`nvram get aliddns_renum`

fi

if [ ! -z "$(echo $scriptfilepath | grep -v "/tmp/script/" | grep aliddns)" ]  && [ ! -s /tmp/script/_aliddns ]; then
	mkdir -p /tmp/script
	{ echo '#!/bin/sh' ; echo $scriptfilepath '"$@"' '&' ; } > /tmp/script/_aliddns
	chmod 777 /tmp/script/_aliddns
fi


aliddns_restart () {

relock="/var/lock/aliddns_restart.lock"
if [ "$1" = "o" ] ; then
	nvram set aliddns_renum="0"
	[ -f $relock ] && rm -f $relock
	return 0
fi
if [ "$1" = "x" ] ; then
	if [ -f $relock ] ; then
		logger -t "【aliddns】" "多次尝试启动失败，等待【"`cat $relock`"分钟】后自动尝试重新启动"
		exit 0
	fi
	aliddns_renum=${aliddns_renum:-"0"}
	aliddns_renum=`expr $aliddns_renum + 1`
	nvram set aliddns_renum="$aliddns_renum"
	if [ "$aliddns_renum" -gt "2" ] ; then
		I=19
		echo $I > $relock
		logger -t "【aliddns】" "多次尝试启动失败，等待【"`cat $relock`"分钟】后自动尝试重新启动"
		while [ $I -gt 0 ]; do
			I=$(($I - 1))
			echo $I > $relock
			sleep 60
			[ "$(nvram get aliddns_renum)" = "0" ] && exit 0
			[ $I -lt 0 ] && break
		done
		nvram set aliddns_renum="0"
	fi
	[ -f $relock ] && rm -f $relock
fi
nvram set aliddns_status=0
eval "$scriptfilepath &"
exit 0
}

aliddns_get_status () {

A_restart=`nvram get aliddns_status`
B_restart="$aliddns_enable$aliddns_interval$aliddns_ak$aliddns_sk$aliddns_domain$aliddns_name$aliddns_domain2$aliddns_name2$aliddns_domain6$aliddns_name6$aliddns_ttl$(cat /etc/storage/ddns_script.sh | grep -v '^#' | grep -v "^$")"
B_restart=`echo -n "$B_restart" | md5sum | sed s/[[:space:]]//g | sed s/-//g`
if [ "$A_restart" != "$B_restart" ] ; then
	nvram set aliddns_status=$B_restart
	needed_restart=1
else
	needed_restart=0
fi
}

aliddns_check () {

aliddns_get_status
if [ "$aliddns_enable" != "1" ] && [ "$needed_restart" = "1" ] ; then
	[ ! -z "$(ps -w | grep "$scriptname keep" | grep -v grep )" ] && logger -t "【aliddns动态域名】" "停止 aliddns" && aliddns_close
	{ kill_ps "$scriptname" exit0; exit 0; }
fi
if [ "$aliddns_enable" = "1" ] ; then
	if [ "$needed_restart" = "1" ] ; then
		aliddns_close
		eval "$scriptfilepath keep &"
		exit 0
	else
		[ -z "$(ps -w | grep "$scriptname keep" | grep -v grep )" ] || [ ! -s "`which curl`" ] && aliddns_restart
	fi
fi
}

aliddns_keep () {
aliddns_start
logger -t "【AliDDNS动态域名】" "守护进程启动"
while true; do
sleep $aliddns_interval
[ ! -s "`which curl`" ] && aliddns_restart
#nvramshow=`nvram showall | grep '=' | grep aliddns | awk '{print gensub(/'"'"'/,"'"'"'\"'"'"'\"'"'"'","g",$0);}'| awk '{print gensub(/=/,"='\''",1,$0)"'\'';";}'` && eval $nvramshow
aliddns_enable=`nvram get aliddns_enable`
[ "$aliddns_enable" = "0" ] && aliddns_close && exit 0;
if [ "$aliddns_enable" = "1" ] ; then
	aliddns_start
fi
done
}

kill_ps () {

COMMAND="$1"
if [ ! -z "$COMMAND" ] ; then
	eval $(ps -w | grep "$COMMAND" | grep -v $$ | grep -v grep | awk '{print "kill "$1";";}')
	eval $(ps -w | grep "$COMMAND" | grep -v $$ | grep -v grep | awk '{print "kill -9 "$1";";}')
fi
if [ "$2" == "exit0" ] ; then
	exit 0
fi
}

aliddns_close () {

kill_ps "/tmp/script/_aliddns"
kill_ps "_aliddns.sh"
kill_ps "$scriptname"

}

aliddns_start () {
IPv6=0
ip -f inet6 neighbor flush all
#清理邻居表缓存，防止出现过期IPv6地址
sleep 1
#ip -f inet6 neighbor show
if [ "$aliddns_domain"x != "x" ] && [ "$aliddns_name"x != "x" ] ; then
	sleep 1
	timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
	aliddns_record_id=""
	domain="$aliddns_domain"
	name="$aliddns_name"
	arDdnsCheck $aliddns_domain $aliddns_name
fi
if [ "$aliddns_domain2"x != "x" ] && [ "$aliddns_name2"x != "x" ] ; then
	sleep 1
	timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
	aliddns_record_id=""
	domain="$aliddns_domain2"
	name="$aliddns_name2"
	arDdnsCheck $aliddns_domain2 $aliddns_name2
fi
if [ "$aliddns_domain6"x != "x" ] && [ "$aliddns_name6"x != "x" ] ; then
	IPv6=1
	sleep 1
	timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
	aliddns_record_id=""
	domain="$aliddns_domain6"
	name="$aliddns_name6"
	arDdnsCheck $aliddns_domain6 $aliddns_name6
fi

source /etc/storage/ddns_script.sh
while read line
do
	line=`echo $line | cut -d '#' -f1`
	line=$(echo $line)
	[ -z "$line" ] && continue
	sleep 1
	IPv6=1
	timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
	IPv6_neighbor=1
	aliddns_record_id=""
	ip6_addrget=""
	name="$(echo "$line" | cut -d '@' -f1)"
	domain="$(echo "$line" | cut -d '@' -f2)"
	inf_MAC="$(echo "$line" | cut -d '@' -f3 | tr 'A-Z' 'a-z')"
	inf_match="$(echo "$line" | cut -d '@' -f4)"
	inf_v_match="$(echo "$line" | cut -d '@' -f5)"
	[ -z "$inf_v_match" ] && inf_v_match="inf_v_match"
	inet6_neighbor="$(echo "$line" | cut -d '@' -f6)"
	inet6_neighbor=$(echo $inet6_neighbor)
	if [ -z "$inet6_neighbor" ] ; then
		a_ip6=/tmp/ip6_neighbor.log
		b_ip6=/tmp/ip6_neighbor_addr.log
		touch $a_ip6 $b_ip6
		neighbors=$(ip -f inet6 neighbor show)
		echo $neighbors > $a_ip6
		sed -i 's/ STALE /\n/g' /tmp/ip6_neighbor.log
		sed -i 's/ DELAY /\n/g' /tmp/ip6_neighbor.log
		sed -i 's/ REACHABLE /\n/g' /tmp/ip6_neighbor.log
		sed -i 's/ PROBE /\n/g' /tmp/ip6_neighbor.log
		sed -i 's/ FAILED /\n/g' /tmp/ip6_neighbor.log
		#切割完成，分行显示——IPv6地址 接口 MAC地址 邻居状态
		cat /tmp/ip6_neighbor.log | grep -i ''$inf_MAC'' | grep -i ''$inf_match'' | grep -v ''$inf_v_match''  > /tmp/ip6_neighbor_addr.log
		# 包含 $inf_MAC(MAC地址) | 包含 $inf_match(如2408等公网前缀) | 排除$inf_v_match(如 fe80:: 内网前缀)
		ip6_addrget="$(cat /tmp/ip6_neighbor_addr.log | cut -d ' ' -f1 | head -n 1) "
		#取得第一个空格前的数据-IPv6地址
		#echo "$ip6_addrget" >> $c_ip6
		#echo "$ip6_addrget" > $b_ip6
		inet6_neighbor=$(echo $ip6_addrget)
	fi
	[ ! -z "$inet6_neighbor" ] && arDdnsCheck $domain $name
	IPv6_neighbor=0
done < /tmp/ip6_ddns_inf

}

urlencode() {
	# urlencode <string>
	out=""
	while read -n1 c
	do
		case $c in
			[a-zA-Z0-9._-]) out="$out$c" ;;
			*) out="$out`printf '%%%02X' "'$c"`" ;;
		esac
	done
	echo -n $out
}

enc() {
	echo -n "$1" | urlencode
}

send_request() {
	args="AccessKeyId=$aliddns_ak&Action=$1&Format=json&$2&Version=2015-01-09"
	hash=$(echo -n "GET&%2F&$(enc "$args")" | openssl dgst -sha1 -hmac "$aliddns_sk&" -binary | openssl base64)
	curl -L -s "http://alidns.aliyuncs.com/?$args&Signature=$(enc "$hash")"
}

get_recordid() {
	grep -Eo '"RecordId":"[0-9]+"' | cut -d':' -f2 | tr -d '"' |head -n1
}

get_recordIP() {
	sed -e "s/"'"TTL":'"/"' \n '"/g" | grep '"Type":"'$domain_type'"' | grep -Eo '"Value":"[^"]*"' | awk -F 'Value":"' '{print $2}' | tr -d '"' |head -n1
}

query_recordInfo() {
	send_request "DescribeDomainRecordInfo" "RecordId=$1&SignatureMethod=HMAC-SHA1&SignatureNonce=$timestamp&SignatureVersion=1.0&Timestamp=$timestamp"
}

query_recordid() {
	send_request "DescribeSubDomainRecords" "SignatureMethod=HMAC-SHA1&SignatureNonce=$timestamp&SignatureVersion=1.0&SubDomain=$name1.$domain&Timestamp=$timestamp&Type=$domain_type"
}

update_record() {
	hostIP_tmp=$(enc "$hostIP")
	send_request "UpdateDomainRecord" "RR=$name1&RecordId=$1&SignatureMethod=HMAC-SHA1&SignatureNonce=$timestamp&SignatureVersion=1.0&TTL=$aliddns_ttl&Timestamp=$timestamp&Type=$domain_type&Value=$hostIP_tmp"
}

add_record() {
	hostIP_tmp=$(enc "$hostIP")
	send_request "AddDomainRecord&DomainName=$domain" "RR=$name1&SignatureMethod=HMAC-SHA1&SignatureNonce=$timestamp&SignatureVersion=1.0&TTL=$aliddns_ttl&Timestamp=$timestamp&Type=$domain_type&Value=$hostIP_tmp"
}

arDdnsInfo() {
case  $name  in
	  \*)
		name1=%2A
		;;
	  \@)
		name1=%40
		;;
	  *)
		name1=$name
		;;
esac

	if [ "$IPv6" = "1" ]; then
		domain_type="AAAA"
	else
		domain_type="A"
	fi
	timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
	# 获得域名ID
	aliddns_record_id=""
	aliddns_record_id=`query_recordid | get_recordid`
	sleep 1
	timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
	# 获得最后更新IP
	recordIP=`query_recordInfo $aliddns_record_id | get_recordIP`
	
	if [ "$IPv6" = "1" ]; then
	echo $recordIP
	return 0
	else
	# Output IP
	case "$recordIP" in 
	[1-9]*)
		echo $recordIP
		return 0
		;;
	*)
		echo "Get Record Info Failed!"
		#logger -t "【AliDDNS动态域名】" "获取记录信息失败！"
		return 1
		;;
	esac
	fi
}

# 查询域名地址
# 参数: 待查询域名
arNslookup() {
mkdir -p /tmp/arNslookup
nslookup $1 | tail -n +3 | grep "Address" | awk '{print $3}'| grep -v ":" | sed -n '1p' > /tmp/arNslookup/$$ &
I=5
while [ ! -s /tmp/arNslookup/$$ ] ; do
		I=$(($I - 1))
		[ $I -lt 0 ] && break
		sleep 1
done
killall nslookup
if [ -s /tmp/arNslookup/$$ ] ; then
cat /tmp/arNslookup/$$ | sort -u | grep -v "^$"
rm -f /tmp/arNslookup/$$
else
	curltest=`which curl`
	if [ -z "$curltest" ] || [ ! -s "`which curl`" ] ; then
		Address="`wget -T 5 -t 3 --no-check-certificate --quiet --output-document=- http://119.29.29.29/d?dn=$1`"
		if [ $? -eq 0 ]; then
		echo "$Address" |  sed s/\;/"\n"/g | sed -n '1p' | grep -E -o '([0-9]+\.){3}[0-9]+'
		fi
	else
		Address="`curl -k -s http://119.29.29.29/d?dn=$1`"
		if [ $? -eq 0 ]; then
		echo "$Address" |  sed s/\;/"\n"/g | sed -n '1p' | grep -E -o '([0-9]+\.){3}[0-9]+'
		fi
	fi
fi
}

arNslookup6() {
mkdir -p /tmp/arNslookup
nslookup $1 | tail -n +3 | grep "Address" | awk '{print $3}'| grep ":" | sed -n '1p' > /tmp/arNslookup/$$ &
I=5
while [ ! -s /tmp/arNslookup/$$ ] ; do
		I=$(($I - 1))
		[ $I -lt 0 ] && break
		sleep 1
done
killall nslookup
if [ -s /tmp/arNslookup/$$ ] ; then
	cat /tmp/arNslookup/$$ | sort -u | grep -v "^$"
	rm -f /tmp/arNslookup/$$
fi
}

# 更新记录信息
# 参数: 主域名 子域名
arDdnsUpdate() {
case  $name  in
	  \*)
		name1=%2A
		;;
	  \@)
		name1=%40
		;;
	  *)
		name1=$name
		;;
esac
	if [ "$IPv6" = "1" ]; then
		domain_type="AAAA"
	else
		domain_type="A"
	fi
I=3
aliddns_record_id=""
while [ "$aliddns_record_id" = "" ] ; do
	I=$(($I - 1))
	[ $I -lt 0 ] && break
	# 获得记录ID
	timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
	aliddns_record_id=`query_recordid | get_recordid`
	echo "recordID $aliddns_record_id"
	sleep 1
done
	timestamp=`date -u "+%Y-%m-%dT%H%%3A%M%%3A%SZ"`
if [ "$aliddns_record_id" = "" ] ; then
	aliddns_record_id=`add_record | get_recordid`
	echo "added record $aliddns_record_id"
	logger -t "【AliDDNS动态域名】" "添加的记录  $aliddns_record_id"
else
	update_record $aliddns_record_id
	echo "updated record $aliddns_record_id"
	logger -t "【AliDDNS动态域名】" "更新的记录  $aliddns_record_id"
fi
# save to file
if [ "$aliddns_record_id" = "" ] ; then
	# failed
	nvram set aliddns_last_act="`date "+%Y-%m-%d %H:%M:%S"`   更新失败"
	logger -t "【AliDDNS动态域名】" "更新失败"
	return 1
else
	nvram set aliddns_record_id="$aliddns_record_id"
	nvram set aliddns_last_act="`date "+%Y-%m-%d %H:%M:%S"`   成功更新：$hostIP"
	logger -t "【AliDDNS动态域名】" "成功更新： $hostIP"
	return 0
fi

}

# 动态检查更新
# 参数: 主域名 子域名
arDdnsCheck() {
	#local postRS
	#local lastIP
	source /etc/storage/ddns_script.sh
	hostIP=$arIpAddress
	hostIP=`echo $hostIP | head -n1 | cut -d' ' -f1`
	if [ -z $(echo "$hostIP" | grep : | grep -v "\.") ] && [ "$IPv6" = "1" ] ; then 
		IPv6=0
		logger -t "【AliDDNS动态域名】" "错误！$hostIP 获取目前 IPv6 失败，请在脚本更换其他获取地址，保证取得IPv6地址(例如:ff03:0:0:0:0:0:0:c1)"
		return 1
	fi
	if [ "$hostIP"x = "x"  ] ; then
		curltest=`which curl`
		if [ -z "$curltest" ] || [ ! -s "`which curl`" ] ; then
			[ "$hostIP"x = "x"  ] && hostIP=`wget -T 5 -t 3 --no-check-certificate --quiet --output-document=- "http://members.3322.org/dyndns/getip" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
			[ "$hostIP"x = "x"  ] && hostIP=`wget -T 5 -t 3 --no-check-certificate --quiet --output-document=- "ip.3322.net" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
			[ "$hostIP"x = "x"  ] && hostIP=`wget -T 5 -t 3 --no-check-certificate --quiet --output-document=- "https://www.ipip.net/" | grep "IP地址" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
			[ "$hostIP"x = "x"  ] && hostIP=`wget -T 5 -t 3 --no-check-certificate --quiet --output-document=- "http://pv.sohu.com/cityjson?ie=utf-8" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
		else
			[ "$hostIP"x = "x"  ] && hostIP=`curl -L -k -s "http://members.3322.org/dyndns/getip" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
			[ "$hostIP"x = "x"  ] && hostIP=`curl -L -k -s ip.3322.net | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
			[ "$hostIP"x = "x"  ] && hostIP=`curl -L -k -s "https://www.ipip.net" | grep "IP地址" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
			[ "$hostIP"x = "x"  ] && hostIP=`curl -L -k -s http://pv.sohu.com/cityjson?ie=utf-8 | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1`
		fi
		if [ "$hostIP"x = "x"  ] ; then
			logger -t "【AliDDNS动态域名】" "错误！获取目前 IP 失败，请在脚本更换其他获取地址"
			return 1
		fi
	fi
	echo "Updating Domain: ${2}.${1}"
	echo "hostIP: ${hostIP}"
	lastIP=$(arDdnsInfo "$1 $2")
	if [ $? -eq 1 ]; then
		[ "$IPv6" != "1" ] && lastIP=$(arNslookup "${2}.${1}")
		[ "$IPv6" = "1" ] && lastIP=$(arNslookup6 "${2}.${1}")
	fi
	echo "lastIP: ${lastIP}"
	if [ "$lastIP" != "$hostIP" ] ; then
		logger -t "【AliDDNS动态域名】" "开始更新 ${2}.${1} 域名 IP 指向"
		logger -t "【AliDDNS动态域名】" "目前 IP: ${hostIP}"
		logger -t "【AliDDNS动态域名】" "上次 IP: ${lastIP}"
		sleep 1
		postRS=$(arDdnsUpdate $1 $2)
		if [ $? -eq 0 ]; then
			echo "postRS: ${postRS}"
			logger -t "【AliDDNS动态域名】" "更新动态DNS记录成功！"
			return 0
		else
			echo ${postRS}
			logger -t "【AliDDNS动态域名】" "更新动态DNS记录失败！请检查您的网络。"
			if [ "$IPv6" = "1" ] ; then 
				IPv6=0
				logger -t "【AliDDNS动态域名】" "错误！$hostIP 获取目前 IPv6 失败，请在脚本更换其他获取地址，保证取得IPv6地址(例如:ff03:0:0:0:0:0:0:c1)"
				return 1
			fi
			return 1
		fi
	fi
	echo ${lastIP}
	echo "Last IP is the same as current IP!"
	return 1
}


initconfig () {

if [ ! -s "/etc/storage/ddns_script.sh" ] ; then
cat > "/etc/storage/ddns_script.sh" <<-\EEE
# 自行测试哪个代码能获取正确的IP，删除前面的#可生效
arIpAddress () {
# IPv4地址获取(几乎无用)
# 获得外网地址
pppoemwan=`nvram get pppoemwan_enable`
if [ "$pppoemwan" -ne 0 ]; then
        curl --interface ppp0 -L -k -s "http://members.3322.org/dyndns/getip" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1
else
curltest=`which curl`
if [ -z "$curltest" ] || [ ! -s "`which curl`" ] ; then
    wget -T 5 -t 3 --no-check-certificate --quiet --output-document=- "http://members.3322.org/dyndns/getip" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1
else
    curl -L -k -s "http://members.3322.org/dyndns/getip" | grep -E -o '([0-9]+\.){3}[0-9]+' | head -n1 | cut -d' ' -f1
fi
fi
}
arIpAddress6 () {
# IPv6地址获取
# 因为一般ipv6没有nat ipv6的获得可以本机获得
ifconfig $(nvram get lan0_ifname_t) | awk '/Global/{print $3}' | awk -F/ '{print $1}'
#ip -6 neigh show | grep 'MAC' | grep '24' | grep -o "^\S\+" | head -n 1
#网络邻居显示   	'MAC地址'  	 '2408等前缀'	去掉后面	第一行
}
if [ "$IPv6_neighbor" != "1" ] ; then
if [ "$IPv6" = "1" ] ; then
arIpAddress=$(arIpAddress6)
else
arIpAddress=$(arIpAddress)
fi
else
arIpAddress=$inet6_neighbor
inet6_neighbor=""
IPv6_neighbor=0
fi

# 根据 ip -6 neigh show 获取终端的信息，设置 ddns 解析，实现每个终端的 IPV6 动态域名
# 参数说明：使用 @ 符号分割，①前缀名称 ②域名 ③MAC【不限大小写】
# ④匹配关键词的ip6地址【可留空/2408等前缀】 ⑤排除关键词的ip6地址【可留空】 ⑥手动指定ip【可留空】 
# 下面是信号填写例子：（删除前面的#可生效）
cat >/tmp/ip6_ddns.inf <<-\EOF
#www@google.com@09:9B:9A:90:9F:D9@@fe80::@



EOF
cat /tmp/ip6_ddns.inf | grep -v '^#'  | grep -v '^$' > /tmp/ip6_ddns_inf
rm -f /tmp/ip6_ddns.inf
EEE
	chmod 755 "$ddns_script"
fi

}

initconfig

case $ACTION in
start)
	aliddns_close
	aliddns_check
	;;
check)
	aliddns_check
	;;
stop)
	aliddns_close
	;;
keep)
	aliddns_keep
	;;
*)
	aliddns_check
	;;
esac

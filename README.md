# 福建电信IPTV源

镜像目标设备抓取源列表后，正则匹配取得“干净”的列表：
^.*ChannelNa\+?me="(.+?)"\,UserChannelID="(.+?)"\,ChannelURL="(.+?)://(.+?)".time.*$

然后将多余字段替换为：
#EXTINF:-1,\1\n\http://10.0.0.1:6666/udp/\4

此处IP地址需自行更换为udpxy的设置
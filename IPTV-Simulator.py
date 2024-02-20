#coding:utf-8

import requests,re,time,random,os,uuid,socket
from Crypto.Cipher import DES3
from urllib.parse import urlparse

# 获取 IPTV 设备的内网地址
def getIp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

# 获取 MAC 地址，强烈建议在抓包设备上修改为机顶盒的MAC地址
def getMac():
    mac = hex(uuid.getnode())[2:]
    return ':'.join([mac[i:i + 2] for i in range(0, len(mac), 2)])

##################################################  以下为必要的信息  ##################################################
key = ''  # 通常是8位数字，可以通过执行 find_key(Authenticator) 爆破
rand = ''  # 通过反解key得到，建议多次抓包确定是否为随机值，如果是随机值，请将此行注释并取消下一行的注释，并将参数8修改为实际位数
# rand = ''.join(random.sample('123456789',8))

# 网络信息，自动获取即可，如有必要，也可以写死固定值
ip = getIp()
mac = getMac()

# 设置本地 uproxy 转发地址
uproxyServer = ''

# 服务器和用户信息，全部都可以由抓包获取到
Server = ''
UserID = ''
STBID = ''
STBType = ''
STBVersion = ''
UserAgent = ''

# 首次运行前请填写 Authenticator，并使用 find_key(Authenticator) 函数爆破 Key 值
Authenticator = ''

# 设置生成m3u列表文件的存放路径
save_dir_m3u = os.getcwd()+'/iptv.m3u'
##################################################  以上为必要的信息  ##################################################


date_now = time.strftime('%Y-%m-%d %X',time.localtime())
BS = DES3.block_size

def pad(s):
    p =  s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    return p
def unpad(s):
    p =  s[0:-ord(s[-1])]
    return p
class prpcrypt():
    def __init__(self,key):
        self.key = key + '0'*16
        self.mode = DES3.MODE_ECB
    def encrypt(self, text): #加密文本字符串,返回 HEX文本
        text = pad(text)
        # 由于必须先 find_key 解码，此处不再进行一次 DES3 方法报错的校验
        cryptor = DES3.new(self.key, self.mode)

        x = len(text) % 8
        if x != 0:
            text = text + '\0' * (8 - x)
        self.ciphertext = cryptor.encrypt(text.encode('ascii'))
        return self.ciphertext.hex()
    def decrypt(self, text):#需要解密的字符串，字符串为十六进制的字符串  如"a34f3e3583"....
        try:
            cryptor = DES3.new(self.key, self.mode)
        except Exception as e:
            if 'degenerates' in str(e):
                raisetxt = 'if key_out[:8] == key_out[8:16] or key_out[-16:-8] == key_out[-8:]:\nraise ValueError("Triple DES key degenerates to single DES")'
                print('请将调用的 DES3.py 文件里 adjust_key_parity 函数中的：%s 注释掉'%raisetxt)
                # 对于 DES3.py 文件的位置通常为：/usr/local/lib/python3.x/dist-packages/Crypto/Cipher
            else:
                print(e)
        de_text = bytes.fromhex(text)
        plain_text = cryptor.decrypt(de_text)
        return plain_text.replace(b'\x08',b'').decode('utf-8')  #返回 string,不需要再做处理

#获取 Token ,通过此 Token 来获取 Session
def getToken():
    url = 'http://%s/iptvepg/platform/index.jsp?UserID=%s&Action=Login&Mode=MENU'%(Server, UserID)
    headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'User-Agent': UserAgent,
    }
    res = requests.get(url,headers = headers,timeout = 10)
    host = urlparse(res.url).netloc

    url = 'http://%s/iptvepg/platform/getencrypttoken.jsp?UserID=%s&Action=Login&TerminalFlag=1&TerminalOsType=0&STBID=&stbtype='%(host, UserID)
    headers = {
                'User-Agent': UserAgent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Referer': 'http://%s/iptvepg/platform/index.jsp?UserID=%s&Action=Login&Mode=MENU'%(host,UserID),
                }
    res = requests.get(url,headers = headers,timeout = 10)
    res.encoding = 'utf-8'
    txt = res.text

    # 获取 EncryptToken 和鉴权主机地址
    EncryptToken = re.search('GetAuthInfo[\(][\'](.*?)[\']', txt, re.DOTALL).group(1)
    RedirectHost = re.search('[\<]form action[\=][\"]http[\:][\/][\/](.*?)[\/]iptvepg', txt, re.DOTALL).group(1)

    ret = {
        'host':host,
        'token':EncryptToken,
        'redirecthost':RedirectHost,
    }
    ret = [host,EncryptToken,RedirectHost]
    return ret

# 获取 IPTV 的鉴权 Session，后面的请求全部需要用到此 Session
def getSession(key):
    n = 0
    while n < 5: #重试
        try:
            host,token,redirecthost = getToken()
            host_new = host.split(":")
            url = 'http://%s/iptvepg/platform/auth.jsp?easip=%s&ipVersion=4&networkid=1'%(redirecthost, host_new[0])
            session_ref = '%s$%s$%s$%s$%s$%s$NULL$CTC'%(rand,token,UserID,STBID,ip,mac) #    随机8位数 +$+TOKEN +$+USERID +$+STBID +$ip +$+mac +$$CTC
            Authenticator = prpcrypt(key).encrypt(session_ref)
            headers = {
                'User-Agent': UserAgent,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Referer': 'http://%s/iptvepg/platform/getencrypttoken.jsp?UserID=%s&Action=Login&TerminalFlag=1&TerminalOsType=0&STBID=&stbtype='%(host, UserID)
            }
            data = {
                'UserID': UserID,
                'Authenticator': Authenticator,
                'StbIP': ip,
            }
            res = requests.post(url,headers = headers,data = data,timeout = 10)
            res.encoding = 'utf-8'

            UserToken = re.search('[\']UserToken[\'][\,][\'](.*?)[\'][\)]', res.text, re.DOTALL).group(1)
            EPGGroupNMB = re.search('[\']EPGGroupNMB[\'][\,][\'](.*?)[\'][\)]', res.text, re.DOTALL).group(1)
            USERGroupNMB = re.search('[\']UserGroupNMB[\'][\,][\'](.*?)[\'][\)]', res.text, re.DOTALL).group(1)

            ret = [host,redirecthost,res.cookies,UserToken,EPGGroupNMB,USERGroupNMB]
            return ret
        except Exception as e:
            n += 1
            time.sleep(3)
            print(e)

# 获取频道列表所在的链接位置
def getFrameBuilderLink(eashost,redirecthost,cookies,UserToken,EPGGroupNMB,USERGroupNMB):
    eashostip = eashost.split(":")

    # 为避免出现意外错误或业务页面变动，此处对实际业务鉴权流程中的多个页面均进行访问
    urlFirst = 'http://%s/iptvepg/function/index.jsp?UserGroupNMB=%s&EPGGroupNMB=%s&UserToken=%s&UserID=%s&STBID=%s&easip=%s&networkid=1' % (redirecthost, USERGroupNMB, EPGGroupNMB, UserToken, UserID, STBID, eashostip[0])
    headersFirst = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'User-Agent': UserAgent,
        'Referer': 'http://%s/iptvepg/platform/auth.jsp?easip=%s&ipVersion=4&networkid=1'%(redirecthost, eashostip[0])
    }
    resFirst = requests.get(urlFirst,headers=headersFirst,cookies = cookies,timeout=10)
    resFirst.encoding = 'utf-8'
    portalauthURL = re.search('[\<]form action[\=][\"](.*?)[\"] name', resFirst.text, re.DOTALL).group(1)

    urlSecond = 'http://%s/iptvepg/function/%s' %(redirecthost, portalauthURL)
    headersSecond = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'User-Agent': UserAgent,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': urlFirst,
    }
    dataSecond = {
        'UserToken': UserToken,
        'UserID': UserID,
        'STBID': STBID,
        'stbinfo': '',
        'prmid': '',
        'StbIP': ip,
        'easip': eashostip[0],
        'networkid': '1',
        'stbtype': STBType,
        'drmsupplier': '',
    }
    resSecond = requests.post(urlSecond,headers = headersSecond,cookies = cookies,data = dataSecond,timeout = 10)
    resSecond.encoding = 'utf-8'
    frameURL = re.search('window.location [\=] [\"](.*?)[\"]', resSecond.text, re.DOTALL).group(1)

    urlThird = 'http://%s/iptvepg/function/%s' % (redirecthost, frameURL)
    headersThird = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'User-Agent': UserAgent,
        'Referer': urlSecond,
    }
    resThird = requests.get(urlThird, headers=headersThird, cookies=cookies, timeout=10)
    resThird.encoding = 'utf-8'
    framesetJudgerURL = re.search('action[\=][\"](.*?)[\"] [\>]', resThird.text, re.DOTALL).group(1)

    urlFourth = 'http://%s/iptvepg/function/%s' % (redirecthost, framesetJudgerURL)
    headersFourth = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'User-Agent': UserAgent,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': urlThird,
    }
    dataFourth = {
        'picturetype': '1,3,5',
    }
    resFourth = requests.post(urlFourth, headers=headersFourth, cookies=cookies, data=dataFourth, timeout=10)
    resFourth.encoding = 'utf-8'
    framesetBuilderURL = re.search('action[\=][\"](.*?)[\"]', resFourth.text, re.DOTALL).group(1)

    # 取得节目单页面地址
    finalURL = 'http://%s/iptvepg/function/%s' % (redirecthost, framesetBuilderURL)
    MAIN_WIN_SRC = re.search('value[\=][\"](.*?)[\"]', resFourth.text, re.DOTALL).group(1)
    ret = [finalURL, MAIN_WIN_SRC, urlFourth]

    return ret

# 获取频道列表
def getChannelList(finalURL, MAIN_WIN_SRC, urlFourth, cookies):
    data = {
            'MAIN_WIN_SRC': MAIN_WIN_SRC,
            'NEED_UPDATE_STB': '1',
            'BUILD_ACTION': 'FRAMESET_BUILDER',
            'hdmistatus': 'undefined',
            }
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'User-Agent': UserAgent,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': urlFourth,
    }
    n = 1 #重试次数
    while n < 5:
        try:
            res = requests.post(finalURL,data = data,headers=headers,cookies = cookies)
            break
        except Exception as e:
            print('获取福建电信IPTV频道列表失败: %s'%e)
            n += 1
            time.sleep(3)
    res.encoding = 'gb2312'

    allChannels = re.findall('ChannelName[\=][\"](.+?)[\"].+?ChannelURL[\=][\"]igmp://(.+?)\",', res.text)
    channels = []
    for channel in allChannels:
        channel = list(channel)
        channels.append(channel)
    print('共获取频道数量为：%s, M3U 文件存储于当前目录的: %s 文件.'%(len(channels), save_dir_m3u))
    return channels

# 获取节目单的主函数
def get_channels(key):
    print('%s 开始运行'%date_now)
    print('警告！仅供福建电信IPTV电视盒故障排查测试使用，切勿用于其他用途，否则后果自负！')

    # 首先登录到鉴权服务器获取 Session
    while len(key) != 8:
        key = input('请输入8位数的key:')
    try:
        host, redirecthost, cookies, usertoken, EPGGroupNMB, USERGroupNMB = getSession(key)
        if len(cookies['JSESSIONID']) < 5:
            print('未获取到 Session，请检查脚本要求的参数是否已正确配置！')
            return
    except Exception as e:
        print('获取 Session 失败,请检查网络！:%s'%e)
        return
    print('已经获取到 Token: %s, 对应的 JSESSIONID: %s'%(usertoken,cookies['JSESSIONID']))

    # 获取最终频道列表页面
    finalURL, MAIN_WIN_SRC, urlFourth = getFrameBuilderLink(host, redirecthost, cookies, usertoken, EPGGroupNMB, USERGroupNMB)

    # 获取频道列表
    channels = getChannelList(finalURL, MAIN_WIN_SRC, urlFourth, cookies)

    fm3u = open(save_dir_m3u,'w')
    m3uline1 = '#EXTM3U\n'
    fm3u.write(m3uline1)
    for channel in channels:
        m3uline = '#EXTINF:-1 ,%s\nhttp://%s/udp/%s\n'%(channel[0], uproxyServer, channel[1])
        fm3u.write(m3uline)
    fm3u.close()

# 爆破 Key 的函数，可能获取到多个，任意一个都是可用的
def find_key(Authenticator):
    keys = []
    while len(Authenticator) < 10:
        Authenticator = input('未配置Authenticator，请输入正确的Authenticator的值：')
    print('开始测试00000000-99999999所有八位数字')
    for x in range(100000000):
        key = str('%08d'%x)
        if x % 500000 == 0:
            print('已经搜索至：-- %s -- '%key)
        pc = prpcrypt('%s'%key)
        try:
            ee = pc.decrypt(Authenticator)
            infos = ee.split('$')
            infotxt = '随机数:%s\n  TOKEN:%s\n  USERID:%s\n  STBID:%s\n  ip:%s\n  mac:%s\n  运营商:%s'%(infos[0],infos[1],infos[2],infos[3],infos[4],infos[5],infos[7]) if len(infos)>7 else ''
            printtxt = '找到key:%s,解密后为:%s\n%s'%(x,ee,infotxt)
            print(printtxt)
            keys.append(key)
        except Exception as e:
            pass

    with open(os.getcwd() +'/key.txt','w') as f:
        line = '%s\n共找到KEY：%s个,分别为：%s\n解密信息为:%s\n详情：%s'%(date_now,len(keys),','.join(keys),str(ee),infotxt)
        f.write(line)
        f.flush()
    print('解密完成！相关信息已存储到当前目录下的 key.txt 内，共查找到 %s 个密钥，分别为：%s'%(len(keys),keys))#

# 以下两个函数执行请根据需要取消注释
# get_channels(key) # 获取组播频道列表
# find_key(Authenticator) # 爆破KEY

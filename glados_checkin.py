# -*- coding: utf-8 -*
'''
cron: 37 8/8 * * *
new Env('glados checkin');
'''
import socket  # 用于端口检测
import base64  # 用于编解码
import json  # 用于Json解析
import os  # 用于导入系统变量
import sys  # 实现 sys.exit
import logging  # 用于日志输出
import time  # 时间
import re  # 正则过滤
import hmac
import struct

GLADOS_MODE = 0
# 0 = Default / 1 = Debug!

if "GLADOS_DEBUG" in os.environ or GLADOS_MODE:  # 判断调试模式变量
    logging.basicConfig(level=logging.DEBUG, format='%(message)s')  # 设置日志为 Debug等级输出
    logger = logging.getLogger(__name__)  # 主模块
    logger.debug("\nDEBUG模式开启!\n")  # 消息输出
else:  # 判断分支
    logging.basicConfig(level=logging.INFO, format='%(message)s')  # Info级日志
    logger = logging.getLogger(__name__)  # 主模块

try:  # 异常捕捉
    import requests  # 导入HTTP模块
except Exception as e:  # 异常捕捉
    logger.info(str(e) + "\n缺少requests模块, 请执行命令：pip3 install requests\n")  # 日志输出
    sys.exit(1)  # 退出脚本
os.environ['no_proxy'] = '*'  # 禁用代理
requests.packages.urllib3.disable_warnings()  # 抑制错误
try:  # 异常捕捉
    from notify import send  # 导入青龙消息通知模块
except Exception as err:  # 异常捕捉
    logger.debug(str(err))  # 调试日志输出
    logger.info("无推送文件")  # 标准日志输出

ver = 21212  # 版本号


def ttotp(key):
    key = base64.b32decode(key.upper() + '=' * ((8 - len(key)) % 8))
    counter = struct.pack('>Q', int(time.time() / 30))
    mac = hmac.new(key, counter, 'sha1').digest()
    offset = mac[-1] & 0x0f
    binary = struct.unpack('>L', mac[offset:offset + 4])[0] & 0x7fffffff
    return str(binary)[-6:].zfill(6)


def ql_send(text):
    if "GLADOS_SEND" in os.environ and os.environ["GLADOS_SEND"] == 'disable':
        return True
    else:
        try:  # 异常捕捉
            send('GLADOS 签到', text)  # 消息发送
        except Exception as err:  # 异常捕捉
            logger.debug(str(err))  # Debug日志输出
            logger.info("通知发送失败")  # 标准日志输出


# 登录青龙 返回值 token
def get_qltoken(username, password, twoFactorSecret):  # 方法 用于获取青龙 Token
    logger.info("Token失效, 新登陆\n")  # 日志输出
    if twoFactorSecret:
        try:
            twoCode = ttotp(twoFactorSecret)
        except Exception as err:
            logger.debug(str(err))  # Debug日志输出
            logger.info("TOTP异常")
            sys.exit(1)
        url = ql_url + "api/user/login"  # 设置青龙地址 使用 format格式化自定义端口
        payload = json.dumps({
            'username': username,
            'password': password
        })  # HTTP请求载荷
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }  # HTTP请求头 设置为 Json格式
        try:  # 异常捕捉
            res = requests.post(url=url, headers=headers, data=payload)  # 使用 requests模块进行 HTTP POST请求
            if res.status_code == 200 and res.json()["code"] == 420:
                url = ql_url + 'api/user/two-factor/login'
                data = json.dumps({
                    "username": username,
                    "password": password,
                    "code": twoCode
                })
                res = requests.put(url=url, headers=headers, data=data)
                if res.status_code == 200 and res.json()["code"] == 200:
                    token = res.json()["data"]['token']  # 从 res.text 返回值中 取出 Token值
                    return token
                else:
                    logger.info("两步校验失败\n")  # 日志输出
                    sys.exit(1)
            elif res.status_code == 200 and res.json()["code"] == 200:
                token = res.json()["data"]['token']  # 从 res.text 返回值中 取出 Token值
                return token
        except Exception as err:
            logger.debug(str(err))  # Debug日志输出
            sys.exit(1)
    else:
        url = ql_url + 'api/user/login'
        payload = {
            'username': username,
            'password': password
        }  # HTTP请求载荷
        payload = json.dumps(payload)  # json格式化载荷
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }  # HTTP请求头 设置为 Json格式
        try:  # 异常捕捉
            res = requests.post(url=url, headers=headers, data=payload)  # 使用 requests模块进行 HTTP POST请求
            if res.status_code == 200 and res.json()["code"] == 200:
                token = res.json()["data"]['token']  # 从 res.text 返回值中 取出 Token值
                return token
            else:
                ql_send("青龙登录失败!")
                sys.exit(1)  # 脚本退出
        except Exception as err:
            logger.debug(str(err))  # Debug日志输出
            logger.info("使用旧版青龙登录接口")
            url = ql_url + 'api/login'  # 设置青龙地址 使用 format格式化自定义端口
            payload = {
                'username': username,
                'password': password
            }  # HTTP请求载荷
            payload = json.dumps(payload)  # json格式化载荷
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }  # HTTP请求头 设置为 Json格式
            try:  # 异常捕捉
                res = requests.post(url=url, headers=headers, data=payload)  # 使用 requests模块进行 HTTP POST请求
                token = json.loads(res.text)["data"]['token']  # 从 res.text 返回值中 取出 Token值
            except Exception as err:  # 异常捕捉
                logger.debug(str(err))  # Debug日志输出
                logger.info("青龙登录失败, 请检查面板状态!")  # 标准日志输出
                ql_send('青龙登陆失败, 请检查面板状态.')
                sys.exit(1)  # 脚本退出
            else:  # 无异常执行分支
                return token  # 返回 token值
        # else:  # 无异常执行分支
        #     return token  # 返回 token值


# 返回值 Token
def ql_login():  # 方法 青龙登录(获取Token 功能同上)
    path = '/ql/config/auth.json'  # 设置青龙 auth文件地址
    if not os.path.isfile(path):
        path = '/ql/data/config/auth.json'  # 尝试设置青龙 auth 新版文件地址
    if os.path.isfile(path):  # 进行文件真值判断
        with open(path, "r") as file:  # 上下文管理
            auth = file.read()  # 读取文件
            file.close()  # 关闭文件
        auth = json.loads(auth)  # 使用 json模块读取
        username = auth["username"]  # 提取 username
        password = auth["password"]  # 提取 password
        token = auth["token"]  # 提取 authkey
        try:
            twoFactorSecret = auth["twoFactorSecret"]
        except Exception as err:
            logger.debug(str(err))  # Debug日志输出
            twoFactorSecret = ''
        if token == '':  # 判断 Token是否为空
            return get_qltoken(username, password, twoFactorSecret)  # 调用方法 get_qltoken 传递 username & password
        else:  # 判断分支
            url = ql_url + 'api/user'  # 设置URL请求地址 使用 Format格式化端口
            headers = {
                'Authorization': 'Bearer {0}'.format(token),
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36 Edg/94.0.992.38'
            }  # 设置用于 HTTP头
            res = requests.get(url=url, headers=headers)  # 调用 request模块发送 get请求
            if res.status_code == 200:  # 判断 HTTP返回状态码
                return token  # 有效 返回 token
            else:  # 判断分支
                return get_qltoken(username, password, twoFactorSecret)  # 调用方法 get_qltoken 传递 username & password
    else:  # 判断分支
        logger.info("没有发现auth文件, 你这是青龙吗???")  # 输出标准日志
        sys.exit(0)  # 脚本退出


# 返回值 list[wskey]
def get_glados_ck():  # 方法 获取 wskey值 [系统变量传递]
    if "GLADOS_CK" in os.environ:  # 判断 GLADOS_CK是否存在于环境变量
        wskey_list = os.environ['GLADOS_CK'].split('&')  # 读取系统变量 以 & 分割变量
        if len(wskey_list) > 0:  # 判断 GLADOS 数量 大于 0 个
            return wskey_list  # 返回 GLADOS [LIST]
        else:  # 判断分支
            logger.info("GLADOS_CK变量未启用")  # 标准日志输出
            sys.exit(1)  # 脚本退出
    else:  # 判断分支
        logger.info("未添加GLADOS_CK变量")  # 标准日志输出
        sys.exit(0)  # 脚本退出

# 返回值 ckstr,result
def get_checkin_ck(ck):  # 方法 签到，返回签到的 ck
    url= "https://glados.rocks/api/user/checkin"
    url2= "https://glados.rocks/api/user/status"
    referer = 'https://glados.rocks/console/checkin'
    origin = "https://glados.rocks"
    useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36"
    payload={
        'token': 'glados.one'
    }
    logger.debug(ck)
    checkin = requests.post(url,headers={'cookie': ck ,'referer': referer,'origin':origin,'user-agent':useragent,'content-type':'application/json;charset=UTF-8'},data=json.dumps(payload))
    state =  requests.get(url2,headers={'cookie': ck ,'referer': referer,'origin':origin,'user-agent':useragent})
    logger.debug(checkin.json())
    logger.debug(state.json())
    cookiestr = str()

    cookies=checkin.cookies
    for name, value in cookies.items():
        logger.info(name,value)
        cookiestr += name+"="+value

    return cookiestr,checkin.json(),state.json()


def ql_check(port):  # 方法 检查青龙端口
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Socket模块初始化
    sock.settimeout(2)  # 设置端口超时
    try:  # 异常捕捉
        sock.connect(('127.0.0.1', port))  # 请求端口
    except Exception as err:  # 捕捉异常
        logger.debug(str(err))  # 调试日志输出
        sock.close()  # 端口关闭
        return False  # 返回 -> False[Bool]
    else:  # 分支判断
        sock.close()  # 关闭端口
        return True  # 返回 -> True[Bool]


def get_env():  # 方法 读取变量
    url = ql_url + 'api/envs'
    try:  # 异常捕捉
        res = s.get(url)  # HTTP请求 [GET] 使用 session
    except Exception as err:  # 异常捕捉
        logger.debug(str(err))  # 调试日志输出
        logger.info("\n青龙环境接口错误")  # 标准日志输出
        sys.exit(1)  # 脚本退出
    else:  # 判断分支
        data = json.loads(res.text)['data']  # 使用Json模块提取值[data]
        return data  # 返回 -> data


def check_id():  # 方法 兼容青龙老版本与新版本 id & _id的问题
    url = ql_url + 'api/envs'
    try:  # 异常捕捉
        res = s.get(url).json()  # HTTP[GET] 请求 使用 session
    except Exception as err:  # 异常捕捉
        logger.debug(str(err))  # 调试日志输出
        logger.info("\n青龙环境接口错误")  # 标准日志输出
        sys.exit(1)  # 脚本退出
    else:  # 判断分支
        if '_id' in res['data'][0]:  # 判断 [_id]
            logger.info("使用 _id 键值")  # 标准日志输出
            return '_id'  # 返回 -> '_id'
        else:  # 判断分支
            logger.info("使用 id 键值")  # 标准日志输出
            return 'id'  # 返回 -> 'id'


def ql_update(e_id, n_ck):  # 方法 青龙更新变量 传递 id cookie
    url = ql_url + 'api/envs'
    data = {
        "name": "GLADOS_CK",
        "value": n_ck,
        ql_id: e_id
    }  # 设置 HTTP POST 载荷
    data = json.dumps(data)  # json模块格式化
    s.put(url=url, data=data)  # HTTP [PUT] 请求 使用 session
    ql_enable(eid)  # 调用方法 ql_enable 传递 eid


def ql_enable(e_id):  # 方法 青龙变量启用 传递值 eid
    url = ql_url + 'api/envs/enable'
    data = '["{0}"]'.format(e_id)  # 格式化 POST 载荷
    res = json.loads(s.put(url=url, data=data).text)  # json模块读取 HTTP[PUT] 的返回值
    if res['code'] == 200:  # 判断返回值为 200
        logger.info("\n账号启用\n--------------------\n")  # 标准日志输出
        return True  # 返回 ->True
    else:  # 判断分支
        logger.info("\n账号启用失败\n--------------------\n")  # 标准日志输出
        return False  # 返回 -> Fasle


def ql_disable(e_id):  # 方法 青龙变量禁用 传递 eid
    url = ql_url + 'api/envs/disable'
    data = '["{0}"]'.format(e_id)  # 格式化 POST 载荷
    res = json.loads(s.put(url=url, data=data).text)  # json模块读取 HTTP[PUT] 的返回值
    if res['code'] == 200:  # 判断返回值为 200
        logger.info("\n账号禁用成功\n--------------------\n")  # 标准日志输出
        return True  # 返回 ->True
    else:  # 判断分支
        logger.info("\n账号禁用失败\n--------------------\n")  # 标准日志输出
        return False  # 返回 -> Fasle


def ql_insert(i_ck):  # 方法 插入新变量
    data = [{"value": i_ck, "name": "GLADOS_CK"}]  # POST数据载荷组合
    data = json.dumps(data)  # Json格式化数据
    url = ql_url + 'api/envs'
    s.post(url=url, data=data)  # HTTP[POST]请求 使用session
    logger.info("\n账号添加完成\n--------------------\n")  # 标准日志输出

def check_port():  # 方法 检查变量传递端口
    logger.info("\n--------------------\n")  # 标准日志输出
    if "QL_PORT" in os.environ:  # 判断 系统变量是否存在[QL_PORT]
        try:  # 异常捕捉
            port = int(os.environ['QL_PORT'])  # 取值 [int]
        except Exception as err:  # 异常捕捉
            logger.debug(str(err))  # 调试日志输出
            logger.info("变量格式有问题...\n格式: export QL_PORT=\"端口号\"")  # 标准日志输出
            logger.info("使用默认端口5700")  # 标准日志输出
            return 5700  # 返回端口 5700
    else:  # 判断分支
        port = 5700  # 默认5700端口
    if not ql_check(port):  # 调用方法 [ql_check] 传递 [port]
        logger.info(str(port) + "端口检查失败, 如果改过端口, 请在变量中声明端口 \n在config.sh中加入 export QL_PORT=\"端口号\"")  # 标准日志输出
        logger.info("\n如果你很确定端口没错, 还是无法执行, 在GitHub给我发issus\n--------------------\n")  # 标准日志输出
        sys.exit(1)  # 脚本退出
    else:  # 判断分支
        logger.info(str(port) + "端口检查通过")  # 标准日志输出
        return port  # 返回->port

def serch_ck():  # 方法 搜索 Pin
    logger.info("env list len:"+str(len(envlist)))
    for i in range(len(envlist)):  # For循环 变量[envlist]的数量
        if  envlist[i]["name"] != "GLADOS_CK":  # 判断 envlist内容
            continue  # 继续循环
        id = envlist[i][ql_id]  # 取值 [ql_id](变量)
        logger.info("GLADOS_CK检索成功\n")  # 标准日志输出
        return True, id  # 返回 -> True[Bool], value, id

    logger.info("GLADOS_CK检索失败\n")  # 标准日志输出
    return False, 1  # 返回 -> False[Bool], 1

if __name__ == '__main__':  # Python主函数执行入口
    port = check_port()  # 调用方法 [check_port]  并赋值 [port]
    ql_url = 'http://127.0.0.1:{0}/'.format(port)
    token = ql_login()  # 调用方法 [ql_login]  并赋值 [token]
    s = requests.session()  # 设置 request session方法
    s.headers.update({"authorization": "Bearer " + str(token)})  # 增加 HTTP头认证
    s.headers.update({"Content-Type": "application/json;charset=UTF-8"})  # 增加 HTTP头 json 类型
    ql_id = check_id()  # 调用方法 [check_id] 并赋值 [ql_id]
    wslist = get_glados_ck()  # 调用方法 [get_glados_ck] 并赋值 [wslist]
    envlist = get_env()  # 调用方法 [get_env] 并赋值 [envlist]
    sleepTime = 10  # 默认休眠时间 10秒

    new_ck = str()

    message_all = str()

    idx = 0
    for ws in wslist:  # wslist变量 for循环  [wslist -> ws]
        idx+=1
        if idx >1 :
            new_ck +="&"
        message_all +="账号"+str(idx)+":\n"
        checkin_ret = get_checkin_ck(ws)

        if len(checkin_ret[0]) == 0:
            message_all +="无 cookie\n"
            new_ck+=ws

        else:
            if idx == 1:
                new_ck = "GLADOS_CK=GLADOS_CK;"
            new_ck+=checkin_ret[0]
            
        mess = checkin_ret[1]['message']
        days = checkin_ret[2]['data']['leftDays']
        days = days.split('.')[0]
        message_all += f"{mess},you have {days} days left\n"
        logger.info(message_all)  # 标准日志输出
        logger.info("脚本休眠 10s \n--------------------\n")  # 标准日志输出
        # time.sleep(sleepTime)  # 脚本休眠

    return_serch = serch_ck()  # 变量 pt_pin 搜索获取 key eid
    if return_serch[0]: 
        eid = return_serch[1]  # 从 return_serch 拿到 eid
        ql_update(eid, new_ck)  # 函数 ql_update 参数 eid GLADOS_CK
        pass
    else:
        ql_insert(new_ck)  # 调用方法 [ql_insert]

    ql_send(message_all)
    logger.info("执行完成\n--------------------")  # 标准日志输出
    sys.exit(0)  # 脚本退出
    # Enjoy
    # glados_checkin

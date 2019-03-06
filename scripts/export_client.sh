#/bin/sh

# 导出客户端证书

# pkcs12: 用来处理pkcs#12格式的证书
# -export: 执行的是导出操作
# -clcerts: 导出的是客户端证书, -cacerts 则表示导出的是 CA 证书
# -name: 导出的证书别名
# -inkey: 证书的私钥路径
# -in: 要导出的证书的路径
# -out: 输出的密钥库文件的路径
openssl pkcs12 -export -clcerts -name myclient -inkey client/private/client.pem -in client/client.crt -out client/client.keystore
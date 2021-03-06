#/bin/sh

# /home/kiki/qt-workspace/github/GmSSL/include
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/kiki/qt-workspace/github/GmSSL/
echo $LD_LIBRARY_PATH
gmssl -help
gmssl ec -out client/private/ec.pem 512
exit

# 客户端证书
mkdir -p client/private
chmod 700 client/private

# 1. 制作客户端私钥
# 常使用 PEM（Privacy Enbanced Mail）格式来保存私钥
# genrsa: 使用RSA算法产生私钥
# 1024: 指定私钥长度, 1024 位强度
# -out: 输出文件的路径, client/private/client.key 是 秘钥文件名
openssl genrsa -out client/private/client.pem 1024
openssl rsa -in client/private/client.pem -out client/private/client.key

# 2. 生成证书签名请求
# req: 执行证书签发命令
# -new: 新证书签发请求
# -key: 指定私钥路径
# -out: 输出的 csr/crt 文件的路径
# openssl req -new -key client/private/client.key -out client/client.csr
openssl req -new -key client/private/client.pem -out client/client.csr

# 3. 用 CA 签发, 生成自签名证书
# x509: 生成 X.509 格式证书
# -req: 执行证书签发命令
# -sha256: 证书摘要采用 sha256 算法
# -in: 要输入的 csr 文件
# -CA: 指定 CA 证书的路径
# -CAkey: 指定 CA 证书的私钥路径
# -CAserial: 指定证书序列号文件的路径
# -CAcreateserial: 表示创建证书序列号文件(即上方提到的 serial 文件), 创建的序列号文件默认名称为 -CA 指定的证书名称后加上.srl后缀
## 签发服务端证书时已经使用 -CAcreateserial 生成过 ca.srl 文件, 因此这里不需要带上这个参数了
# -days: 证书的有效期(天)
# -key: 指定私钥路径
# -out: 输出的 csr/crt 文件的路径
# 需要依次输入国家, 地区, 城市, 组织, 组织单位, Common Name和Email
# Common Name 可写自己的名字或域名, 如果要支持https, Common Name应与域名保持一致, 否则会引起浏览器警告
openssl x509 -req -sha256 -in client/client.csr -CA ca/ca.crt -CAkey ca/private/ca.key -days 3650 -out client/client.crt
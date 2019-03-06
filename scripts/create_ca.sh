#/bin/sh

mkdir -p ca/private
chmod 700 ca/private

# 制作 CA 私钥, 根证书(公钥)
# openssl req -x509 -days 3650 -newkey rsa:1024 -keyout ca/private/ca.key -out ca/ca.crt

# 1. 制作 CA 私钥
# 常使用 PEM（Privacy Enbanced Mail）格式来保存私钥
# genrsa: 使用RSA算法产生私钥
# 1024: 指定私钥长度, 1024 位强度
# -out: 输出文件的路径, ca/private/ca.key 是 秘钥文件名
openssl genrsa -out ca/private/ca.key 1024

# 2. 制作 CA 根证书(公钥)
# req: 执行证书签发命令
# -new: 新证书签发请求
# -x509: 生成 X.509 格式证书
# -days: 证书的有效期(天)
# -key: 指定私钥路径
# -out: 输出的 csr/crt 文件的路径
openssl req -new -x509 -days 3650 -key ca/private/ca.key -out ca/ca.crt
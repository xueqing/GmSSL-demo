#/bin/sh

# 导出信任证书

keytool -importcert -trustcacerts -alias www.bmi-tech.cn -file ca/ca.cer -keystore ca/ca-trust.keystore
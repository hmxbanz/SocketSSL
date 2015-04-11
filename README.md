
SSL Serrver Socket with commercial ssl
# SSLSocketServer_StartSSLCerts.cs 
# SSLSocketClient_StartSSLCerts.cs

Use free ssl cert(ssl.p12) from startssl.com format pfx .p12
servername => certyfikate CN field


#======================================================================================================
# SocketSSL
SocketSSL Server and Client and Create certs


# How to create certyficates(FakeServerName):
makecert -sv RootCATest.pvk -r -n "CN=FakeServerName" RootCATest.cer
makecert -ic RootCATest.cer -iv RootCATest.pvk -n "CN=FakeServerName" -sv  TempCert.pvk -pe -sky exchange TempCert.cer
cert2spc TempCert.cer TempCert.spc
pvkimprt -pfx TempCert.spc TempCert.pvk

# How to use:
SslTcpServer.exe TempCert.cer
SslTcpClient.exe  localhost FakeServerName


# Links tuts:
http://stackoverflow.com/questions/9982865/sslstream-example-how-do-i-get-certificates-that-work




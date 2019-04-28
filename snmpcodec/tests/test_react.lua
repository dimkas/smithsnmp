zsnmpd=require'zsnmpd.daemon'

config={
 communities = {
   { community = 'public', views = { ["."] = 'ro' } },
   { community = 'private', views = { ["."] = 'rw' } },
 },

 users = {
   { user = 'roNoAuthUser', views = { ["."] = 'ro' } },
   { user = 'rwNoAuthUser', views = { ["."] = 'rw' } },
   { user = 'roAuthUser', auth_mode = "md5", auth_phrase = "roAuthUser", views = { ["."] = 'ro' } },
   { user = 'rwAuthUser', auth_mode = "md5", auth_phrase = "rwAuthUser", views = { ["."] = 'rw' } },
   { user = 'roAuthPrivUser', auth_mode = "md5", auth_phrase = "roAuthPrivUser", encrypt_mode = "aes", encrypt_phrase = "roAuthPrivUser", views = { ["."] = 'ro' } },
   { user = 'rwAuthPrivUser', auth_mode = "md5", auth_phrase = "rwAuthPrivUser", encrypt_mode = "aes", encrypt_phrase = "rwAuthPrivUser", views = { ["."] = 'rw' } },
 },

 mib_module_path = 'mibs',

 mib_modules = {
 ["1.3.6.1.2.1.1"] = 'system',
 },
}

zsnmpd.load_config(config)

ZDC_DIR= '/workspace/zdc/'
APP_DIR= '/workspace/ptmstp/lua/'

package.path=ZDC_DIR..'bin/?.lua;'..APP_DIR..'?.lua;'..package.path
package.cpath=ZDC_DIR..'lib/mac64/?.so;'..APP_DIR..'../build/mac64/?.so;'..package.cpath
package.path=ZDC_DIR..'lua/?.lua;'..ZDC_DIR..'lib/lua/?.lua;'..package.path

socket=require'socket'
snmpcodec=require "snmpcodec"
udp=socket.udp()
assert(udp:setsockname('*',161))
while true do
 buf,host,port=udp:receivefrom()
 print('receive',#buf)
 sendbuf=snmpcodec.snmp_receive(buf)
 print('sendbuf',#sendbuf,host,port)
 udp:sendto(sendbuf,host,port)
end

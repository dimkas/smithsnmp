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

 mib_module_path = '../mibs',

 mib_modules = {
 ["1.3.6.1.2.1.1"] = 'system',
 ["1.3.6.1.2.1.2"] = 'interfaces',
 --    ["1.3.6.1.2.1.4"] = 'ip',
 --    ["1.3.6.1.2.1.6"] = 'tcp',
 --    ["1.3.6.1.2.1.7"] = 'udp',
 ["1.3.6.1.4.1.8888.1"] = 'two_cascaded_index_table',
 ["1.3.6.1.4.1.8888.2"] = 'three_cascaded_index_table',
 ["1.3.6.1.1"] = 'dummy',
 --    ["1.3.6.1.2.1.5"] = 'icmp',
 ["1.3.6.1.6.3.1.1.4"] = 'snmptrap',
 },
}

zsnmpd.load_config(config)

ZDC_DIR= '/workspace/zdc/'
APP_DIR= '/workspace/ptmstp/lua/'

package.path=ZDC_DIR..'bin/?.lua;'..APP_DIR..'?.lua;'..package.path
package.cpath=ZDC_DIR..'lib/mac64/?.so;'..APP_DIR..'../build/mac64/?.so;'..package.cpath
package.path=ZDC_DIR..'lua/?.lua;'..ZDC_DIR..'lib/lua/?.lua;'..package.path

socket=require'socket'
udp=socket.udp()
assert(udp:setsockname('*',161))
while true do
 buf=udp:receive()
 print('receive',#buf)
 zsnmpd.snmp_receive(buf)
end

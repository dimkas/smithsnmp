
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "snmp.h"

int smithsnmp_mib_node_reg(lua_State *L);
int smithsnmp_mib_node_unreg(lua_State *L);
int smithsnmp_mib_community_reg(lua_State *L);
int smithsnmp_mib_community_unreg(lua_State *L);
int smithsnmp_mib_user_create(lua_State *L);
int smithsnmp_mib_user_reg(lua_State *L);
int smithsnmp_mib_user_unreg(lua_State *L);

int snmp_trap_init();
int snmp_trap_varbind(lua_State *L);
int snmp_trap_getbuffer(lua_State *L);

int snmpcodec_init(lua_State *L);
int snmp_receive(lua_State *L);

static const luaL_Reg R[] =
{
  { "init", snmpcodec_init },

  //mib
  { "mib_node_reg", smithsnmp_mib_node_reg },
  { "mib_node_unreg", smithsnmp_mib_node_unreg },
  { "mib_community_reg", smithsnmp_mib_community_reg },
  { "mib_community_unreg", smithsnmp_mib_community_unreg },
  { "mib_user_create", smithsnmp_mib_user_create },
  { "mib_user_reg", smithsnmp_mib_user_reg },
  { "mib_user_unreg", smithsnmp_mib_user_unreg },

  { "snmp_receive", snmp_receive },

  // trap
  { "trap_varbind",snmp_trap_varbind },
  { "trap_getbuffer",snmp_trap_getbuffer },
  { NULL, NULL }
};

int luaopen_snmpcodec(lua_State *L)
{
  snmp_trap_init();

#if LUA_VERSION_NUM < 502
	luaL_register(L,"snmpcodec", R);
#else
	lua_newtable(L);
	luaL_setfuncs(L, R, 0);
#endif

	return 1;
}

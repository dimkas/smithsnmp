#include <ctype.h>
#include <string.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "trap.h"
#include "mib.h"
#include "snmp.h"
#include "protocol.h"

struct snmp_datagram snmp_datagram;
const uint8_t snmpv3_engine_id[] = {
  0x80, 0x00, 0x00, 0x00,
  /* Text tag */
  0x04,
  /* Text content */
  'S', 'm', 'a', 'r', 't', 'S', 'N', 'M', 'P'
};

/* Register mib nodes from Lua */
int
smithsnmp_mib_node_reg(lua_State *L)
{
  oid_t *grp_id;
  int i, grp_id_len, grp_cb;

  /* Check if the first argument is a table. */
  luaL_checktype(L, 1, LUA_TTABLE);
  /* Get oid length */
  grp_id_len = lua_objlen(L, 1);
  /* Get oid */
  grp_id = xmalloc(grp_id_len * sizeof(oid_t));
  for (i = 0; i < grp_id_len; i++) {
    lua_rawgeti(L, 1, i + 1);
    grp_id[i] = lua_tointeger(L, -1);
    lua_pop(L, 1);
  }
  /* Attach lua handler to group node */
  if (!lua_isfunction(L, -1)) {
    lua_pushstring(L, "MIB handler is not a function!");
    lua_error(L);
  }
  grp_cb = luaL_ref(L, LUA_ENVIRONINDEX);

  /* Register group node */
  i = mib_node_reg(grp_id, grp_id_len, grp_cb);
  free(grp_id);

  /* Return value */
  lua_pushnumber(L, i);
  return 1;
}

/* Unregister mib nodes from Lua */
int
smithsnmp_mib_node_unreg(lua_State *L)
{
  oid_t *grp_id;
  int i, grp_id_len;

  /* Check if the first argument is a table. */
  luaL_checktype(L, 1, LUA_TTABLE);
  /* Get oid length */
  grp_id_len = lua_objlen(L, 1);
  /* Get oid */
  grp_id = xmalloc(grp_id_len * sizeof(oid_t));
  for (i = 0; i < grp_id_len; i++) {
    lua_rawgeti(L, 1, i + 1);
    grp_id[i] = lua_tointeger(L, -1);
    lua_pop(L, 1);
  }

  /* Unregister group node */
  i = 0;
  mib_node_unreg(grp_id, grp_id_len);
  free(grp_id);

  /* Return value */
  lua_pushnumber(L, i);
  return 1;
}

/* Register community string from Lua */
int
smithsnmp_mib_community_reg(lua_State *L)
{
  oid_t *oid;
  int i, id_len, attribute;
  const char *community;

  /* Check if the first argument is a table. */
  luaL_checktype(L, 1, LUA_TTABLE);
  /* Get oid length */
  id_len = lua_objlen(L, 1);
  /* Get oid */
  oid = xmalloc(id_len * sizeof(oid_t));
  for (i = 0; i < id_len; i++) {
    lua_rawgeti(L, 1, i + 1);
    oid[i] = lua_tointeger(L, -1);
    lua_pop(L, 1);
  }

  /* Community string and RW attribute */
  community = luaL_checkstring(L, 2);
  attribute = luaL_checkint(L, 3);

  /* Register community string */
  mib_community_reg(oid, id_len, community, attribute);
  free(oid);

  return 0;
}

/* Unregister mib community string from Lua */
int
smithsnmp_mib_community_unreg(lua_State *L)
{
  /* Unregister community string */
  const char *community = luaL_checkstring(L, 1);
  int attribute = luaL_checkint(L, 2);
  mib_community_unreg(community, attribute);

  return 0;
}

/* Create user from Lua */
int
smithsnmp_mib_user_create(lua_State *L)
{
  const char *user;
  const char *auth_phrase;
  const char *encrypt_phrase;
  uint8_t auth_mode, encrypt_mode;

  user = luaL_checkstring(L, 1);
  auth_mode = luaL_checkint(L, 2);
  auth_phrase = luaL_checkstring(L, 3);
  if (strlen(auth_phrase) && strlen(auth_phrase) < 8) {
    /* at least 8 characters */
    lua_pushboolean(L, 0);
    return 1;
  }
  encrypt_mode = luaL_checkint(L, 4);
  encrypt_phrase = luaL_checkstring(L, 5);
  if (strlen(encrypt_phrase) && strlen(encrypt_phrase) < 8) {
    /* at least 8 characters */
    lua_pushboolean(L, 0);
    return 1;
  }

  /* Create user */
  mib_user_create(user, auth_mode, auth_phrase, encrypt_mode, encrypt_phrase);

  lua_pushboolean(L, 1);
  return 1;
}

/* Register mib user from Lua */
int
smithsnmp_mib_user_reg(lua_State *L)
{
  oid_t *oid;
  int i, id_len, attribute;
  const char *user;

  /* Check if the first argument is a table. */
  luaL_checktype(L, 1, LUA_TTABLE);
  /* Get oid length */
  id_len = lua_objlen(L, 1);
  /* Get oid */
  oid = xmalloc(id_len * sizeof(oid_t));
  for (i = 0; i < id_len; i++) {
    lua_rawgeti(L, 1, i + 1);
    oid[i] = lua_tointeger(L, -1);
    lua_pop(L, 1);
  }

  /* User string and RW attribute */
  user = luaL_checkstring(L, 2);
  attribute = luaL_checkint(L, 3);

  /* Register user string */
  mib_user_reg(oid, id_len, user, attribute);
  free(oid);

  return 0;
}

/* Unregister mib user string from Lua */
int
smithsnmp_mib_user_unreg(lua_State *L)
{
  /* Unregister user string */
  const char *user = luaL_checkstring(L, 1);
  int attribute = luaL_checkint(L, 2);
  mib_user_unreg(user, attribute);

  return 0;
}

int snmpcodec_init(lua_State *L)
{
  /* Init mib tree */
  INIT_LIST_HEAD(&snmp_datagram.vb_in_list);
  INIT_LIST_HEAD(&snmp_datagram.vb_out_list);

  mib_init(L);
  return 0;  
}

static void
snmpcodec_send(uint8_t *buf, int len)
{
}

struct protocol_operation snmp_prot_ops = {
  "snmpcodec",
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  snmpcodec_send,
  NULL,
};

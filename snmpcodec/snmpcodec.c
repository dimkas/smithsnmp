#include <ctype.h>
#include <string.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "trap.h"
#include "mib.h"
#include "snmp.h"

static struct trap_datagram snmp_trap_datagram;


static void
trap_datagram_clear(struct trap_datagram *tdg)
{
  vb_list_free(&tdg->vb_list);
  free(tdg->send_buf);
  tdg->data_len = 0;
  tdg->send_len = 0;
  tdg->vb_cnt = 0;
  tdg->vb_list_len = 0;
  tdg->trap_hdr.pdu_len = 0;
}

static void
snmp_trapv2_header(struct trap_datagram *tdg, uint8_t **buffer)
{
  uint8_t *buf = *buffer;
  struct trapv2_hdr *trap_hdr = &tdg->trap_hdr.trap.v2;

  /* Request ID */
  *buf++ = ASN1_TAG_INT;
  buf += ber_length_enc(trap_hdr->req_id_len, buf);
  buf += ber_value_enc(&trap_hdr->req_id, 1, ASN1_TAG_INT, buf);

  /* Error status */
  *buf++ = ASN1_TAG_INT;
  buf += ber_length_enc(trap_hdr->err_stat_len, buf);
  buf += ber_value_enc(&trap_hdr->err_stat, 1, ASN1_TAG_INT, buf);

  /* Error index */
  *buf++ = ASN1_TAG_INT;
  buf += ber_length_enc(trap_hdr->err_idx_len, buf);
  buf += ber_value_enc(&trap_hdr->err_idx, 1, ASN1_TAG_INT, buf);

  *buffer = buf;
}

static void
snmp_trap_encode(struct trap_datagram *tdg)
{
  uint8_t *buf;
  uint32_t oid_len, len_len;
  const uint32_t tag_len = 1;
  struct var_bind *vb;
  struct list_head *curr;
  struct trap_hdr *trap_hdr = &tdg->trap_hdr;
  struct trapv2_hdr *pdu_hdr = &tdg->trap_hdr.trap.v2;

  /* varbind list len */
  len_len = ber_length_enc_try(tdg->vb_list_len);
  trap_hdr->pdu_len += tag_len + len_len + tdg->vb_list_len;

  /* request id len */
  len_len = ber_length_enc_try(pdu_hdr->req_id_len);
  trap_hdr->pdu_len += tag_len + len_len + pdu_hdr->req_id_len;

  /* error status len */
  len_len = ber_length_enc_try(pdu_hdr->err_stat_len);
  trap_hdr->pdu_len += tag_len + len_len + pdu_hdr->err_stat_len;

  /* error index len */
  len_len = ber_length_enc_try(pdu_hdr->err_idx_len);
  trap_hdr->pdu_len += tag_len + len_len + pdu_hdr->err_idx_len;

  /* PDU len */
  len_len = ber_length_enc_try(trap_hdr->pdu_len);
  tdg->data_len += tag_len + len_len + trap_hdr->pdu_len;

  /* community len */
  len_len = ber_length_enc_try(tdg->comm_len);
  tdg->data_len += tag_len + len_len + tdg->comm_len;

  /* version len */
  len_len = ber_length_enc_try(tdg->ver_len);
  tdg->data_len += tag_len + len_len + tdg->ver_len;

  /* send buffer len */
  len_len = ber_length_enc_try(tdg->data_len);
  tdg->send_len += tag_len + len_len + tdg->data_len;

  /* allocate trap buffer */
  tdg->send_buf = xmalloc(tdg->send_len);
  buf = tdg->send_buf;

  /* sequence tag */
  *buf++ = ASN1_TAG_SEQ;
  buf += ber_length_enc(tdg->data_len, buf);

  /* version */
  int version = tdg->version - 1;
  *buf++ = ASN1_TAG_INT;
  buf += ber_length_enc(tdg->ver_len, buf);
  buf += ber_value_enc(&version, tdg->ver_len, ASN1_TAG_INT, buf);

  /* community */
  *buf++ = ASN1_TAG_OCTSTR;
  buf += ber_length_enc(tdg->comm_len, buf);
  buf += ber_value_enc(tdg->community, tdg->comm_len, ASN1_TAG_OCTSTR, buf);

  /* trap header */
  *buf++ = tdg->trap_hdr.pdu_type;
  buf += ber_length_enc(trap_hdr->pdu_len, buf);

  switch (tdg->version) {
  /*
  case TRAP_V1:
    snmp_trapv1_header(tdg);
    break;
  */
  case TRAP_V2:
    snmp_trapv2_header(tdg, &buf);
    break;
  default:
    SMARTSNMP_LOG(L_INFO, "Sorry, only support Trap v2!\n");
    free(tdg->send_buf);
    return;
  }

  /* varbind list */
  *buf++ = ASN1_TAG_SEQ;
  buf += ber_length_enc(tdg->vb_list_len, buf);

  list_for_each(curr, &tdg->vb_list) {
    vb = list_entry(curr, struct var_bind, link);

    *buf++ = ASN1_TAG_SEQ;
    buf += ber_length_enc(vb->vb_len, buf);

    /* oid */
    *buf++ = ASN1_TAG_OBJID;
    oid_len = ber_value_enc_try(vb->oid, vb->oid_len, ASN1_TAG_OBJID);
    buf += ber_length_enc(oid_len, buf);
    buf += ber_value_enc(vb->oid, vb->oid_len, ASN1_TAG_OBJID, buf);

    /* value */
    *buf++ = vb->value_type;
    buf += ber_length_enc(vb->value_len, buf);
    memcpy(buf, vb->value, vb->value_len);
    buf += vb->value_len;
  }
}

/* Add varbind(s) into trap datagram */
static int
_snmp_trap_varbind(const oid_t *oid, uint32_t oid_len, Variable *var)
{
  struct var_bind *vb;
  struct trap_datagram *tdg = &snmp_trap_datagram;
  uint32_t id_len, len_len, val_len;
  const uint32_t tag_len = 1;

  val_len = ber_value_enc_try(value(var), length(var), tag(var));
  vb = vb_new(oid_len, val_len);
  if (vb != NULL) {
    /* new varbind */
    oid_cpy(vb->oid, oid, oid_len);
    vb->oid_len = oid_len;
    vb->value_type = tag(var);
    vb->value_len = ber_value_enc(value(var), length(var), tag(var), vb->value);

    /* oid length encoding */
    id_len = ber_value_enc_try(vb->oid, vb->oid_len, ASN1_TAG_OBJID);
    len_len = ber_length_enc_try(id_len);
    vb->vb_len = tag_len + len_len + id_len;

    /* value length encoding */
    len_len = ber_length_enc_try(vb->value_len);
    vb->vb_len += tag_len + len_len + vb->value_len;

    /* varbind length encoding */
    len_len = ber_length_enc_try(vb->vb_len);
    tdg->vb_list_len += tag_len + len_len + vb->vb_len;

    /* add into list */
    list_add_tail(&vb->link, &tdg->vb_list);
    tdg->vb_cnt++;

    return 0;
  }

  return -1;
}

/* Trap varbind */
int
snmp_trap_varbind(lua_State *L)
{
  oid_t *oid;
  int i, oid_len;
  Variable var;

  /* varbind oid */
  luaL_checktype(L, 1, LUA_TTABLE);
  oid_len = lua_objlen(L, 1);
  oid = xmalloc(oid_len * sizeof(oid_t));
  for (i = 0; i < oid_len; i++) {
    lua_rawgeti(L, 1, i + 1);
    oid[i] = lua_tointeger(L, -1);
    lua_pop(L, 1);
  }

  /* object tag and value */
  memset(&var, 0, sizeof(var));
  tag(&var) = luaL_checkint(L, 2);

  switch (tag(&var)) {
  case ASN1_TAG_INT:
    length(&var) = 1;
    integer(&var) = lua_tointeger(L, 3);
    break;
  case ASN1_TAG_OCTSTR:
    length(&var) = lua_objlen(L, 3);
    memcpy(octstr(&var), lua_tostring(L, 3), length(&var));
    break;
  case ASN1_TAG_CNT:
    length(&var) = 1;
    count(&var) = lua_tonumber(L, 3);
    break;
  case ASN1_TAG_IPADDR:
    length(&var) = lua_objlen(L, 3);
    for (i = 0; i < length(&var); i++) {
      lua_rawgeti(L, 3, i + 1);
      ipaddr(&var)[i] = lua_tointeger(L, -1);
      lua_pop(L, 1);
    }
    break;
  case ASN1_TAG_OBJID:
    length(&var) = lua_objlen(L, 3);
    for (i = 0; i < length(&var); i++) {
      lua_rawgeti(L, 3, i + 1);
      oid(&var)[i] = lua_tointeger(L, -1);
      lua_pop(L, 1);
    }
    break;
  case ASN1_TAG_GAU:
    length(&var) = 1;
    gauge(&var) = lua_tonumber(L, 3);
    break;
  case ASN1_TAG_TIMETICKS:
    length(&var) = 1;
    timeticks(&var) = lua_tonumber(L, 3);
    break;
  //default:
    // assert(0);
  }

  _snmp_trap_varbind(oid, oid_len, &var);
  free(oid);

  return 0;
}

static int
snmp_trap_getbuffer(lua_State *L)
{
  struct trap_datagram *tdg = &snmp_trap_datagram;
  struct trap_hdr *trap_hdr = &tdg->trap_hdr;
  struct trapv2_hdr *pdu_hdr = &tdg->trap_hdr.trap.v2;
  uint8_t version = TRAP_V2;
  size_t comm_len;

  const char *community = luaL_checklstring(L, 1, &comm_len);

  tdg->version = version;
  tdg->ver_len = 1;
  tdg->community = community;
  tdg->comm_len = comm_len;

  pdu_hdr->req_id = random();
  pdu_hdr->req_id_len = ber_value_enc_try(&pdu_hdr->req_id, 1, ASN1_TAG_INT);
  pdu_hdr->err_stat = 0;
  pdu_hdr->err_stat_len = ber_value_enc_try(&pdu_hdr->err_stat_len, 1, ASN1_TAG_INT);
  pdu_hdr->err_idx = 0;
  pdu_hdr->err_idx_len = ber_value_enc_try(&pdu_hdr->err_idx_len, 1, ASN1_TAG_INT);
  switch (version) {
  case TRAP_V1:
    trap_hdr->pdu_type = SNMP_TRAP_V1;
    break;
  case TRAP_V2:
    trap_hdr->pdu_type = SNMP_TRAP_V2;
    break;
  default:
    break;
  }

  /* Encode SNMP trap datagram */
  snmp_trap_encode(tdg);

  lua_pushlstring(L,tdg->send_buf, tdg->send_len);

  /* clear trap datagram */
  trap_datagram_clear(tdg);

  return 1;
}

static const luaL_Reg R[] =
{
	{ "trap_varbind",snmp_trap_varbind },
	{ "trap_getbuffer",snmp_trap_getbuffer },
	{ NULL, NULL }
};

int luaopen_snmpcodec(lua_State *L)
{
  struct trap_datagram *tdg = &snmp_trap_datagram;
  INIT_LIST_HEAD(&tdg->vb_list);

#if LUA_VERSION_NUM < 502
	luaL_register(L,"snmpcodec", R);
#else
	lua_newtable(L);
	luaL_setfuncs(L, R, 0);
#endif

	return 1;
}

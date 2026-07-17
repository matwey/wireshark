/* packet-telnet.c
 * Routines for Telnet packet dissection; see RFC 854 and RFC 855
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/* Telnet authentication options as per     RFC2941
 * Kerberos v5 telnet authentication as per RFC2942
 * VMware Serial Port Proxy documented at https://developer.vmware.com/docs/11763/using-a-proxy-with-virtual-serial-ports
 */
#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/asn1.h>
#include <epan/tfs.h>
#include <epan/conversation.h>
#include <wsutil/array.h>
#include <wsutil/str_util.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/wsgcrypt.h>
#include "packet-kerberos.h"
#include "packet-tls-utils.h"
#include "packet-tn3270.h"
#include "packet-tn5250.h"
#include "packet-acdr.h"

void proto_reg_handoff_telnet(void);
void proto_register_telnet(void);

static int proto_telnet;
static int hf_telnet_cmd;
static int hf_telnet_subcmd;
static int hf_telnet_auth_cmd;
static int hf_telnet_auth_name;
static int hf_telnet_auth_type;
static int hf_telnet_auth_mod_who;
static int hf_telnet_auth_mod_how;
static int hf_telnet_auth_mod_cred_fwd;
static int hf_telnet_auth_mod_enc;
static int hf_telnet_auth_krb5_type;
static int hf_telnet_auth_ssl_status;
static int hf_telnet_auth_data;

static int hf_telnet_string_subopt_value;
static int hf_telnet_naws_subopt_width;
static int hf_telnet_naws_subopt_height;
static int hf_telnet_outmark_subopt_cmd;
static int hf_telnet_outmark_subopt_banner;
static int hf_telnet_comport_subopt_signature;
static int hf_telnet_comport_subopt_baud_rate;
static int hf_telnet_comport_subopt_data_size;
static int hf_telnet_comport_subopt_parity;
static int hf_telnet_comport_subopt_stop;
static int hf_telnet_comport_subopt_control;
static int hf_telnet_comport_linestate;
static int hf_telnet_comport_set_linestate_mask;
static int hf_telnet_comport_modemstate;
static int hf_telnet_comport_set_modemstate_mask;
static int hf_telnet_comport_subopt_flow_control_suspend;
static int hf_telnet_comport_subopt_flow_control_resume;
static int hf_telnet_comport_subopt_purge;
static int hf_telnet_rfc_subopt_cmd;
static int hf_telnet_tabstop;

static int hf_telnet_enc_cmd;
static int hf_telnet_enc_type;
static int hf_telnet_enc_type_data;
static int hf_telnet_enc_key_id;

static int hf_telnet_data;
static int hf_telnet_option_data;
static int hf_telnet_subcommand_data;

static int hf_tn3270_subopt;
static int hf_tn3270_connect;
static int hf_tn3270_is;
static int hf_tn3270_request_string;
static int hf_tn3270_reason;
static int hf_tn3270_request;
static int hf_tn3270_regime_subopt_value;
static int hf_tn3270_regime_cmd;

static int hf_telnet_starttls;

static int hf_telnet_vmware_cmd;
static int hf_telnet_vmware_known_suboption_code;
static int hf_telnet_vmware_unknown_subopt_code;
static int hf_telnet_vmware_vmotion_sequence;
static int hf_telnet_vmware_vmotion_secret;
static int hf_telnet_vmware_proxy_direction;
static int hf_telnet_vmware_proxy_serviceUri;
static int hf_telnet_vmware_vm_vc_uuid;
static int hf_telnet_vmware_vm_bios_uuid;
static int hf_telnet_vmware_vm_location_uuid;
static int hf_telnet_vmware_vm_name;

static int hf_telnet_ilo2_cmd;
static int hf_telnet_ilo2_key_index;
static int hf_telnet_ilo2_encrypted_data;
static int hf_telnet_ilo2_decrypted_data;
static int hf_telnet_ilo2_mouse_dx;
static int hf_telnet_ilo2_mouse_dy;
static int hf_telnet_ilo2_mouse_client_x;
static int hf_telnet_ilo2_mouse_client_y;
static int hf_telnet_ilo2_button_mask;
static int hf_telnet_ilo2_click_count;
static int hf_telnet_ilo2_raw_byte;
static int hf_telnet_ilo2_mouse_mode;
static int hf_telnet_ilo2_decrypted_text;
static int hf_telnet_ilo2_dvc_video;

static int ett_telnet;
static int ett_telnet_cmd;
static int ett_ilo2_decrypted;
static int ett_telnet_subopt;
static int ett_status_subopt;
static int ett_rcte_subopt;
static int ett_olw_subopt;
static int ett_ops_subopt;
static int ett_crdisp_subopt;
static int ett_htstops_subopt;
static int ett_htdisp_subopt;
static int ett_ffdisp_subopt;
static int ett_vtstops_subopt;
static int ett_vtdisp_subopt;
static int ett_lfdisp_subopt;
static int ett_extasc_subopt;
static int ett_bytemacro_subopt;
static int ett_det_subopt;
static int ett_supdupout_subopt;
static int ett_sendloc_subopt;
static int ett_termtype_subopt;
static int ett_tacacsui_subopt;
static int ett_outmark_subopt;
static int ett_tlocnum_subopt;
static int ett_tn3270reg_subopt;
static int ett_x3pad_subopt;
static int ett_naws_subopt;
static int ett_tspeed_subopt;
static int ett_rfc_subopt;
static int ett_linemode_subopt;
static int ett_xdpyloc_subopt;
static int ett_env_subopt;
static int ett_auth_subopt;
static int ett_enc_subopt;
static int ett_newenv_subopt;
static int ett_tn3270e_subopt;
static int ett_xauth_subopt;
static int ett_charset_subopt;
static int ett_rsp_subopt;
static int ett_comport_subopt;
static int ett_starttls_subopt;
static int ett_ilo2;
static int ett_ilo2_cmd;

static expert_field ei_telnet_suboption_length;
static expert_field ei_telnet_invalid_subcommand;
static expert_field ei_telnet_invalid_linestate;
static expert_field ei_telnet_invalid_stop;
static expert_field ei_telnet_enc_cmd_unknown;
static expert_field ei_telnet_invalid_data_size;
static expert_field ei_telnet_invalid_modemstate;
static expert_field ei_telnet_invalid_parity;
static expert_field ei_telnet_invalid_purge;
static expert_field ei_telnet_invalid_baud_rate;
static expert_field ei_telnet_invalid_control;
static expert_field ei_telnet_vmware_unexp_data;

static dissector_handle_t telnet_handle;

static dissector_handle_t tn3270_handle;
static dissector_handle_t tn5250_handle;
static dissector_handle_t tls_handle;

/* Some defines for Telnet */

#define TCP_PORT_TELNET 23

#define TN_IAC   255
#define TN_DONT  254
#define TN_DO    253
#define TN_WONT  252
#define TN_WILL  251
#define TN_SB    250
#define TN_GA    249
#define TN_EL    248
#define TN_EC    247
#define TN_AYT   246
#define TN_AO    245
#define TN_IP    244
#define TN_BRK   243
#define TN_DM    242
#define TN_NOP   241
#define TN_SE    240
#define TN_EOR   239
#define TN_ABORT 238
#define TN_SUSP  237
#define TN_EOF   236
#define TN_ARE     1

/* HP iLO2 proprietary commands */
#define ILO2_CMD_ENCRYPT        0xC0
#define ILO2_CMD_CHG_KEYS       0xC1
#define ILO2_CMD_TS_AVAIL       0xC2
#define ILO2_CMD_TS_NOT_AVAIL   0xC3
#define ILO2_CMD_TS_STARTED     0xC4
#define ILO2_CMD_TS_STOPPED     0xC5
#define ILO2_CMD_MOUSE_MOVE     0xD0
#define ILO2_CMD_BTN_PRESS      0xD1
#define ILO2_CMD_BTN_RELEASE    0xD2
#define ILO2_CMD_BTN_CLICK      0xD3
#define ILO2_CMD_RAW_BYTE       0xD4
#define ILO2_CMD_SET_MOUSE_MODE 0xD5

static const value_string ilo2_cmd_vals[] = {
  { ILO2_CMD_ENCRYPT,        "HP iLO2 Encrypt" },
  { ILO2_CMD_CHG_KEYS,       "HP iLO2 Change Keys" },
  { ILO2_CMD_TS_AVAIL,       "HP iLO2 Terminal Services Available" },
  { ILO2_CMD_TS_NOT_AVAIL,   "HP iLO2 Terminal Services Not Available" },
  { ILO2_CMD_TS_STARTED,     "HP iLO2 Terminal Services Started" },
  { ILO2_CMD_TS_STOPPED,     "HP iLO2 Terminal Services Stopped" },
  { ILO2_CMD_MOUSE_MOVE,     "HP iLO2 Mouse Move" },
  { ILO2_CMD_BTN_PRESS,      "HP iLO2 Button Press" },
  { ILO2_CMD_BTN_RELEASE,    "HP iLO2 Button Release" },
  { ILO2_CMD_BTN_CLICK,      "HP iLO2 Button Click" },
  { ILO2_CMD_RAW_BYTE,       "HP iLO2 Raw Byte" },
  { ILO2_CMD_SET_MOUSE_MODE, "HP iLO2 Set Mouse Mode" },
  { 0, NULL }
};

static const value_string ilo2_mouse_mode_vals[] = {
  { 1, "Absolute" },
  { 2, "Relative" },
  { 0, NULL }
};

static const value_string cmd_vals[] = {
  { TN_EOF,    "End of File" },
  { TN_SUSP,   "Suspend Current Process" },
  { TN_ABORT,  "Abort Process" },
  { TN_EOR,    "End of Record" },
  { TN_SE,     "Suboption End" },
  { TN_NOP,    "No Operation" },
  { TN_DM,     "Data Mark" },
  { TN_BRK,    "Break" },
  { TN_IP,     "Interrupt Process" },
  { TN_AO,     "Abort Output" },
  { TN_AYT,    "Are You There?" },
  { TN_EC,     "Escape Character" },
  { TN_EL,     "Erase Line" },
  { TN_GA,     "Go Ahead" },
  { TN_DONT,   "Don't" },
  { TN_DO,     "Do" },
  { TN_WONT,   "Won't" },
  { TN_WILL,   "Will" },
  { TN_SB,     "Suboption" },
  { 0, NULL }
};

typedef enum {
  NO_LENGTH,            /* option has no data, hence no length */
  FIXED_LENGTH,         /* option always has the same length */
  VARIABLE_LENGTH       /* option is variable-length - optlen is minimum */
} tn_opt_len_type;

/* Member of table of IP or TCP options. */
typedef struct tn_opt {
  const char      *name;          /* name of option */
  int             *subtree_index; /* pointer to subtree index for option */
  tn_opt_len_type  len_type;      /* type of option length field */
  unsigned         optlen;        /* value length should be (minimum if VARIABLE) */
  void  (*dissect)(packet_info *pinfo, const char *, tvbuff_t *, unsigned, unsigned, proto_tree *, proto_item*);
                                  /* routine to dissect option */
} tn_opt;

typedef struct _telnet_conv_info {
  uint32_t  starttls_requested_in;  /* Frame of first sender of START_TLS FOLLOWS */
  uint32_t  starttls_port;          /* Source port for first sender */
  ssize_t   vmotion_sequence_len;   /* Length of "sequence" field for VMware vSPC vMotion. */
} telnet_conv_info_t;

/* HP iLO2 RC4 state */
typedef struct _ilo2_rc4 {
  uint8_t   s_box[256];
  uint8_t   key_box[256];
  uint8_t   key[16];
  uint8_t   seed[16];
  int       i;
  int       j;
  bool      initialized;
} ilo2_rc4_t;

/* HP iLO2 conversation info */
typedef struct _ilo2_conv_info {
  ilo2_rc4_t  server_rc4;   /* decryption: server -> client (uses INFOB) */
  ilo2_rc4_t  client_rc4;   /* decryption: client -> server (uses INFOC) */
  address     client_addr;  /* IP address of the iLO2 client */
  bool        client_addr_set;
  bool        encrypt_enabled;
  bool        dvc_mode;
  bool        dvc_encryption;
  bool        server_encryption_active;  /* server->client data is now encrypted */
  bool        client_encryption_active;  /* client->server data is now encrypted */
  bool        dvc_active;                /* DVC video mode has been entered */
} ilo2_conv_info_t;

/* HP iLO2 session keys - from user-provided session parameters */
static const uint8_t ilo2_decrypt_key[16] = {  /* INFOB: server->client decryption */
  0x1C, 0x46, 0x54, 0xA7, 0x54, 0x2E, 0x6B, 0x8A,
  0x87, 0x2C, 0xBF, 0x33, 0x04, 0x74, 0xD9, 0x9E
};
static const uint8_t ilo2_encrypt_key[16] = {  /* INFOC: client->server encryption */
  0xBC, 0xF9, 0x5B, 0x76, 0x60, 0x1D, 0xD0, 0x2A,
  0xF4, 0x2D, 0x7F, 0xB9, 0x9E, 0x0E, 0x60, 0xA0
};

static void
ilo2_rc4_init(ilo2_rc4_t *rc4, const uint8_t *seed)
{
  int k;
  gcry_md_hd_t md;
  uint8_t digest[16];

  memcpy(rc4->seed, seed, 16);
  memset(rc4->key, 0, 16);

  /* Compute initial key: MD5(seed || zeros) */
  gcry_md_open(&md, GCRY_MD_MD5, 0);
  gcry_md_write(md, rc4->seed, 16);
  gcry_md_write(md, rc4->key, 16);
  memcpy(digest, gcry_md_read(md, GCRY_MD_MD5), 16);
  gcry_md_close(md);
  memcpy(rc4->key, digest, 16);

  /* Initialize S-box */
  for (k = 0; k < 256; k++) {
    rc4->s_box[k] = (uint8_t)k;
    rc4->key_box[k] = rc4->key[k % 16];
  }

  /* KSA */
  rc4->j = 0;
  for (rc4->i = 0; rc4->i < 256; rc4->i++) {
    rc4->j = ((rc4->j & 0xFF) + (rc4->s_box[rc4->i] & 0xFF) + (rc4->key_box[rc4->i] & 0xFF)) & 0xFF;
    uint8_t tmp = rc4->s_box[rc4->i];
    rc4->s_box[rc4->i] = rc4->s_box[rc4->j];
    rc4->s_box[rc4->j] = tmp;
  }

  rc4->i = 0;
  rc4->j = 0;
  rc4->initialized = true;
}

static void
ilo2_rc4_update_key(ilo2_rc4_t *rc4)
{
  int k;
  gcry_md_hd_t md;
  uint8_t digest[16];

  gcry_md_open(&md, GCRY_MD_MD5, 0);
  gcry_md_write(md, rc4->seed, 16);
  gcry_md_write(md, rc4->key, 16);
  memcpy(digest, gcry_md_read(md, GCRY_MD_MD5), 16);
  gcry_md_close(md);
  memcpy(rc4->key, digest, 16);

  for (k = 0; k < 256; k++) {
    rc4->s_box[k] = (uint8_t)k;
    rc4->key_box[k] = rc4->key[k % 16];
  }

  rc4->j = 0;
  for (rc4->i = 0; rc4->i < 256; rc4->i++) {
    rc4->j = ((rc4->j & 0xFF) + (rc4->s_box[rc4->i] & 0xFF) + (rc4->key_box[rc4->i] & 0xFF)) & 0xFF;
    uint8_t tmp = rc4->s_box[rc4->i];
    rc4->s_box[rc4->i] = rc4->s_box[rc4->j];
    rc4->s_box[rc4->j] = tmp;
  }

  rc4->i = 0;
  rc4->j = 0;
}

static uint8_t
ilo2_rc4_random(ilo2_rc4_t *rc4)
{
  rc4->i = ((rc4->i & 0xFF) + 1) & 0xFF;
  rc4->j = ((rc4->j & 0xFF) + (rc4->s_box[rc4->i] & 0xFF)) & 0xFF;
  uint8_t k = rc4->s_box[rc4->i];
  rc4->s_box[rc4->i] = rc4->s_box[rc4->j];
  rc4->s_box[rc4->j] = k;
  uint8_t m = (uint8_t)((rc4->s_box[rc4->i] & 0xFF) + (rc4->s_box[rc4->j] & 0xFF)) & 0xFF;
  return rc4->s_box[m];
}

static void
ilo2_rc4_decrypt(ilo2_rc4_t *rc4, uint8_t *data, int len)
{
  int i;
  for (i = 0; i < len; i++) {
    data[i] ^= ilo2_rc4_random(rc4);
  }
}

static ilo2_conv_info_t *
ilo2_get_session(packet_info *pinfo)
{
  conversation_t     *conversation = find_or_create_conversation(pinfo);
  ilo2_conv_info_t   *ilo2_info;

  ilo2_info = (ilo2_conv_info_t *)conversation_get_proto_data(conversation, proto_telnet);
  if (!ilo2_info) {
    ilo2_info = wmem_new0(wmem_file_scope(), ilo2_conv_info_t);
    ilo2_info->encrypt_enabled = false;
    ilo2_info->dvc_mode = false;
    ilo2_info->dvc_encryption = false;
    ilo2_info->server_encryption_active = false;
    ilo2_info->client_encryption_active = false;

    /* Initialize RC4 with user-provided session keys */
    ilo2_rc4_init(&ilo2_info->server_rc4, ilo2_decrypt_key);
    ilo2_rc4_init(&ilo2_info->client_rc4, ilo2_encrypt_key);

    conversation_add_proto_data(conversation, proto_telnet, ilo2_info);
  }
  return ilo2_info;
}

static bool
ilo2_is_from_client(packet_info *pinfo, ilo2_conv_info_t *ilo2)
{
  if (!ilo2->client_addr_set) {
    /* First ENCRYPT command with data sets the client address */
    return true;
  }
  return addresses_equal(&pinfo->src, &ilo2->client_addr);
}

static void
check_tn3270_model(packet_info *pinfo _U_, const char *terminaltype)
{
  int  model;

  if ((strcmp(terminaltype,"IBM-3278-2-E") == 0) || (strcmp(terminaltype,"IBM-3278-2") == 0) ||
      (strcmp(terminaltype,"IBM-3278-3") == 0) || (strcmp(terminaltype,"IBM-3278-4") == 0) ||
      (strcmp(terminaltype,"IBM-3278-5") == 0) || (strcmp(terminaltype,"IBM-3277-2") == 0) ||
      (strcmp(terminaltype,"IBM-3279-3") == 0) || (strcmp(terminaltype,"IBM-3279-4") == 0) ||
      (strcmp(terminaltype,"IBM-3279-2-E") == 0) || (strcmp(terminaltype,"IBM-3279-2") == 0) ||
      (strcmp(terminaltype,"IBM-3279-4-E") == 0)) {
    model = terminaltype[9] - '0';
    add_tn3270_conversation(pinfo, 0, model);
  }
}

static void
check_for_tn3270(packet_info *pinfo _U_, const char *optname, const char *terminaltype)
{
  if (strcmp(optname,"Terminal Type") != 0) {
    return;
  }
  check_tn3270_model(pinfo, terminaltype);

  if ((strcmp(terminaltype,"IBM-5555-C01") == 0) || /* 24 x 80 Double-Byte Character Set color display */
      (strcmp(terminaltype,"IBM-5555-B01") == 0) || /* 24 x 80 Double-Byte Character Set (DBCS)*/
      (strcmp(terminaltype,"IBM-3477-FC") == 0) ||  /* 27 x 132 color display*/
      (strcmp(terminaltype,"IBM-3477-FG") == 0) ||  /* 27 x 132 monochrome display*/
      (strcmp(terminaltype,"IBM-3180-2") == 0) ||   /* 27 x 132 monochrome display*/
      (strcmp(terminaltype,"IBM-3179-2") == 0) ||   /* 24 x 80 color display*/
      (strcmp(terminaltype,"IBM-3196-A1") == 0) ||  /* 24 x 80 monochrome display*/
      (strcmp(terminaltype,"IBM-5292-2") == 0) ||   /* 24 x 80 color display*/
      (strcmp(terminaltype,"IBM-5291-1") == 0) ||   /* 24 x 80 monochrome display*/
      (strcmp(terminaltype,"IBM-5251-11") == 0))    /* 24 x 80 monochrome display*/
    add_tn5250_conversation(pinfo, 0);
}

static telnet_conv_info_t *
telnet_get_session(packet_info *pinfo)
{
  conversation_t        *conversation = find_or_create_conversation(pinfo);
  telnet_conv_info_t    *telnet_info;

  telnet_info = (telnet_conv_info_t*)conversation_get_proto_data(conversation, proto_telnet);
  if (!telnet_info) {
    telnet_info = wmem_new0(wmem_file_scope(), telnet_conv_info_t);
    telnet_info->vmotion_sequence_len = -1;
    conversation_add_proto_data(conversation, proto_telnet, telnet_info);
  }
  return telnet_info;
}

/* Record some data/negotiation/subnegotiation in the "Info" column. */
static void
add_telnet_info_str(packet_info *pinfo, unsigned *num_items, const char *str)
{
  const unsigned max_info_items = 5; /* Arbitrary limit so the column doesn't end up too wide. */

  if (*num_items == 0) {
    /* Replace the default info text. */
    col_add_str(pinfo->cinfo, COL_INFO, str);
  } else if (*num_items < max_info_items) {
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, str);
  } else if (*num_items == max_info_items) {
    /* Too many to display.  Finish with an ellipsis. */
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, UTF8_HORIZONTAL_ELLIPSIS);
  }
  (*num_items)++;
}

/* Record in the "Info" column that a number of Telnet data bytes arrived. */
static void
add_telnet_data_bytes_str(packet_info *pinfo, unsigned *num_items, unsigned len)
{
  char str[30];

  snprintf(str, sizeof str, "%u byte%s data", len, plurality(len, "", "s"));
  add_telnet_info_str(pinfo, num_items, str);
}

static void
dissect_string_subopt(packet_info *pinfo, const char *optname, tvbuff_t *tvb, unsigned offset, unsigned len,
                      proto_tree *tree, proto_item *item)
{
  uint8_t cmd;

  cmd = tvb_get_uint8(tvb, offset);
  switch (cmd) {

  case 0:       /* IS */
    proto_tree_add_uint_format(tree, hf_telnet_subcmd, tvb, offset, 1, cmd, "Here's my %s", optname);
    offset++;
    len--;
    if (len > 0) {
      proto_tree_add_item(tree, hf_telnet_string_subopt_value, tvb, offset, len, ENC_ASCII);
    }
    check_for_tn3270(pinfo, optname, tvb_format_text(pinfo->pool, tvb, offset, len));
    break;

  case 1:       /* SEND */
    proto_tree_add_uint_format(tree, hf_telnet_subcmd, tvb, offset, 1, cmd, "Send your %s", optname);
    offset++;
    len--;
    if (len > 0)
      proto_tree_add_bytes_format(tree, hf_telnet_subcommand_data, tvb, offset, len, NULL, "Extra data");
    break;

  default:
    expert_add_info_format(pinfo, item, &ei_telnet_invalid_subcommand, "Invalid %s subcommand %u", optname, cmd);

    offset++;
    len--;
    if (len > 0)
      proto_tree_add_item(tree, hf_telnet_subcommand_data, tvb, offset, len, ENC_NA);
    break;
  }
}

static void
dissect_tn3270_regime_subopt(packet_info *pinfo, const char *optname _U_, tvbuff_t *tvb, unsigned offset,
                       unsigned len, proto_tree *tree, proto_item *item _U_)
{
#define TN3270_REGIME_ARE          0x01
#define TN3270_REGIME_IS           0x00

  uint8_t cmd;

  while (len > 0) {
    cmd = tvb_get_uint8(tvb, offset);
    switch (cmd) {
    case TN3270_REGIME_ARE:
    case TN3270_REGIME_IS:
      if (cmd == TN3270_REGIME_ARE) {
        proto_tree_add_uint_format(tree, hf_tn3270_regime_cmd, tvb, offset, 1, cmd, "ARE");
        add_tn3270_conversation(pinfo, 0, 0);
      } else {
        proto_tree_add_uint_format(tree, hf_tn3270_regime_cmd, tvb, offset, 1, cmd, "IS");
      }
      proto_tree_add_item(tree, hf_tn3270_regime_subopt_value, tvb, offset + 1, len - 1, ENC_ASCII);
      return;
    default:
      proto_tree_add_uint_format(tree, hf_tn3270_regime_cmd, tvb, offset, 1, cmd, "Bogus value: %u", cmd);
      break;
    }
    offset++;
    len --;
  }

}

#define TN3270_ASSOCIATE          0x00
#define TN3270_CONNECT            0x01
#define TN3270_DEVICE_TYPE        0x02
#define TN3270_FUNCTIONS          0x03
#define TN3270_IS                 0x04
#define TN3270_REASON             0x05
#define TN3270_REJECT             0x06
#define TN3270_REQUEST            0x07
#define TN3270_SEND               0x08
/*       Reason_codes*/
#define TN3270_CONN_PARTNER       0x00
#define TN3270_DEVICE_IN_USE      0x01
#define TN3270_INV_ASSOCIATE      0x02
#define TN3270_INV_DEVICE_NAME    0x03
#define TN3270_INV_DEVICE_TYPE    0x04
#define TN3270_TYPE_NAME_ERROR    0x05
#define TN3270_UNKNOWN_ERROR      0x06
#define TN3270_UNSUPPORTED_REQ    0x07
/*       Function Names*/
#define TN3270_BIND_IMAGE         0x00
#define TN3270_DATA_STREAM_CTL    0x01
#define TN3270_RESPONSES          0x02
#define TN3270_SCS_CTL_CODES      0x03
#define TN3270_SYSREQ             0x04

static const value_string tn3270_subopt_vals[] = {
  { TN3270_ASSOCIATE,   "ASSOCIATE" },
  { TN3270_CONNECT,     "CONNECT" },
  { TN3270_DEVICE_TYPE, "DEVICE-TYPE" },
  { TN3270_FUNCTIONS,   "FUNCTIONS" },
  { TN3270_IS,          "IS" },
  { TN3270_REASON,      "REASON" },
  { TN3270_REJECT,      "REJECT" },
  { TN3270_REQUEST,     "REQUEST" },
  { TN3270_SEND,        "SEND" },
  { 0, NULL }
};

static const value_string tn3270_reason_vals[] = {
  { TN3270_CONN_PARTNER,    "CONN-PARTNER" },
  { TN3270_DEVICE_IN_USE,   "DEVICE-IN-USE" },
  { TN3270_INV_ASSOCIATE,   "INV-ASSOCIATE" },
  { TN3270_INV_DEVICE_NAME, "INV-DEVICE-NAME" },
  { TN3270_INV_DEVICE_TYPE, "INV-DEVICE-TYPE" },
  { TN3270_TYPE_NAME_ERROR, "TYPE-NAME-ERROR" },
  { TN3270_UNKNOWN_ERROR,   "UNKNOWN-ERROR" },
  { TN3270_UNSUPPORTED_REQ, "UNSUPPORTED-REQ" },
  { 0, NULL }
};

static const value_string tn3270_request_vals[] = {
  { TN3270_BIND_IMAGE,      "BIND-IMAGE" },
  { TN3270_DATA_STREAM_CTL, "DATA-STREAM-CTL" },
  { TN3270_RESPONSES,       "RESPONSES" },
  { TN3270_SCS_CTL_CODES,   "SCS-CTL-CODES" },
  { TN3270_SYSREQ,          "SYSREQ" },
  { 0, NULL }
};

static void
dissect_tn3270e_subopt(packet_info *pinfo _U_, const char *optname _U_, tvbuff_t *tvb, unsigned offset,
  unsigned len, proto_tree *tree, proto_item *item _U_)
{

  uint8_t cmd;
  unsigned    datalen;
  unsigned    connect_offset = 0;
  unsigned    device_type    = 0;
  unsigned    rsn            = 0;

  while (len > 0) {
    cmd = tvb_get_uint8(tvb, offset);
    proto_tree_add_item( tree, hf_tn3270_subopt, tvb, offset, 1, ENC_BIG_ENDIAN );
    switch (cmd) {
      case TN3270_CONNECT:
            proto_tree_add_item( tree, hf_tn3270_connect, tvb, offset + 1, len, ENC_ASCII );
            offset += (len - 1);
            len -= (len - 1);
            break;
      case TN3270_IS:
            device_type = tvb_get_uint8(tvb, offset-1);
            if (device_type == TN3270_DEVICE_TYPE) {
                /* If there is a terminal type to display, then it will be followed by CONNECT */
                if (tvb_find_uint8_length(tvb, offset + 1, len, TN3270_CONNECT, &connect_offset)) {
                  datalen = connect_offset - (offset + 1);
                  if (datalen > 0) {
                    proto_tree_add_item( tree, hf_tn3270_is, tvb, offset + 1, datalen, ENC_ASCII );
                    check_tn3270_model(pinfo, tvb_format_text(pinfo->pool, tvb, offset + 1, datalen));
                    offset += datalen;
                    len -= datalen;
                  }
                }
            }
            break;
      case TN3270_REASON:
            offset++;
            len--;
            proto_tree_add_item( tree, hf_tn3270_reason, tvb, offset, 1, ENC_BIG_ENDIAN );
            break;
      case TN3270_REQUEST:
            add_tn3270_conversation(pinfo, 1, 0);
            device_type = tvb_get_uint8(tvb, offset-1);
            if (device_type == TN3270_DEVICE_TYPE) {
              proto_tree_add_item( tree, hf_tn3270_request_string, tvb, offset + 1, len-1, ENC_ASCII );
              offset += (len - 1);
              len -= (len - 1);
            }else if (device_type == TN3270_FUNCTIONS) {
              while (len > 0) {
                rsn = tvb_get_uint8(tvb, offset);
                proto_tree_add_item( tree, hf_tn3270_request, tvb, offset, 1, ENC_BIG_ENDIAN );
                if (try_val_to_str(rsn, tn3270_request_vals) == NULL)
                    break;

                offset++;
                len--;
              }
            }
            break;
    }
    offset++;
    len--;
  }

}

static void
dissect_starttls_subopt(packet_info *pinfo _U_, const char *optname _U_, tvbuff_t *tvb, unsigned offset,
  unsigned len _U_, proto_tree *tree, proto_item *item _U_)
{
  telnet_conv_info_t *session = telnet_get_session(pinfo);

  proto_tree_add_item(tree, hf_telnet_starttls, tvb, offset, 1, ENC_BIG_ENDIAN);

  if (session->starttls_requested_in == 0) {
    /* First sender (client or server) requesting to start TLS. */
    session->starttls_requested_in = pinfo->num;
    session->starttls_port = pinfo->srcport;
  } else if (session->starttls_requested_in < pinfo->num &&
      session->starttls_port != pinfo->srcport) {
    /* Other side confirms that following data is TLS. */
    ssl_starttls_ack(tls_handle, pinfo, telnet_handle);
  }
}

static const value_string telnet_outmark_subopt_cmd_vals[] = {
  { '\x06', "ACK" },
  { '\x15', "NAK" },
  { 'D',    "Default" },
  { 'T',    "Top" },
  { 'B',    "Bottom" },
  { 'L',    "Left" },
  { 'R',    "Right" },
  { 0, NULL }
};

static void
dissect_outmark_subopt(packet_info *pinfo _U_, const char *optname _U_, tvbuff_t *tvb, unsigned offset,
  unsigned len, proto_tree *tree, proto_item *item _U_)
{
  unsigned    gs_offset, datalen;

  while (len > 0) {
    proto_tree_add_item(tree, hf_telnet_outmark_subopt_cmd, tvb, offset, 1, ENC_ASCII);

    offset++;
    len--;

    /* Look for a GS */
    if (!tvb_find_uint8_length(tvb, offset, len, 29, &gs_offset)) {
      /* None found - run to the end of the packet. */
      gs_offset = offset + len;
    }
    datalen = gs_offset - offset;
    if (datalen > 0) {
      proto_tree_add_item(tree, hf_telnet_outmark_subopt_banner, tvb, offset, datalen, ENC_ASCII);
      offset += datalen;
      len -= datalen;
    }
  }
}

static void
dissect_htstops_subopt(packet_info *pinfo, const char *optname, tvbuff_t *tvb, unsigned offset, unsigned len,
                       proto_tree *tree, proto_item *item)
{
  uint8_t cmd;
  uint8_t tabval;

  cmd = tvb_get_uint8(tvb, offset);
  switch (cmd) {

  case 0:       /* IS */
    proto_tree_add_uint_format(tree, hf_telnet_subcmd, tvb, offset, 1, cmd, "Here's my %s", optname);
    offset++;
    len--;
    break;

  case 1:       /* SEND */
    proto_tree_add_uint_format(tree, hf_telnet_subcmd, tvb, offset, 1, cmd, "Send your %s", optname);
    offset++;
    len--;
    break;

  default:
    expert_add_info_format(pinfo, item, &ei_telnet_invalid_subcommand, "Invalid %s subcommand %u", optname, cmd);
    offset++;
    len--;
    if (len > 0)
      proto_tree_add_item(tree, hf_telnet_subcommand_data, tvb, offset, len, ENC_NA);
    return;
  }

  while (len > 0) {
    tabval = tvb_get_uint8(tvb, offset);
    switch (tabval) {

    case 0:
      proto_tree_add_uint_format(tree, hf_telnet_tabstop, tvb, offset, 1,
                          tabval, "Sender wants to handle tab stops");
      break;

    default:
      proto_tree_add_uint_format(tree, hf_telnet_tabstop, tvb, offset, 1,
                          tabval, "Sender wants receiver to handle tab stop at %u",
                          tabval);
      break;

    case 251:
    case 252:
    case 253:
    case 254:
      proto_tree_add_uint_format(tree, hf_telnet_tabstop, tvb, offset, 1,
                          tabval, "Invalid value: %u", tabval);
      break;

    case 255:
      proto_tree_add_uint_format(tree, hf_telnet_tabstop, tvb, offset, 1,
                          tabval, "Sender wants receiver to handle tab stops");
      break;
    }
    offset++;
    len--;
  }
}

static void
dissect_naws_subopt(packet_info *pinfo _U_, const char *optname _U_, tvbuff_t *tvb, unsigned offset,
                    unsigned len _U_, proto_tree *tree, proto_item *item _U_)
{
  proto_tree_add_item(tree, hf_telnet_naws_subopt_width, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_telnet_naws_subopt_height, tvb, offset, 2, ENC_BIG_ENDIAN);
}

/* BEGIN RFC-2217 (COM Port Control) Definitions */

#define TNCOMPORT_SIGNATURE             0
#define TNCOMPORT_SETBAUDRATE           1
#define TNCOMPORT_SETDATASIZE           2
#define TNCOMPORT_SETPARITY             3
#define TNCOMPORT_SETSTOPSIZE           4
#define TNCOMPORT_SETCONTROL            5
#define TNCOMPORT_NOTIFYLINESTATE       6
#define TNCOMPORT_NOTIFYMODEMSTATE      7
#define TNCOMPORT_FLOWCONTROLSUSPEND    8
#define TNCOMPORT_FLOWCONTROLRESUME      9
#define TNCOMPORT_SETLINESTATEMASK      10
#define TNCOMPORT_SETMODEMSTATEMASK     11
#define TNCOMPORT_PURGEDATA             12

/* END RFC-2217 (COM Port Control) Definitions */

static void
dissect_comport_subopt(packet_info *pinfo, const char *optname, tvbuff_t *tvb, unsigned offset, unsigned len,
                       proto_tree *tree, proto_item *item)
{
  static const char *datasizes[] = {
    "Request",
    "<invalid>",
    "<invalid>",
    "<invalid>",
    "<invalid>",
    "5",
    "6",
    "7",
    "8"
  };
  static const char *parities[] = {
    "Request",
    "None",
    "Odd",
    "Even",
    "Mark",
    "Space"
  };
  static const char *stops[] = {
    "Request",
    "1",
    "2",
    "1.5"
  };
  static const char *control[] = {
    "Output Flow Control Request",
    "Output Flow: None",
    "Output Flow: XON/XOFF",
    "Output Flow: CTS/RTS",
    "Break Request",
    "Break: ON",
    "Break: OFF",
    "DTR Request",
    "DTR: ON",
    "DTR: OFF",
    "RTS Request",
    "RTS: ON",
    "RTS: OFF",
    "Input Flow Control Request",
    "Input Flow: None",
    "Input Flow: XON/XOFF",
    "Input Flow: CTS/RTS",
    "Output Flow: DCD",
    "Input Flow: DTR",
    "Output Flow: DSR"
  };
  static const char *linestate_bits[] = {
    "Data Ready",
    "Overrun Error",
    "Parity Error",
    "Framing Error",
    "Break Detected",
    "Transfer Holding Register Empty",
    "Transfer Shift Register Empty",
    "Timeout Error"
  };
  static const char *modemstate_bits[] = {
    "DCTS",
    "DDSR",
    "TERI",
    "DDCD",
    "CTS",
    "DSR",
    "RI",
    "DCD"
  };
  static const char *purges[] = {
    "Purge None",
    "Purge RX",
    "Purge TX",
    "Purge RX/TX"
  };

  uint8_t cmd;
  uint8_t isservercmd;
  const char *source;

  cmd = tvb_get_uint8(tvb, offset);
  isservercmd = cmd > 99;
  cmd = (isservercmd) ? (cmd - 100) : cmd;
  source = (isservercmd) ? "Server" : "Client";
  switch (cmd) {
  case TNCOMPORT_SIGNATURE:
    len--;
    if (len == 0) {
      proto_tree_add_string_format(tree, hf_telnet_comport_subopt_signature, tvb, offset, 1, "", "%s Requests Signature", source);
    } else {
      char *sig = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset + 1, len, ENC_ASCII);
      proto_tree_add_string_format(tree, hf_telnet_comport_subopt_signature, tvb, offset, 1 + len, sig,
                                         "%s Signature: %s",source, sig);
    }
    break;

  case TNCOMPORT_SETBAUDRATE:
    len--;
    if (len >= 4) {
      uint32_t baud = tvb_get_ntohl(tvb, offset+1);
      if (baud == 0) {
        proto_tree_add_uint_format_value(tree, hf_telnet_comport_subopt_baud_rate, tvb, offset, 5, 0, "%s Requests Baud Rate",source);
      } else {
        proto_tree_add_uint_format_value(tree, hf_telnet_comport_subopt_baud_rate, tvb, offset, 5, baud, "%s Baud Rate: %d",source,baud);
      }
    } else {
      expert_add_info_format(pinfo, item, &ei_telnet_invalid_baud_rate, "%s <Invalid Baud Rate Packet>", source);
    }
    break;

  case TNCOMPORT_SETDATASIZE:
    len--;
    if (len >= 1) {
      uint8_t datasize = tvb_get_uint8(tvb, offset+1);
      const char *ds = (datasize > 8) ? "<invalid>" : datasizes[datasize];
      proto_tree_add_uint_format_value(tree, hf_telnet_comport_subopt_data_size, tvb, offset, 2, datasize,
                                       "%s Data Size: %s",source,ds);
    } else {
      expert_add_info_format(pinfo, item, &ei_telnet_invalid_data_size, "%s <Invalid Data Size Packet>", source);
    }
    break;

  case TNCOMPORT_SETPARITY:
    len--;
    if (len >= 1) {
      uint8_t parity = tvb_get_uint8(tvb, offset+1);
      const char *pr = (parity > 5) ? "<invalid>" : parities[parity];
      proto_tree_add_uint_format_value(tree, hf_telnet_comport_subopt_parity, tvb, offset, 2, parity,
                                       "%s Parity: %s",source,pr);
    } else {
      expert_add_info_format(pinfo, item, &ei_telnet_invalid_parity, "%s <Invalid Parity Packet>", source);
    }
    break;
  case TNCOMPORT_SETSTOPSIZE:
    len--;
    if (len >= 1) {
      uint8_t stop = tvb_get_uint8(tvb, offset+1);
      const char *st = (stop > 3) ? "<invalid>" : stops[stop];
      proto_tree_add_uint_format_value(tree, hf_telnet_comport_subopt_stop, tvb, offset, 2, stop,
                                       "%s Stop: %s",source,st);
    } else {
      expert_add_info_format(pinfo, item, &ei_telnet_invalid_stop, "%s <Invalid Stop Packet>", source);
    }
    break;

  case TNCOMPORT_SETCONTROL:
    len--;
    if (len >= 1) {
      uint8_t crt = tvb_get_uint8(tvb, offset+1);
      const char *c = (crt > 19) ? "Control: <invalid>" : control[crt];
      proto_tree_add_uint_format_value(tree, hf_telnet_comport_subopt_control, tvb, offset, 2, crt,
                                       "%s Stop: %s",source,c);
    } else {
      expert_add_info_format(pinfo, item, &ei_telnet_invalid_control, "%s <Invalid Control Packet>", source);
    }
    break;

  case TNCOMPORT_SETLINESTATEMASK:
  case TNCOMPORT_NOTIFYLINESTATE:
    len--;
    if (len >= 1) {
      const char *print_pattern = (cmd == TNCOMPORT_SETLINESTATEMASK) ?
        "%s Set Linestate Mask: %s" : "%s Linestate: %s";
      int hf_line = (cmd == TNCOMPORT_SETLINESTATEMASK) ?
        hf_telnet_comport_set_linestate_mask : hf_telnet_comport_linestate;
      char ls_buffer[512];
      uint8_t ls = tvb_get_uint8(tvb, offset+1);
      int print_count = 0;
      int idx;
      ls_buffer[0] = '\0';
      for (idx = 0; idx < 8; idx++) {
        int bit = ls & 1;
        if (bit) {
          if (print_count != 0) {
            (void) g_strlcat(ls_buffer,", ",512);
          }
          (void) g_strlcat(ls_buffer,linestate_bits[idx], 512);
          print_count++;
        }
        ls = ls >> 1;
      }
      proto_tree_add_string_format(tree, hf_line, tvb, offset, 2, ls_buffer, print_pattern, source, ls_buffer);
    } else {
      const char *print_pattern = (cmd == TNCOMPORT_SETLINESTATEMASK) ?
        "%s <Invalid Linestate Mask>" : "%s <Invalid Linestate Packet>";
      expert_add_info_format(pinfo, item, &ei_telnet_invalid_linestate, print_pattern, source);
    }
    break;

  case TNCOMPORT_SETMODEMSTATEMASK:
  case TNCOMPORT_NOTIFYMODEMSTATE:
    len--;
    if (len >= 1) {
      const char *print_pattern = (cmd == TNCOMPORT_SETMODEMSTATEMASK) ?
        "%s Set Modemstate Mask: %s" : "%s Modemstate: %s";
      int hf_modem = (cmd == TNCOMPORT_SETMODEMSTATEMASK) ?
        hf_telnet_comport_set_modemstate_mask : hf_telnet_comport_modemstate;
      char ms_buffer[256];
      uint8_t ms = tvb_get_uint8(tvb, offset+1);
      int print_count = 0;
      int idx;
      ms_buffer[0] = '\0';
      for (idx = 0; idx < 8; idx++) {
        int bit = ms & 1;
        if (bit) {
          if (print_count != 0) {
            (void) g_strlcat(ms_buffer,", ",256);
          }
          (void) g_strlcat(ms_buffer,modemstate_bits[idx],256);
          print_count++;
        }
        ms = ms >> 1;
      }
      proto_tree_add_string_format(tree, hf_modem, tvb, offset, 2, ms_buffer, print_pattern, source, ms_buffer);
    } else {
      const char *print_pattern = (cmd == TNCOMPORT_SETMODEMSTATEMASK) ?
        "%s <Invalid Modemstate Mask>" : "%s <Invalid Modemstate Packet>";
      expert_add_info_format(pinfo, item, &ei_telnet_invalid_modemstate, print_pattern, source);
    }
    break;

  case TNCOMPORT_FLOWCONTROLSUSPEND:
    len--;
    proto_tree_add_none_format(tree, hf_telnet_comport_subopt_flow_control_suspend, tvb, offset, 1, "%s Flow Control Suspend",source);
    break;

  case TNCOMPORT_FLOWCONTROLRESUME:
    len--;
    proto_tree_add_none_format(tree, hf_telnet_comport_subopt_flow_control_resume, tvb, offset, 1, "%s Flow Control Resume",source);
    break;

  case TNCOMPORT_PURGEDATA:
    len--;
    if (len >= 1) {
      uint8_t purge = tvb_get_uint8(tvb, offset+1);
      const char *p = (purge > 3) ? "<Purge invalid>" : purges[purge];
      proto_tree_add_uint_format_value(tree, hf_telnet_comport_subopt_purge, tvb, offset, 2, purge,
                                       "%s %s",source,p);
    } else {
      expert_add_info_format(pinfo, item, &ei_telnet_invalid_purge, "%s <Invalid Purge Packet>", source);
    }
    break;

  default:
    expert_add_info_format(pinfo, item, &ei_telnet_invalid_subcommand, "Invalid %s subcommand %u", optname, cmd);
    offset++;
    len--;
    if (len > 0)
      proto_tree_add_item(tree, hf_telnet_subcommand_data, tvb, offset, len, ENC_NA);
    return;
  }

}

static const value_string rfc_opt_vals[] = {
  { 0, "OFF" },
  { 1, "ON" },
  { 2, "RESTART-ANY" },
  { 3, "RESTART-XON" },
  { 0, NULL }
};

static void
dissect_rfc_subopt(packet_info *pinfo _U_, const char *optname _U_, tvbuff_t *tvb, unsigned offset,
                   unsigned len _U_, proto_tree *tree, proto_item *item _U_)
{
  proto_tree_add_item(tree, hf_telnet_rfc_subopt_cmd, tvb, offset, 1, ENC_BIG_ENDIAN);
}

#define TN_ENC_IS               0
#define TN_ENC_SUPPORT          1
#define TN_ENC_REPLY            2
#define TN_ENC_START            3
#define TN_ENC_END              4
#define TN_ENC_REQUEST_START    5
#define TN_ENC_REQUEST_END      6
#define TN_ENC_ENC_KEYID        7
#define TN_ENC_DEC_KEYID        8
static const value_string enc_cmd_vals[] = {
  { TN_ENC_IS,            "IS" },
  { TN_ENC_SUPPORT,       "SUPPORT" },
  { TN_ENC_REPLY,         "REPLY" },
  { TN_ENC_START,         "START" },
  { TN_ENC_END,           "END" },
  { TN_ENC_REQUEST_START, "REQUEST-START" },
  { TN_ENC_REQUEST_END,   "REQUEST-END" },
  { TN_ENC_ENC_KEYID,     "ENC_KEYID" },
  { TN_ENC_DEC_KEYID,     "DEC_KEYID" },
  { 0, NULL }
};

#define TN_ENCTYPE_NULL                 0
#define TN_ENCTYPE_DES_CFB64            1
#define TN_ENCTYPE_DES_OFB64            2
#define TN_ENCTYPE_DES3_CFB64           3
#define TN_ENCTYPE_DES3_OFB64           4
#define TN_ENCTYPE_CAST5_40_CFB64       8
#define TN_ENCTYPE_CAST5_40_OFB64       9
#define TN_ENCTYPE_CAST128_CFB64        10
#define TN_ENCTYPE_CAST128_OFB64        11
static const value_string enc_type_vals[] = {
  { TN_ENCTYPE_NULL,                  "NULL" },
  { TN_ENCTYPE_DES_CFB64,             "DES_CFB64" },
  { TN_ENCTYPE_DES_OFB64,             "DES_OFB64" },
  { TN_ENCTYPE_DES3_CFB64,            "DES3_CFB64" },
  { TN_ENCTYPE_DES3_OFB64,            "DES3_OFB64" },
  { TN_ENCTYPE_CAST5_40_CFB64,        "CAST5_40_CFB64" },
  { TN_ENCTYPE_CAST5_40_OFB64,        "CAST5_40_OFB64" },
  { TN_ENCTYPE_CAST128_CFB64,         "CAST128_CFB64" },
  { TN_ENCTYPE_CAST128_OFB64,         "CAST128_OFB64" },
  { 0, NULL }
};


#define TN_AC_IS        0
#define TN_AC_SEND      1
#define TN_AC_REPLY     2
#define TN_AC_NAME      3
static const value_string auth_cmd_vals[] = {
  { TN_AC_IS,     "IS" },
  { TN_AC_SEND,   "SEND" },
  { TN_AC_REPLY,  "REPLY" },
  { TN_AC_NAME,   "NAME" },
  { 0, NULL }
};

#define TN_AT_NULL           0
#define TN_AT_KRB4           1
#define TN_AT_KRB5           2
#define TN_AT_SPX            3
#define TN_AT_MINK           4
#define TN_AT_SRP            5
#define TN_AT_RSA            6
#define TN_AT_SSL            7
#define TN_AT_LOKI          10
#define TN_AT_SSA           11
#define TN_AT_KEA_SJ        12
#define TN_AT_KEA_SJ_INTEG  13
#define TN_AT_DSS           14
#define TN_AT_NTLM          15
static const value_string auth_type_vals[] = {
  { TN_AT_NULL,         "NULL" },
  { TN_AT_KRB4,         "Kerberos v4" },
  { TN_AT_KRB5,         "Kerberos v5" },
  { TN_AT_SPX,          "SPX" },
  { TN_AT_MINK,         "MINK" },
  { TN_AT_SRP,          "SRP" },
  { TN_AT_RSA,          "RSA" },
  { TN_AT_SSL,          "SSL" },
  { TN_AT_LOKI,         "LOKI" },
  { TN_AT_SSA,          "SSA" },
  { TN_AT_KEA_SJ,       "KEA_SJ" },
  { TN_AT_KEA_SJ_INTEG, "KEA_SJ_INTEG" },
  { TN_AT_DSS,          "DSS" },
  { TN_AT_NTLM,         "NTLM" },
  { 0, NULL }
};
static const true_false_string auth_mod_cred_fwd = {
  "Client WILL forward auth creds",
  "Client will NOT forward auth creds"
};
static const true_false_string auth_mod_how = {
  "Mutual authentication",
  "One Way authentication"
};
#define TN_AM_OFF               0x00
#define TN_AM_USING_TELOPT      0x01
#define TN_AM_AFTER_EXCHANGE    0x02
#define TN_AM_RESERVED          0x04
static const value_string auth_mod_enc[] = {
  { TN_AM_OFF,            "Off" },
  { TN_AM_USING_TELOPT,   "Telnet Options" },
  { TN_AM_AFTER_EXCHANGE, "After Exchange" },
  { TN_AM_RESERVED,       "Reserved" },
  { 0, NULL }
};
#define TN_KRB5_TYPE_AUTH               0
#define TN_KRB5_TYPE_REJECT             1
#define TN_KRB5_TYPE_ACCEPT             2
#define TN_KRB5_TYPE_RESPONSE           3
#define TN_KRB5_TYPE_FORWARD            4
#define TN_KRB5_TYPE_FORWARD_ACCEPT     5
#define TN_KRB5_TYPE_FORWARD_REJECT     6
static const value_string auth_krb5_types[] = {
  { TN_KRB5_TYPE_AUTH,            "Auth" },
  { TN_KRB5_TYPE_REJECT,          "Reject" },
  { TN_KRB5_TYPE_ACCEPT,          "Accept" },
  { TN_KRB5_TYPE_RESPONSE,        "Response" },
  { TN_KRB5_TYPE_FORWARD,         "Forward" },
  { TN_KRB5_TYPE_FORWARD_ACCEPT,  "Forward Accept" },
  { TN_KRB5_TYPE_FORWARD_REJECT,  "Forward Reject" },
  { 0, NULL }
};
static void
dissect_authentication_type_pair(packet_info *pinfo _U_, tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
  static int * const auth_mods[] = {
    &hf_telnet_auth_mod_enc,
    &hf_telnet_auth_mod_cred_fwd,
    &hf_telnet_auth_mod_how,
    &hf_telnet_auth_mod_who,
    NULL
  };

  proto_tree_add_item(tree, hf_telnet_auth_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_bitmask_list(tree, tvb, offset+1, 1, auth_mods, ENC_BIG_ENDIAN);
}

/* Assume no telnet option subnegotiation exceeds 10 kB (arbitrary limit). */
#define MAX_TELNET_OPTION_SUBNEG_LEN 10240

static tvbuff_t *
unescape_and_tvbuffify_telnet_option(packet_info *pinfo, tvbuff_t *tvb, unsigned offset, unsigned len)
{
  tvbuff_t     *option_subneg_tvb;
  uint8_t      *buf;
  const uint8_t *spos;
  uint8_t      *dpos;
  int           skip, l;

  if(len >= MAX_TELNET_OPTION_SUBNEG_LEN)
    return NULL;

  spos = tvb_get_ptr(tvb, offset, len);
  const uint8_t *last_src_pos = spos + len - 1;
  buf = (uint8_t *)wmem_alloc(pinfo->pool, len);
  dpos = buf;
  skip = 0;
  l = len;
  while(l > 0) {
    // XXX Add expert info if spos >= last_src_pos?
    if(spos < last_src_pos && (spos[0] == 0xff) && (spos[1] == 0xff)) {
      skip++;
      l -= 2;
      *(dpos++) = 0xff;
      spos += 2;
      continue;
    }
    *(dpos++) = *(spos++);
    l--;
  }
  option_subneg_tvb = tvb_new_child_real_data(tvb, buf, len-skip, len-skip);
  add_new_data_source(pinfo, option_subneg_tvb, "Unpacked Telnet Option");

  return option_subneg_tvb;
}


/* as per RFC2942 */
static void
dissect_krb5_authentication_data(packet_info *pinfo, tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree, uint8_t acmd)
{
  tvbuff_t *krb5_tvb;
  uint8_t   krb5_cmd;

  krb5_cmd=tvb_get_uint8(tvb, offset);
  proto_tree_add_uint(tree, hf_telnet_auth_krb5_type, tvb, offset, 1, krb5_cmd);
  offset++;
  len--;


  /* IAC SB AUTHENTICATION IS <authentication-type-pair> AUTH <Kerberos V5 KRB_AP_REQ message> IAC SE */
  if((acmd==TN_AC_IS)&&(krb5_cmd==TN_KRB5_TYPE_AUTH)){
    if(len){
      krb5_tvb=tvb_new_subset_length(tvb, offset, len);
      dissect_kerberos_main(krb5_tvb, pinfo, tree, false, NULL);
    }
  }



  /* IAC SB AUTHENTICATION REPLY <authentication-type-pair> ACCEPT IAC SE */
  /* nothing more to dissect */



  /* IAC SB AUTHENTICATION REPLY <authentication-type-pair> REJECT <optional reason for rejection> IAC SE*/
/*qqq*/


  /* IAC SB AUTHENTICATION REPLY <authentication-type-pair> RESPONSE <KRB_AP_REP message> IAC SE */
  if((acmd==TN_AC_REPLY)&&(krb5_cmd==TN_KRB5_TYPE_RESPONSE)){
    if(len){
      krb5_tvb=tvb_new_subset_length(tvb, offset, len);
      dissect_kerberos_main(krb5_tvb, pinfo, tree, false, NULL);
    }
  }


  /* IAC SB AUTHENTICATION <authentication-type-pair> FORWARD <KRB_CRED message> IAC SE */
  /* XXX unclear what this one looks like */


  /* IAC SB AUTHENTICATION <authentication-type-pair> FORWARD_ACCEPT IAC SE */
  /* nothing more to dissect */



  /* IAC SB AUTHENTICATION <authentication-type-pair> FORWARD_REJECT */
  /* nothing more to dissect */
}


#define TN_AUTH_SSL_START  1
#define TN_AUTH_SSL_ACCEPT 2
#define TN_AUTH_SSL_REJECT 3

static const value_string ssl_auth_status[] = {
  { TN_AUTH_SSL_START,  "Start" },
  { TN_AUTH_SSL_ACCEPT, "Accepted" },
  { TN_AUTH_SSL_REJECT, "Rejected" },
  { 0, NULL }
};

static void
dissect_ssl_authentication_data(packet_info *pinfo, tvbuff_t *tvb, unsigned offset, proto_tree *tree, uint8_t acmd)
{
  unsigned ssl_status;

  proto_tree_add_item_ret_uint(tree, hf_telnet_auth_ssl_status, tvb, offset, 1, ENC_NA, &ssl_status);

  if (acmd == TN_AC_REPLY && ssl_status == TN_AUTH_SSL_ACCEPT)
    /* TLS negotiation will immediately follow this packet. */
    ssl_starttls_ack(tls_handle, pinfo, telnet_handle);
}

/* as per RFC2941 */
static void
dissect_authentication_data(packet_info *pinfo, tvbuff_t *tvb, unsigned offset, unsigned len, proto_tree *tree, uint8_t acmd)
{
  uint8_t auth_type;

  dissect_authentication_type_pair(pinfo, tvb, offset, tree);
  auth_type = tvb_get_uint8(tvb, offset);
  offset += 2;
  len -= 2;

  switch (auth_type) {
  case TN_AT_NULL:
    break;

  case TN_AT_SSL:
    dissect_ssl_authentication_data(pinfo, tvb, offset, tree, acmd);
    break;

  case TN_AT_KRB5:
    dissect_krb5_authentication_data(pinfo, tvb, offset, len, tree, acmd);
    break;

  default:
    /* We don't (yet) know how to dissect the data for this authentication type. */
    if (len > 0)
      proto_tree_add_bytes_format(tree, hf_telnet_auth_data, tvb, offset, len, NULL, "Unhandled authentication data");
  }
}

static void
dissect_authentication_subopt(packet_info *pinfo, const char *optname _U_, tvbuff_t *tvb, unsigned offset, unsigned len,
                              proto_tree *tree, proto_item *item _U_)
{
  uint8_t acmd;

  acmd=tvb_get_uint8(tvb, offset);
  proto_tree_add_uint(tree, hf_telnet_auth_cmd, tvb, offset, 1, acmd);
  offset++;
  len--;

  switch(acmd){
  case TN_AC_REPLY:
  case TN_AC_IS:
    dissect_authentication_data(pinfo, tvb, offset, len, tree, acmd);
    break;

  case TN_AC_SEND:
    while(len>0){
      dissect_authentication_type_pair(pinfo, tvb, offset, tree);
      offset+=2;
      len-=2;
    }
    break;

  case TN_AC_NAME:
    proto_tree_add_item(tree, hf_telnet_auth_name, tvb, offset, len, ENC_ASCII);
    break;
  }
}

/* This function only uses the octet in the buffer at 'offset' */
static void dissect_encryption_type(tvbuff_t *tvb, unsigned offset, proto_tree *tree) {
  uint8_t etype;
  etype = tvb_get_uint8(tvb, offset);
  proto_tree_add_uint(tree, hf_telnet_enc_type, tvb, offset, 1, etype);
}

static void
dissect_encryption_subopt(packet_info *pinfo, const char *optname _U_, tvbuff_t *tvb, unsigned offset, unsigned len,
                          proto_tree *tree, proto_item *item)
{
  uint8_t ecmd, key_first_octet;

  ecmd = tvb_get_uint8(tvb, offset);
  proto_tree_add_uint(tree, hf_telnet_enc_cmd, tvb, offset, 1, ecmd);

  offset++;
  len--;

  switch(ecmd) {
  case TN_ENC_IS:
  case TN_ENC_REPLY:
    /* encryption type, type-specific data ... */
    if (len > 0) {
      dissect_encryption_type(tvb, offset, tree);
      offset++;
      len--;
      proto_tree_add_item(tree, hf_telnet_enc_type_data, tvb, offset, len, ENC_NA);
    }
    break;

  case TN_ENC_SUPPORT:
    /* list of encryption types ... */
    while (len > 0) {
      dissect_encryption_type(tvb, offset, tree);
      offset++;
      len--;
    }
    break;

  case TN_ENC_START:
    /* keyid ... */
    if (len > 0) {
      key_first_octet = tvb_get_uint8(tvb, offset);
      proto_tree_add_bytes_format(tree, hf_telnet_enc_key_id, tvb, offset, len, NULL, (key_first_octet == 0) ? "Default key" : "Key ID");
    }
    break;

  case TN_ENC_END:
    /* no data */
    break;

  case TN_ENC_REQUEST_START:
    /* (optional) keyid */
    if (len > 0)
      proto_tree_add_bytes_format(tree, hf_telnet_enc_key_id, tvb, offset, len, NULL, "Key ID (advisory)");
    break;

  case TN_ENC_REQUEST_END:
    /* no data */
    break;

  case TN_ENC_ENC_KEYID:
  case TN_ENC_DEC_KEYID:
    /* (optional) keyid - if not supplied, there are no more known keys */
    if (len > 0)
      proto_tree_add_item(tree, hf_telnet_enc_key_id, tvb, offset, len, ENC_NA);
    break;

  default:
    expert_add_info(pinfo, item, &ei_telnet_enc_cmd_unknown);
  }
}

#define VMWARE_TELNET_EXT 232

/* Option Subnegotiation */
#define VMWARE_KNOWN_SUBOPTIONS_1 0
#define VMWARE_KNOWN_SUBOPTIONS_2 1

/* Unknown Command Response */
#define VMWARE_UNKNOWN_SUBOPTION_RCVD_1 2
#define VMWARE_UNKNOWN_SUBOPTION_RCVD_2 3

/* vMotion Notification */
#define VMWARE_VMOTION_BEGIN 40
#define VMWARE_VMOTION_GOAHEAD 41
#define VMWARE_VMOTION_NOTNOW 43
#define VMWARE_VMOTION_PEER 44
#define VMWARE_VMOTION_PEER_OK 45
#define VMWARE_VMOTION_COMPLETE 46
#define VMWARE_VMOTION_ABORT 48

/* Proxy operation */
#define VMWARE_DO_PROXY 70
#define VMWARE_WILL_PROXY 71
#define VMWARE_WONT_PROXY 73

/* Virtual machine identification */
#define VMWARE_VM_VC_UUID 80
#define VMWARE_GET_VM_VC_UUID 81
#define VMWARE_VM_NAME 82
#define VMWARE_GET_VM_NAME 83
#define VMWARE_VM_BIOS_UUID 84
#define VMWARE_GET_VM_BIOS_UUID 85
#define VMWARE_VM_LOCATION_UUID 86
#define VMWARE_GET_VM_LOCATION_UUID 87

static const value_string vmware_cmd_vals[] = {
  { VMWARE_KNOWN_SUBOPTIONS_1,       "KNOWN-SUBOPTIONS-1" },
  { VMWARE_KNOWN_SUBOPTIONS_2,       "KNOWN-SUBOPTIONS-2" },
  { VMWARE_UNKNOWN_SUBOPTION_RCVD_1, "UNKNOWN-SUBOPTION-RCVD-1" },
  { VMWARE_UNKNOWN_SUBOPTION_RCVD_2, "UNKNOWN-SUBOPTION-RCVD-2" },
  { VMWARE_VMOTION_BEGIN,            "VMOTION-BEGIN" },
  { VMWARE_VMOTION_GOAHEAD,          "VMOTION-GOAHEAD" },
  { VMWARE_VMOTION_NOTNOW,           "VMOTION-NOTNOW" },
  { VMWARE_VMOTION_PEER,             "VMOTION-PEER" },
  { VMWARE_VMOTION_PEER_OK,          "VMOTION-PEER-OK" },
  { VMWARE_VMOTION_COMPLETE,         "VMOTION-COMPLETE" },
  { VMWARE_VMOTION_ABORT,            "VMOTION-ABORT" },
  { VMWARE_DO_PROXY,                 "DO-PROXY" },
  { VMWARE_WILL_PROXY,               "WILL-PROXY" },
  { VMWARE_WONT_PROXY,               "WONT-PROXY" },
  { VMWARE_VM_VC_UUID,               "VM-VC-UUID" },
  { VMWARE_GET_VM_VC_UUID,           "GET-VM-VC-UUID" },
  { VMWARE_VM_NAME,                  "VM-NAME" },
  { VMWARE_GET_VM_NAME,              "GET-VM-NAME" },
  { VMWARE_VM_BIOS_UUID,             "VM-BIOS-UUID" },
  { VMWARE_GET_VM_BIOS_UUID,         "GET-VM-BIOS-UUID" },
  { VMWARE_VM_LOCATION_UUID,         "VM-LOCATION-UUID" },
  { VMWARE_GET_VM_LOCATION_UUID,     "GET-VM-LOCATION-UUID" },
  { 0, NULL }
};

/* Encoding for the "direction" argument to DO-PROXY: */
#define VMWARE_PROXY_DIRECTION_CLIENT 'C'
#define VMWARE_PROXY_DIRECTION_SERVER 'S'

static const value_string vmware_proxy_direction_vals[] = {
  { VMWARE_PROXY_DIRECTION_CLIENT, "Client" },
  { VMWARE_PROXY_DIRECTION_SERVER, "Server" },
  { 0, NULL }
};

static void
dissect_vmware_subopt(packet_info *pinfo _U_, const char *optname _U_, tvbuff_t *tvb, unsigned offset, unsigned len,
                      proto_tree *tree, proto_item *item _U_)
{
  /*
   * The VMware virtual serial port proxy uses the Telnet protocol over TCP
   * port 13370.  Use "Decode As..." or specify "-d tcp.port==13370,telnet" on
   * the command-line.
   */

  uint8_t vmwcmd;

  vmwcmd = tvb_get_uint8(tvb, offset);
  proto_tree_add_uint(tree, hf_telnet_vmware_cmd, tvb, offset, 1, vmwcmd);
  offset++;
  len--;

  switch (vmwcmd) {

  /* --- Option Subnegotiation --- */

  case VMWARE_KNOWN_SUBOPTIONS_1:
  case VMWARE_KNOWN_SUBOPTIONS_2:
    /* Data: suboptions... */
    while (len > 0) {
      proto_tree_add_item(tree, hf_telnet_vmware_known_suboption_code, tvb, offset, 1, ENC_NA);
      offset++;
      len--;
    }
    break;

  /* --- Unknown Command Response --- */

  case VMWARE_UNKNOWN_SUBOPTION_RCVD_1:
  case VMWARE_UNKNOWN_SUBOPTION_RCVD_2:
    /* Data: suboption */
    proto_tree_add_item(tree, hf_telnet_vmware_unknown_subopt_code, tvb, offset, 1, ENC_NA);
    offset++;
    len--;
    break;

  /* --- vMotion Notification --- */

  case VMWARE_VMOTION_BEGIN:
  case VMWARE_VMOTION_NOTNOW:
  case VMWARE_VMOTION_PEER_OK:
  case VMWARE_VMOTION_COMPLETE: {
    /* Data: sequence */
    telnet_conv_info_t *session = telnet_get_session(pinfo);
    if (session->vmotion_sequence_len < 0) {
      /*
       * There is nothing which _requires_ that the sequence length be constant
       * throughout a Telnet conversation, but all implementations currently
       * behave that way and here we assume it will be so.  If that changes,
       * subsequent VMOTION-GOAHEAD/VMOTION-PEER messages might be incorrectly
       * dissected, with bytes incorrectly assigned to the sequence or secret
       * fields.  This should not be a big deal.
       */
      session->vmotion_sequence_len = len;
    }
    proto_tree_add_item(tree, hf_telnet_vmware_vmotion_sequence, tvb, offset, len, ENC_NA);
    offset += len;
    len = 0;
  }
    break;

  case VMWARE_VMOTION_GOAHEAD:
  case VMWARE_VMOTION_PEER: {
    /* Data: sequence secret */
    telnet_conv_info_t *session = telnet_get_session(pinfo);

    /*
     * The lack of delimiter between "sequence" and "secret" makes dissection
     * challenging.  We need to track the "vMotion conversation", which spans
     * two Telnet conversations with different endpoints.  The vMotion
     * conversation is identified by a blob containing the concatenation of the
     * sequence and secret.
     */
    if ((vmwcmd == VMWARE_VMOTION_GOAHEAD && session->vmotion_sequence_len >= 0) ||
        (vmwcmd == VMWARE_VMOTION_PEER && session->vmotion_sequence_len < 0)) {
      conversation_element_t conv_key[2] = {
        {
          .type = CE_BLOB,
          .blob = {
             .val = tvb_memdup(pinfo->pool, tvb, offset, len),
             .len = len,
          },
        },
        {
          .type = CE_CONVERSATION_TYPE,
          .conversation_type_val = CONVERSATION_VSPC_VMOTION,
        }
      };
      conversation_t *vmotion_conv = find_conversation_full(pinfo->num, conv_key);

      if (vmwcmd == VMWARE_VMOTION_GOAHEAD && vmotion_conv == NULL) {
        /*
         * We have the full sequence and secret and we know the length of the
         * "sequence" field.  Stash it (or, really, its session) where we can
         * find it later.
         */
        vmotion_conv = conversation_new_full(pinfo->num, conv_key);
        conversation_add_proto_data(vmotion_conv, proto_telnet, session);
      } else if (vmwcmd == VMWARE_VMOTION_PEER && vmotion_conv != NULL) {
        /*
         * Try to find the length of the "sequence" field from the conversation
         * containing the VMOTION-GOAHEAD message.
         */
        telnet_conv_info_t const *source_session =
          (telnet_conv_info_t const *)conversation_get_proto_data(vmotion_conv, proto_telnet);

        if (source_session != NULL) {
          session->vmotion_sequence_len = source_session->vmotion_sequence_len;
        }
        /* The secret is only used once, so the vMotion conversation ends here. */
        vmotion_conv->last_frame = pinfo->num;
      }
      wmem_free(pinfo->pool, (void *)conv_key[0].blob.val);
    }
    if (session->vmotion_sequence_len >= 0 && (unsigned)session->vmotion_sequence_len <= len) {
      proto_tree_add_item(tree, hf_telnet_vmware_vmotion_sequence, tvb, offset, (unsigned)session->vmotion_sequence_len, ENC_NA);
      offset += (unsigned)session->vmotion_sequence_len;
      len -= (unsigned)session->vmotion_sequence_len;

      proto_tree_add_item(tree, hf_telnet_vmware_vmotion_secret, tvb, offset, len, ENC_NA);
      offset += len;
      len = 0;
    } else {
      /*
       * With no delimiter between "sequence" and "secret", nor any other way
       * of determining the lengths of those fields, we lack the information to
       * be able to dissect this.  Skip it.
       */
      offset += len;
      len = 0;
    }
  }
    break;

  case VMWARE_VMOTION_ABORT:
    /* no data */
    break;

  /* --- Proxy Operation --- */

  case VMWARE_DO_PROXY:
    /* Data: direction serviceUri */
    proto_tree_add_item(tree, hf_telnet_vmware_proxy_direction, tvb, offset, 1, ENC_ASCII);
    offset++;
    len--;
    proto_tree_add_item(tree, hf_telnet_vmware_proxy_serviceUri, tvb, offset, len, ENC_UTF_8);
    offset += len;
    len = 0;
    break;

  case VMWARE_WILL_PROXY:
  case VMWARE_WONT_PROXY:
    /* no data */
    break;

  /* --- Virtual Machine Identification --- */

  case VMWARE_GET_VM_VC_UUID:
  case VMWARE_GET_VM_NAME:
  case VMWARE_GET_VM_BIOS_UUID:
  case VMWARE_GET_VM_LOCATION_UUID:
    /* no data */
    break;

  case VMWARE_VM_NAME:
    /* Data: vm-name */
    proto_tree_add_item(tree, hf_telnet_vmware_vm_name, tvb, offset, len, ENC_UTF_8);
    offset += len;
    len = 0;
    break;

  case VMWARE_VM_VC_UUID:
    /* Data: vm-uuid */
    proto_tree_add_item(tree, hf_telnet_vmware_vm_vc_uuid, tvb, offset, len, ENC_ASCII);
    offset += len;
    len = 0;
    break;

  case VMWARE_VM_BIOS_UUID:
    /* Data: vm-uuid */
    proto_tree_add_item(tree, hf_telnet_vmware_vm_bios_uuid, tvb, offset, len, ENC_ASCII);
    offset += len;
    len = 0;
    break;

  case VMWARE_VM_LOCATION_UUID:
    /* Data: vm-uuid */
    proto_tree_add_item(tree, hf_telnet_vmware_vm_location_uuid, tvb, offset, len, ENC_ASCII);
    offset += len;
    len = 0;
    break;

  default:
    expert_add_info_format(pinfo, item, &ei_telnet_invalid_subcommand, "Invalid %s subcommand %u", optname, vmwcmd);
    if (len > 0)
      proto_tree_add_item(tree, hf_telnet_subcommand_data, tvb, offset, len, ENC_NA);
    return;
  }
  if (len > 0) {
    proto_item *pi = proto_tree_add_bytes_format(tree, hf_telnet_subcommand_data, tvb, offset, len, NULL, "Unexpected data");
    expert_add_info_format(pinfo, pi, &ei_telnet_vmware_unexp_data, "%u bytes unexpected data", len);
  }
}

static const tn_opt options[] = {
  {
    "Binary Transmission",                      /* RFC 856 */
    NULL,                                       /* no suboption negotiation */
    NO_LENGTH,
    0,
    NULL
  },
  {
    "Echo",                                     /* RFC 857 */
    NULL,                                       /* no suboption negotiation */
    NO_LENGTH,
    0,
    NULL
  },
  {
    "Reconnection",                             /* DOD Protocol Handbook */
    NULL,
    NO_LENGTH,
    0,
    NULL
  },
  {
    "Suppress Go Ahead",                        /* RFC 858 */
    NULL,                                       /* no suboption negotiation */
    NO_LENGTH,
    0,
    NULL
  },
  {
    "Approx Message Size Negotiation",          /* Ethernet spec(!) */
    NULL,
    NO_LENGTH,
    0,
    NULL
  },
  {
    "Status",                                   /* RFC 859 */
    &ett_status_subopt,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Timing Mark",                              /* RFC 860 */
    NULL,                                       /* no suboption negotiation */
    NO_LENGTH,
    0,
    NULL
  },
  {
    "Remote Controlled Trans and Echo",         /* RFC 726 */
    &ett_rcte_subopt,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Output Line Width",                        /* DOD Protocol Handbook */
    &ett_olw_subopt,
    VARIABLE_LENGTH,                            /* XXX - fill me in */
    0,                                          /* XXX - fill me in */
    NULL                                        /* XXX - fill me in */
  },
  {
    "Output Page Size",                         /* DOD Protocol Handbook */
    &ett_ops_subopt,
    VARIABLE_LENGTH,                            /* XXX - fill me in */
    0,                                          /* XXX - fill me in */
    NULL                                        /* XXX - fill me in */
  },
  {
    "Output Carriage-Return Disposition",       /* RFC 652 */
    &ett_crdisp_subopt,
    FIXED_LENGTH,
    2,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Output Horizontal Tab Stops",              /* RFC 653 */
    &ett_htstops_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_htstops_subopt
  },
  {
    "Output Horizontal Tab Disposition",        /* RFC 654 */
    &ett_htdisp_subopt,
    FIXED_LENGTH,
    2,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Output Formfeed Disposition",              /* RFC 655 */
    &ett_ffdisp_subopt,
    FIXED_LENGTH,
    2,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Output Vertical Tabstops",                 /* RFC 656 */
    &ett_vtstops_subopt,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Output Vertical Tab Disposition",          /* RFC 657 */
    &ett_vtdisp_subopt,
    FIXED_LENGTH,
    2,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Output Linefeed Disposition",              /* RFC 658 */
    &ett_lfdisp_subopt,
    FIXED_LENGTH,
    2,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Extended ASCII",                           /* RFC 698 */
    &ett_extasc_subopt,
    FIXED_LENGTH,
    2,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Logout",                                   /* RFC 727 */
    NULL,                                       /* no suboption negotiation */
    NO_LENGTH,
    0,
    NULL
  },
  {
    "Byte Macro",                               /* RFC 735 */
    &ett_bytemacro_subopt,
    VARIABLE_LENGTH,
    2,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Data Entry Terminal",                      /* RFC 732, RFC 1043 */
    &ett_det_subopt,
    VARIABLE_LENGTH,
    2,
    NULL                                        /* XXX - fill me in */
  },
  {
    "SUPDUP",                                   /* RFC 734, RFC 736 */
    NULL,                                       /* no suboption negotiation */
    NO_LENGTH,
    0,
    NULL
  },
  {
    "SUPDUP Output",                            /* RFC 749 */
    &ett_supdupout_subopt,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Send Location",                            /* RFC 779 */
    &ett_sendloc_subopt,
    VARIABLE_LENGTH,
    0,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Terminal Type",                            /* RFC 1091 */
    &ett_termtype_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_string_subopt
  },
  {
    "End of Record",                            /* RFC 885 */
    NULL,                                       /* no suboption negotiation */
    NO_LENGTH,
    0,
    NULL
  },
  {
    "TACACS User Identification",               /* RFC 927 */
    &ett_tacacsui_subopt,
    FIXED_LENGTH,
    4,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Output Marking",                           /* RFC 933 */
    &ett_outmark_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_outmark_subopt,
  },
  {
    "Terminal Location Number",                 /* RFC 946 */
    &ett_tlocnum_subopt,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Telnet 3270 Regime",                       /* RFC 1041 */
    &ett_tn3270reg_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_tn3270_regime_subopt
  },
  {
    "X.3 PAD",                                  /* RFC 1053 */
    &ett_x3pad_subopt,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Negotiate About Window Size",              /* RFC 1073, DW183 */
    &ett_naws_subopt,
    FIXED_LENGTH,
    4,
    dissect_naws_subopt
  },
  {
    "Terminal Speed",                           /* RFC 1079 */
    &ett_tspeed_subopt,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Remote Flow Control",                      /* RFC 1372 */
    &ett_rfc_subopt,
    FIXED_LENGTH,
    1,
    dissect_rfc_subopt
  },
  {
    "Linemode",                                 /* RFC 1184 */
    &ett_linemode_subopt,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - fill me in */
  },
  {
    "X Display Location",                       /* RFC 1096 */
    &ett_xdpyloc_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_string_subopt
  },
  {
    "Environment Option",                       /* RFC 1408, RFC 1571 */
    &ett_env_subopt,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Authentication Option",                    /* RFC 2941 */
    &ett_auth_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_authentication_subopt
  },
  {
    "Encryption Option",                        /* RFC 2946 */
    &ett_enc_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_encryption_subopt
  },
  {
    "New Environment Option",                   /* RFC 1572 */
    &ett_newenv_subopt,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - fill me in */
  },
  {
    "TN3270E",                                  /* RFC 1647 */
    &ett_tn3270e_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_tn3270e_subopt
  },
  {
    "XAUTH",                                    /* XAUTH  */
    &ett_xauth_subopt,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - fill me in */
  },
  {
    "CHARSET",                                  /* CHARSET  */
    &ett_charset_subopt,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - fill me in */
  },
  {
    "Remote Serial Port",                       /* Remote Serial Port */
    &ett_rsp_subopt,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - fill me in */
  },
  {
    "COM Port Control",                         /* RFC 2217 */
    &ett_comport_subopt,
    VARIABLE_LENGTH,
    1,
    dissect_comport_subopt
  },
  {
    "Suppress Local Echo",                      /* draft-rfced-exp-atmar-00 */
    NULL,
    NO_LENGTH,
    0,
    NULL
  },
  {
    "Start TLS",                                /* draft-ietf-tn3270e-telnet-tls-06 */
    &ett_starttls_subopt,
    FIXED_LENGTH,
    1,
    dissect_starttls_subopt
  },
  {
    "KERMIT",                                   /* RFC 2840 */
    NULL,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - stub */
  },
  {
    "SEND-URL",                                 /* draft-croft-telnet-url-trans-00 */
    NULL,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - stub */
  },
  {
    "FORWARD_X",                                /* draft-altman-telnet-fwdx-03 */
    NULL,
    VARIABLE_LENGTH,
    1,
    NULL                                        /* XXX - stub */
  }

};

static const tn_opt telnet_opt_vmware = {
  "VMware Virtual Serial Port Proxy",
  NULL,
  VARIABLE_LENGTH,
  1,
  dissect_vmware_subopt
};

static const tn_opt telnet_opt_unknown = {
  "<unknown option>",
  NULL,
  VARIABLE_LENGTH,
  0,
  NULL
};

static const tn_opt *
telnet_find_option(uint8_t opt_byte)
{
  if (opt_byte < array_length(options))
    return &options[opt_byte];

  if (opt_byte == VMWARE_TELNET_EXT)
    return &telnet_opt_vmware;

  return &telnet_opt_unknown;
}

static int
telnet_sub_option(packet_info *pinfo, proto_tree *option_tree, proto_item *option_item, tvbuff_t *tvb, unsigned start_offset)
{
  unsigned      offset = start_offset;
  uint8_t       opt_byte;
  const tn_opt *opt;
  unsigned      subneg_len;
  unsigned      iac_offset;
  unsigned      len;
  tvbuff_t     *unescaped_tvb;
  unsigned      cur_offset;
  bool          iac_found;

  /*
   * As data with value iac (0xff) is possible, this value must be escaped
   * with iac (rfc 854).
   */
  unsigned  iac_data = 0;

  offset += 2;  /* skip IAC and SB */

  /* Get the option code */
  opt_byte = tvb_get_uint8(tvb, offset);
  opt = telnet_find_option(opt_byte);
  offset++;

  /* Search for an unescaped IAC. */
  cur_offset = offset;
  len = tvb_reported_length_remaining(tvb, offset);
  do {
    iac_found = tvb_find_uint8_length(tvb, cur_offset, len, TN_IAC, &iac_offset);
    if (iac_found == false) {
      /* None found - run to the end of the packet. */
      offset += len;
      /* To exit loop ?? (to keep logic from tvb_find_uint8())*/
      iac_found = true;
    } else {
      if (!tvb_offset_exists(tvb, iac_offset + 1) ||
          (tvb_get_uint8(tvb, iac_offset + 1) != TN_IAC)) {
        /* We really found a single IAC, so we're done */
        offset = iac_offset;
      } else {
        /*
         * We saw an escaped IAC, so we have to move ahead to the
         * next section
         */
        iac_found = false;
        cur_offset = iac_offset + 2;
        iac_data += 1;
      }
    }

  } while (!iac_found);

  subneg_len = offset - start_offset;

  start_offset += 3;    /* skip IAC, SB, and option code */
  subneg_len -= 3;

  if (subneg_len > 0) {

    /* Now dissect the suboption parameters. */
    if (opt->dissect != NULL) {

      switch (opt->len_type) {

      case NO_LENGTH:
        /* There isn't supposed to *be* sub-option negotiation for this. */
        expert_add_info_format(pinfo, option_item, &ei_telnet_suboption_length, "Bogus suboption data");
        return offset;

      case FIXED_LENGTH:
        /* Make sure the length is what it's supposed to be. */
        if (subneg_len - iac_data != opt->optlen) {
          expert_add_info_format(pinfo, option_item, &ei_telnet_suboption_length, "Suboption parameter length is %d, should be %d", subneg_len, opt->optlen);
          return offset;
        }
        break;

      case VARIABLE_LENGTH:
        /* Make sure the length is greater than the minimum. */
        if (subneg_len - iac_data < opt->optlen) {
          expert_add_info_format(pinfo, option_item, &ei_telnet_suboption_length, "Suboption parameter length is %d, should be at least %d", subneg_len, opt->optlen);
          return offset;
        }
        break;
      }

      /* We have a dissector for this suboption's parameters; call it. */
      if (iac_data > 0) {
        /* Data is escaped, we have to unescape it. */
        unescaped_tvb = unescape_and_tvbuffify_telnet_option(pinfo, tvb, start_offset, subneg_len);
        (*opt->dissect)(pinfo, opt->name, unescaped_tvb, 0, subneg_len - iac_data, option_tree, option_item);
      } else {
        (*opt->dissect)(pinfo, opt->name, tvb, start_offset, subneg_len, option_tree, option_item);
      }
    } else {
      /* We don't have a dissector for them; just show them as data. */
      if (iac_data > 0) {
        /* Data is escaped, we have to unescape it. */
        unescaped_tvb = unescape_and_tvbuffify_telnet_option(pinfo, tvb, start_offset, subneg_len);
        proto_tree_add_item(option_tree, hf_telnet_option_data, unescaped_tvb, 0, subneg_len - iac_data, ENC_NA);
      } else {
        proto_tree_add_item(option_tree, hf_telnet_option_data, tvb, start_offset, subneg_len, ENC_NA);
      }
    }
  }
  return offset;
}

static void
telnet_suboption_name(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int* offset, const char** optname,
                      proto_tree **opt_tree, proto_item **opt_item, const char *type)
{
  uint8_t       opt_byte;
  const tn_opt *opt;
  int           ett = ett_telnet_subopt;

  opt_byte = tvb_get_uint8(tvb, *offset);
  opt = telnet_find_option(opt_byte);
  if (opt->subtree_index != NULL)
    ett = *(opt->subtree_index);
  *opt_item = proto_tree_add_uint_format_value(tree, hf_telnet_subcmd, tvb, *offset, 1, opt_byte, "%s", opt->name);
  *opt_tree = proto_item_add_subtree(*opt_item, ett);

  (*offset)++;
  (*optname) = wmem_strdup_printf(pinfo->pool, "%s %s", type, opt->name);
}

static int
telnet_command(packet_info *pinfo, proto_tree *telnet_tree, tvbuff_t *tvb, int start_offset, unsigned *num_info_items)
{
  int    offset = start_offset;
  unsigned char optcode;
  const char* optname = NULL;
  proto_item *cmd_item, *subopt_item = NULL;
  proto_tree *cmd_tree, *subopt_tree = NULL;

  offset += 1;  /* skip IAC */
  optcode = tvb_get_uint8(tvb, offset);

  cmd_tree = proto_tree_add_subtree(telnet_tree, tvb, start_offset, 2, ett_telnet_cmd, &cmd_item, "Command header");
  proto_tree_add_item(cmd_tree, hf_telnet_cmd, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  switch(optcode) {
  case TN_WILL:
    telnet_suboption_name(cmd_tree, pinfo, tvb, &offset, &optname, &subopt_tree, &subopt_item, "Will");
    break;

  case TN_WONT:
    telnet_suboption_name(cmd_tree, pinfo, tvb, &offset, &optname, &subopt_tree, &subopt_item, "Won't");
    break;

  case TN_DO:
    telnet_suboption_name(cmd_tree, pinfo, tvb, &offset, &optname, &subopt_tree, &subopt_item, "Do");
    break;

  case TN_DONT:
    telnet_suboption_name(cmd_tree, pinfo, tvb, &offset, &optname, &subopt_tree, &subopt_item, "Don't");
    break;

  case TN_SB:
    telnet_suboption_name(cmd_tree, pinfo, tvb, &offset, &optname, &subopt_tree, &subopt_item, "Suboption");
    break;

  case ILO2_CMD_ENCRYPT: {
    /* HP iLO2 Encrypt: IAC + 0xC0 + 4-byte key index + encrypted data */
    ilo2_conv_info_t *ilo2 = ilo2_get_session(pinfo);
    ilo2->encrypt_enabled = true;
    ilo2->dvc_encryption = true;

    /* Mark encryption as active for server→client direction.
     * ESC [ R is sent as plaintext by the server before DVC mode,
     * but the server encrypts data after IAC C0. We handle ESC [ R
     * detection in the raw data before decryption. */
    if (ilo2_is_from_client(pinfo, ilo2)) {
      ilo2->client_encryption_active = true;
    } else {
      ilo2->server_encryption_active = true;
    }
    uint32_t key_index = 0;
    if (tvb_offset_exists(tvb, offset + 3)) {
      key_index  = (uint32_t)tvb_get_uint8(tvb, offset)     << 24;
      key_index |= (uint32_t)tvb_get_uint8(tvb, offset + 1) << 16;
      key_index |= (uint32_t)tvb_get_uint8(tvb, offset + 2) << 8;
      key_index |= (uint32_t)tvb_get_uint8(tvb, offset + 3);
      proto_tree_add_item(cmd_tree, hf_telnet_ilo2_key_index, tvb, offset, 4, ENC_BIG_ENDIAN);
    }
    offset += 4;

    /* Consume all remaining bytes as encrypted data */
    {
      unsigned enc_len = tvb_reported_length_remaining(tvb, offset);
      if (enc_len > 0) {
        uint8_t *decrypted = (uint8_t *)wmem_alloc(pinfo->pool, enc_len);
        tvbuff_t *decrypted_tvb;
        bool from_client;

        tvb_memcpy(tvb, decrypted, offset, enc_len);

        /* Determine direction and use appropriate RC4 */
        from_client = ilo2_is_from_client(pinfo, ilo2);
        if (!ilo2->client_addr_set) {
          /* First ENCRYPT with data - record client address */
          copy_address(&ilo2->client_addr, &pinfo->src);
          ilo2->client_addr_set = true;
        }

        if (from_client) {
          ilo2_rc4_decrypt(&ilo2->client_rc4, decrypted, enc_len);
        } else {
          ilo2_rc4_decrypt(&ilo2->server_rc4, decrypted, enc_len);
        }

        proto_tree_add_bytes_format(cmd_tree, hf_telnet_ilo2_encrypted_data,
                                   tvb, offset, enc_len, NULL, "Encrypted data (%u bytes)", enc_len);
        decrypted_tvb = tvb_new_real_data(decrypted, enc_len, enc_len);
        tvb_set_child_real_data_tvbuff(tvb, decrypted_tvb);
        proto_tree_add_item(cmd_tree, hf_telnet_ilo2_decrypted_data,
                           decrypted_tvb, 0, enc_len, ENC_NA);
        offset += enc_len;
      }
    }

    optname = wmem_strdup_printf(pinfo->pool, "HP iLO2 Encrypt (key=0x%08X)", key_index);
    break;
  }

  case ILO2_CMD_CHG_KEYS:
    optname = "HP iLO2 Change Keys";
    ilo2_rc4_update_key(&ilo2_get_session(pinfo)->client_rc4);
    ilo2_rc4_update_key(&ilo2_get_session(pinfo)->server_rc4);
    break;

  case ILO2_CMD_TS_AVAIL:
    optname = "HP iLO2 Terminal Services Available";
    break;

  case ILO2_CMD_TS_NOT_AVAIL:
    optname = "HP iLO2 Terminal Services Not Available";
    break;

  case ILO2_CMD_TS_STARTED:
    optname = "HP iLO2 Terminal Services Started";
    break;

  case ILO2_CMD_TS_STOPPED:
    optname = "HP iLO2 Terminal Services Stopped";
    break;

  case ILO2_CMD_MOUSE_MOVE: {
    /* Mouse Move: 2 bytes (dx, dy) + optional 4 bytes (clientX, clientY) */
    int8_t dx = 0, dy = 0;
    if (tvb_offset_exists(tvb, offset + 1)) {
      dx = (int8_t)tvb_get_uint8(tvb, offset);
      dy = (int8_t)tvb_get_uint8(tvb, offset + 1);
      proto_tree_add_item(cmd_tree, hf_telnet_ilo2_mouse_dx, tvb, offset, 1, ENC_NA);
      proto_tree_add_item(cmd_tree, hf_telnet_ilo2_mouse_dy, tvb, offset + 1, 1, ENC_NA);
      offset += 2;
      /* Check for absolute coordinates (4 more bytes) */
      if (tvb_offset_exists(tvb, offset + 3)) {
        uint16_t client_x = (uint16_t)tvb_get_uint8(tvb, offset) << 8 | tvb_get_uint8(tvb, offset + 1);
        uint16_t client_y = (uint16_t)tvb_get_uint8(tvb, offset + 2) << 8 | tvb_get_uint8(tvb, offset + 3);
        proto_tree_add_item(cmd_tree, hf_telnet_ilo2_mouse_client_x, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(cmd_tree, hf_telnet_ilo2_mouse_client_y, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        offset += 4;
        optname = wmem_strdup_printf(pinfo->pool, "HP iLO2 Mouse Move dx=%d dy=%d (%u,%u)", dx, dy, client_x, client_y);
      } else {
        optname = wmem_strdup_printf(pinfo->pool, "HP iLO2 Mouse Move dx=%d dy=%d", dx, dy);
      }
    }
    break;
  }

  case ILO2_CMD_BTN_PRESS: {
    uint8_t mask = 0;
    if (tvb_offset_exists(tvb, offset)) {
      mask = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(cmd_tree, hf_telnet_ilo2_button_mask, tvb, offset, 1, ENC_NA);
      offset++;
    }
    optname = wmem_strdup_printf(pinfo->pool, "HP iLO2 Button Press (0x%02X)", mask);
    break;
  }

  case ILO2_CMD_BTN_RELEASE: {
    uint8_t mask = 0;
    if (tvb_offset_exists(tvb, offset)) {
      mask = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(cmd_tree, hf_telnet_ilo2_button_mask, tvb, offset, 1, ENC_NA);
      offset++;
    }
    optname = wmem_strdup_printf(pinfo->pool, "HP iLO2 Button Release (0x%02X)", mask);
    break;
  }

  case ILO2_CMD_BTN_CLICK: {
    uint8_t mask = 0, count = 0;
    if (tvb_offset_exists(tvb, offset + 1)) {
      mask = tvb_get_uint8(tvb, offset);
      count = tvb_get_uint8(tvb, offset + 1);
      proto_tree_add_item(cmd_tree, hf_telnet_ilo2_button_mask, tvb, offset, 1, ENC_NA);
      proto_tree_add_item(cmd_tree, hf_telnet_ilo2_click_count, tvb, offset + 1, 1, ENC_NA);
      offset += 2;
    }
    optname = wmem_strdup_printf(pinfo->pool, "HP iLO2 Button Click (0x%02X, %u)", mask, count);
    break;
  }

  case ILO2_CMD_RAW_BYTE: {
    uint8_t raw = 0;
    if (tvb_offset_exists(tvb, offset)) {
      raw = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(cmd_tree, hf_telnet_ilo2_raw_byte, tvb, offset, 1, ENC_NA);
      offset++;
    }
    optname = wmem_strdup_printf(pinfo->pool, "HP iLO2 Raw Byte (0x%02X)", raw);
    break;
  }

  case ILO2_CMD_SET_MOUSE_MODE: {
    uint8_t mode = 0;
    if (tvb_offset_exists(tvb, offset)) {
      mode = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(cmd_tree, hf_telnet_ilo2_mouse_mode, tvb, offset, 1, ENC_NA);
      offset++;
    }
    optname = wmem_strdup_printf(pinfo->pool, "HP iLO2 Set Mouse Mode (%s)", val_to_str_const(mode, ilo2_mouse_mode_vals, "Unknown"));
    break;
  }

  default:
    if (optcode >= 0xC0 && optcode <= 0xDF) {
      optname = val_to_str_const(optcode, ilo2_cmd_vals, "HP iLO2 Unknown Command");
    } else {
      optname = val_to_str_const(optcode, cmd_vals, "<unknown option>");
    }
    break;
  }

  proto_item_set_text(cmd_item, "%s", optname);
  if (optcode != TN_SE) {
    add_telnet_info_str(pinfo, num_info_items, optname);
  }

  if (optcode == TN_SB) {
    offset = telnet_sub_option(pinfo, subopt_tree, subopt_item, tvb, start_offset);
  }

  proto_item_set_len(cmd_item, offset-start_offset);

  return offset;
}

static void
telnet_add_text(proto_tree *tree, tvbuff_t *tvb, unsigned offset, unsigned len)
{
  unsigned next_offset;
  unsigned linelen;
  uint8_t  c;
  bool last_char_was_cr;

  while (len != 0 && tvb_offset_exists(tvb, offset)) {
    /*
     * Find the end of the line.
     */
    tvb_find_line_end_length(tvb, offset, len, &linelen, &next_offset);
    len -= next_offset - offset;        /* subtract out the line's characters */

    /*
     * In Telnet, CR NUL is the way you send a CR by itself in the
     * default ASCII mode; don't treat CR by itself as a line ending,
     * treat only CR NUL, CR LF, or LF by itself as a line ending.
     */
    if (next_offset == offset + linelen + 1 && len >= 1) {
      /*
       * Well, we saw a one-character line ending, so either it's a CR
       * or an LF; we have at least two characters left, including the
       * CR.
       *
       * If the line ending is a CR, skip all subsequent CRs; at
       * least one capture appeared to have multiple CRs at the end of
       * a line.
       */
      if (tvb_get_uint8(tvb, offset + linelen) == '\r') {
        last_char_was_cr = true;
        while (len != 0 && tvb_offset_exists(tvb, next_offset)) {
          c = tvb_get_uint8(tvb, next_offset);
          next_offset++;        /* skip over that character */
          len--;
          if (c == '\n' || (c == '\0' && last_char_was_cr)) {
            /*
             * LF is a line ending, whether preceded by CR or not.
             * NUL is a line ending if preceded by CR.
             */
            break;
          }
          last_char_was_cr = (c == '\r');
        }
      }
    }

    /*
     * Now compute the length of the line *including* the end-of-line
     * indication, if any; we display it all.
     */
    linelen = next_offset - offset;

    proto_tree_add_item(tree, hf_telnet_data, tvb, offset, linelen, ENC_ASCII);
    offset = next_offset;
  }
}

static unsigned
find_unescaped_iac(tvbuff_t *tvb, unsigned offset, unsigned len)
{
  unsigned iac_offset = offset;

  /* If we find an IAC (0XFF), make sure it is not followed by another 0XFF.
     Such cases indicate that it is not an IAC at all */
  while ((tvb_find_uint8_length(tvb, iac_offset, len, TN_IAC, &iac_offset)) &&
         (tvb_get_uint8(tvb, iac_offset + 1) == TN_IAC))
  {
    iac_offset+=2;
    len = tvb_reported_length_remaining(tvb, iac_offset);
  }
  return iac_offset;
}

/* Dissect client→server decrypted iLO2 payload: scan for IAC+command bytes */
static void
dissect_ilo2_c2s_decrypted(proto_tree *parent_tree, tvbuff_t *tvb, unsigned offset, unsigned len)
{
  proto_tree *tree;
  proto_item *item;
  unsigned    pos = 0;

  item = proto_tree_add_item(parent_tree, hf_telnet_ilo2_decrypted_data, tvb, offset, len, ENC_NA);
  tree = proto_item_add_subtree(item, ett_ilo2_decrypted);

  while (pos < len) {
    if (tvb_get_uint8(tvb, offset + pos) == TN_IAC && (pos + 1) < len) {
      uint8_t cmd = tvb_get_uint8(tvb, offset + pos + 1);
      if (cmd >= ILO2_CMD_MOUSE_MOVE && cmd <= ILO2_CMD_SET_MOUSE_MODE) {
        unsigned cmd_start = pos;
        unsigned cmd_len;
        proto_item *cmd_item;
        proto_tree *cmd_tree;

        switch (cmd) {
        case ILO2_CMD_MOUSE_MOVE:
          cmd_len = 4;
          /* Check for absolute mouse: 0xFF D0 0x40 0xC0 + 4 bytes client coords */
          if ((pos + 9) < len) {
            uint8_t b2 = tvb_get_uint8(tvb, offset + pos + 2);
            uint8_t b3 = tvb_get_uint8(tvb, offset + pos + 3);
            if (b2 == 0x40 && b3 == 0xC0) {
              cmd_len = 10;
            }
          }
          break;
        case ILO2_CMD_BTN_PRESS:
        case ILO2_CMD_BTN_RELEASE:
          cmd_len = 3;
          break;
        case ILO2_CMD_BTN_CLICK:
          cmd_len = 4;
          break;
        case ILO2_CMD_RAW_BYTE:
          cmd_len = 3;
          break;
        case ILO2_CMD_SET_MOUSE_MODE:
          cmd_len = 3;
          break;
        default:
          cmd_len = 2;
          break;
        }

        /* Don't go past the buffer */
        if (cmd_start + cmd_len > len)
          cmd_len = len - cmd_start;

        cmd_tree = proto_tree_add_subtree_format(tree, tvb, offset + cmd_start, cmd_len,
                                          ett_ilo2_cmd, &cmd_item,
                                          "%s", val_to_str_const(cmd, ilo2_cmd_vals, "Unknown"));
        proto_tree_add_item(cmd_tree, hf_telnet_ilo2_cmd, tvb, offset + cmd_start, 1, ENC_NA);

        if (cmd == ILO2_CMD_MOUSE_MOVE && cmd_len >= 4) {
          int8_t dx = (int8_t)tvb_get_uint8(tvb, offset + cmd_start + 2);
          int8_t dy = (int8_t)tvb_get_uint8(tvb, offset + cmd_start + 3);
          proto_tree_add_item(cmd_tree, hf_telnet_ilo2_mouse_dx, tvb, offset + cmd_start + 2, 1, ENC_NA);
          proto_tree_add_item(cmd_tree, hf_telnet_ilo2_mouse_dy, tvb, offset + cmd_start + 3, 1, ENC_NA);
          if (cmd_len >= 10) {
            uint16_t cx = tvb_get_ntohs(tvb, offset + cmd_start + 4);
            uint16_t cy = tvb_get_ntohs(tvb, offset + cmd_start + 6);
            proto_tree_add_item(cmd_tree, hf_telnet_ilo2_mouse_client_x, tvb, offset + cmd_start + 4, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(cmd_tree, hf_telnet_ilo2_mouse_client_y, tvb, offset + cmd_start + 6, 2, ENC_BIG_ENDIAN);
            proto_item_append_text(cmd_item, "  abs(%u, %u)", cx, cy);
          } else {
            proto_item_append_text(cmd_item, "  rel(%d, %d)", dx, dy);
          }
        } else if ((cmd == ILO2_CMD_BTN_PRESS || cmd == ILO2_CMD_BTN_RELEASE || cmd == ILO2_CMD_BTN_CLICK) && cmd_len >= 3) {
          uint8_t mask = tvb_get_uint8(tvb, offset + cmd_start + 2);
          proto_tree_add_item(cmd_tree, hf_telnet_ilo2_button_mask, tvb, offset + cmd_start + 2, 1, ENC_NA);
          proto_item_append_text(cmd_item, "  0x%02X%s%s%s", mask,
                                 (mask & 0x04) ? " Left" : "",
                                 (mask & 0x02) ? " Center" : "",
                                 (mask & 0x01) ? " Right" : "");
          if (cmd == ILO2_CMD_BTN_CLICK && cmd_len >= 4) {
            proto_tree_add_item(cmd_tree, hf_telnet_ilo2_click_count, tvb, offset + cmd_start + 3, 1, ENC_NA);
          }
        } else if (cmd == ILO2_CMD_RAW_BYTE && cmd_len >= 3) {
          proto_tree_add_item(cmd_tree, hf_telnet_ilo2_raw_byte, tvb, offset + cmd_start + 2, 1, ENC_NA);
        } else if (cmd == ILO2_CMD_SET_MOUSE_MODE && cmd_len >= 3) {
          uint8_t mode = tvb_get_uint8(tvb, offset + cmd_start + 2);
          proto_tree_add_item(cmd_tree, hf_telnet_ilo2_mouse_mode, tvb, offset + cmd_start + 2, 1, ENC_NA);
          proto_item_append_text(cmd_item, " (%s)", val_to_str_const(mode, ilo2_mouse_mode_vals, "Unknown"));
        }

        pos += cmd_len;
        continue;
      }
    }
    pos++;
  }
}

/* Dissect server→client decrypted iLO2 payload */
static void
dissect_ilo2_s2c_decrypted(proto_tree *parent_tree, tvbuff_t *tvb, unsigned offset, unsigned len,
                           ilo2_conv_info_t *ilo2, packet_info *pinfo)
{
  proto_tree *tree;
  proto_item *item;
  unsigned    i;
  unsigned    printable_count = 0;
  unsigned    escbracket_count = 0;
  bool        has_esc_r = false;

  /* Check for ESC [ R / ESC [ r in the data to detect DVC mode entry */
  for (i = 0; i + 2 < len; i++) {
    uint8_t b0 = tvb_get_uint8(tvb, offset + i);
    uint8_t b1 = tvb_get_uint8(tvb, offset + i + 1);
    uint8_t b2 = tvb_get_uint8(tvb, offset + i + 2);
    if (b0 == 0x1B && b1 == '[' && (b2 == 'R' || b2 == 'r')) {
      has_esc_r = true;
      ilo2->dvc_active = true;
      break;
    }
  }

  /* Count printable characters */
  for (i = 0; i < len; i++) {
    uint8_t c = tvb_get_uint8(tvb, offset + i);
    if (c >= 0x20 && c < 0x7F) {
      printable_count++;
    }
    if (c == 0x1B || c == '[') {
      escbracket_count++;
    }
  }

  /* If DVC was already active or this looks like DVC video data */
  if (ilo2->dvc_active || has_esc_r) {
    item = proto_tree_add_item(parent_tree, hf_telnet_ilo2_decrypted_data, tvb, offset, len, ENC_NA);
    tree = proto_item_add_subtree(item, ett_ilo2_decrypted);

    /* Find ESC [ R/r position */
    unsigned dvc_start = 0;
    if (has_esc_r) {
      for (i = 0; i + 2 < len; i++) {
        uint8_t b0 = tvb_get_uint8(tvb, offset + i);
        uint8_t b1 = tvb_get_uint8(tvb, offset + i + 1);
        uint8_t b2 = tvb_get_uint8(tvb, offset + i + 2);
        if (b0 == 0x1B && b1 == '[' && (b2 == 'R' || b2 == 'r')) {
          dvc_start = i + 3;
          break;
        }
      }
    }

    /* Show any pre-DVC text */
    if (dvc_start > 0) {
      proto_tree_add_bytes_format(tree, hf_telnet_ilo2_decrypted_data,
                                 tvb, offset, dvc_start, NULL,
                                 "Pre-DVC text (%u bytes)", dvc_start);
      uint8_t mode_char = tvb_get_uint8(tvb, offset + dvc_start - 1);
      proto_tree_add_bytes_format(tree, hf_telnet_ilo2_decrypted_data,
                                 tvb, offset + dvc_start - 1, 3, NULL,
                                 "DVC Mode Entry: ESC[%c",
                                 mode_char == 'R' ? 'R' : 'r');
    }

    /* Show DVC bitstream data */
    if (dvc_start < len) {
      ilo2->dvc_active = true;
      proto_tree_add_bytes_format(tree, hf_telnet_ilo2_dvc_video,
                                  tvb, offset + dvc_start, len - dvc_start, NULL,
                                  "DVC Video Bitstream (%u bytes)", len - dvc_start);
    }
  } else if ((len > 100 && printable_count < len / 4) ||
             (len >= 10 && printable_count < len / 2 && escbracket_count == 0)) {
    /* Large binary data with few printable chars - likely DVC bitstream */
    ilo2->dvc_active = true;
    item = proto_tree_add_item(parent_tree, hf_telnet_ilo2_decrypted_data, tvb, offset, len, ENC_NA);
    tree = proto_item_add_subtree(item, ett_ilo2_decrypted);
    proto_tree_add_bytes_format(tree, hf_telnet_ilo2_dvc_video,
                                tvb, offset, len, NULL,
                                "DVC Video Bitstream (%u bytes)", len);
  } else if (printable_count > 0 && (printable_count * 3 > len)) {
    /* Mostly printable text */
    char *text = (char *)wmem_alloc(pinfo->pool, len + 1);
    tvb_memcpy(tvb, (uint8_t *)text, offset, len);
    text[len] = '\0';
    item = proto_tree_add_item(parent_tree, hf_telnet_ilo2_decrypted_text, tvb, offset, len, ENC_NA);
    tree = proto_item_add_subtree(item, ett_ilo2_decrypted);
    proto_tree_add_string(tree, hf_telnet_ilo2_decrypted_text, tvb, offset, len, text);
  } else {
    /* Binary data */
    item = proto_tree_add_item(parent_tree, hf_telnet_ilo2_decrypted_data, tvb, offset, len, ENC_NA);
  }
}

/* Scan raw server→client data for ESC [ R (DVC mode entry) BEFORE decryption.
 * If found: show pre-ESC [ R as plaintext, show ESC [ R as mode entry,
 * decrypt post-ESC [ R with RC4, and set server_encryption_active.
 * Returns true if ESC [ R was found and data was handled. */
static bool
handle_s2c_esc_r_raw(tvbuff_t *tvb, proto_tree *tree, int offset, unsigned len,
                     ilo2_conv_info_t *ilo2, packet_info *pinfo)
{
  uint8_t *raw;
  unsigned esc_r_pos = (unsigned)-1;
  unsigned i;

  if (ilo2_is_from_client(pinfo, ilo2) || ilo2->server_encryption_active)
    return false;

  raw = (uint8_t *)wmem_alloc(pinfo->pool, len);
  tvb_memcpy(tvb, raw, offset, len);

  for (i = 0; i + 2 < len; i++) {
    if (raw[i] == 0x1B && raw[i + 1] == '[' && (raw[i + 2] == 'R' || raw[i + 2] == 'r')) {
      esc_r_pos = i;
      break;
    }
  }

  if (esc_r_pos == (unsigned)-1)
    return false;

  {
    unsigned pre_len = esc_r_pos;
    unsigned post_start = esc_r_pos + 3;
    unsigned post_len = len - post_start;

    /* Show any pre-ESC [ R plaintext text */
    if (pre_len > 0) {
      char *text = (char *)wmem_alloc(pinfo->pool, pre_len + 1);
      memcpy(text, raw, pre_len);
      text[pre_len] = '\0';
      proto_tree_add_string(tree, hf_telnet_ilo2_decrypted_text, tvb, offset, pre_len, text);
    }

    /* Show ESC [ R as DVC mode entry */
    proto_tree_add_bytes_format(tree, hf_telnet_ilo2_decrypted_data,
                               tvb, offset + esc_r_pos, 3, NULL,
                               "DVC Mode Entry: ESC[%c", raw[esc_r_pos + 2]);

    /* Decrypt and dissect post-ESC [ R data */
    if (post_len > 0) {
      uint8_t *decrypted = (uint8_t *)wmem_alloc(pinfo->pool, post_len);
      tvbuff_t *decrypted_tvb;
      memcpy(decrypted, raw + post_start, post_len);
      ilo2_rc4_decrypt(&ilo2->server_rc4, decrypted, post_len);
      decrypted_tvb = tvb_new_real_data(decrypted, post_len, post_len);
      tvb_set_child_real_data_tvbuff(tvb, decrypted_tvb);
      proto_tree_add_bytes_format(tree, hf_telnet_ilo2_encrypted_data,
                                 tvb, offset + post_start, post_len, NULL,
                                 "Encrypted data (%u bytes)", post_len);
      dissect_ilo2_s2c_decrypted(tree, decrypted_tvb, 0, post_len, ilo2, pinfo);
    }

    ilo2->server_encryption_active = true;
  }
  return true;
}

static int
dissect_telnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree *telnet_tree, *ti;
  tvbuff_t   *next_tvb;
  int         offset    = 0;
  unsigned    len       = 0;
  unsigned    is_tn3270 = 0;
  unsigned    is_tn5250 = 0;
  int         data_len;
  int         iac_offset;
  unsigned    num_info_items = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TELNET");
  col_set_str(pinfo->cinfo, COL_INFO, "Telnet Data" UTF8_HORIZONTAL_ELLIPSIS);

  is_tn3270 = find_tn3270_conversation(pinfo);
  is_tn5250 = find_tn5250_conversation(pinfo);

  ti = proto_tree_add_item(tree, proto_telnet, tvb, offset, -1, ENC_NA);
  telnet_tree = proto_item_add_subtree(ti, ett_telnet);

  /*
   * Scan through the buffer looking for an IAC byte.
   */
  while ((len = tvb_reported_length_remaining(tvb, offset)) > 0) {
    ilo2_conv_info_t *ilo2 = ilo2_get_session(pinfo);
    bool from_client = ilo2_is_from_client(pinfo, ilo2);

    /* If encryption is active for this direction, all bytes are encrypted -
     * no IAC bytes exist in the stream. Skip scanning and decrypt all.
     * Exception: server→client may contain plaintext ESC [ R which signals
     * DVC mode entry — detect it in the raw data before decrypting. */
    if ((from_client && ilo2->client_encryption_active) ||
        (!from_client && ilo2->server_encryption_active)) {
      /* For server→client: check if raw data contains ESC [ R (plaintext) */
      if (!from_client) {
        bool found_esc_r = false;
        unsigned esc_r_pos = 0;
        {
          uint8_t *raw_check = (uint8_t *)wmem_alloc(pinfo->pool, len);
          unsigned k;
          tvb_memcpy(tvb, raw_check, offset, len);
          for (k = 0; k + 2 < len; k++) {
            if (raw_check[k] == 0x1B && raw_check[k+1] == '[' &&
                (raw_check[k+2] == 'R' || raw_check[k+2] == 'r')) {
              found_esc_r = true;
              esc_r_pos = k;
              break;
            }
          }
        }

        if (found_esc_r) {
          /* Split: decrypt pre-ESC [ R, show ESC [ R as plaintext, decrypt post */
          unsigned pre_len = esc_r_pos;
          unsigned post_start = esc_r_pos + 3;
          unsigned post_len = len - post_start;

          add_telnet_data_bytes_str(pinfo, &num_info_items, len);

          /* Decrypt and show pre-ESC [ R data */
          if (pre_len > 0) {
            uint8_t *decrypted = (uint8_t *)wmem_alloc(pinfo->pool, pre_len);
            tvbuff_t *decrypted_tvb;
            tvb_memcpy(tvb, decrypted, offset, pre_len);
            ilo2_rc4_decrypt(&ilo2->server_rc4, decrypted, pre_len);
            decrypted_tvb = tvb_new_real_data(decrypted, pre_len, pre_len);
            tvb_set_child_real_data_tvbuff(tvb, decrypted_tvb);
            proto_tree_add_bytes_format(telnet_tree, hf_telnet_ilo2_encrypted_data,
                                       tvb, offset, pre_len, NULL, "Encrypted data (%u bytes)", pre_len);
            dissect_ilo2_s2c_decrypted(telnet_tree, decrypted_tvb, 0, pre_len, ilo2, pinfo);
          }

          /* Show ESC [ R as plaintext DVC mode entry */
          {
            uint8_t esc_byte = tvb_get_uint8(tvb, offset + esc_r_pos + 2);
            proto_tree_add_bytes_format(telnet_tree, hf_telnet_ilo2_decrypted_data,
                                       tvb, offset + esc_r_pos, 3, NULL,
                                       "DVC Mode Entry: ESC[%c (plaintext)",
                                       esc_byte == 'R' ? 'R' : 'r');
          }

          /* Decrypt and show post-ESC [ R data */
          if (post_len > 0) {
            uint8_t *decrypted = (uint8_t *)wmem_alloc(pinfo->pool, post_len);
            tvbuff_t *decrypted_tvb;
            tvb_memcpy(tvb, decrypted, offset + post_start, post_len);
            ilo2_rc4_decrypt(&ilo2->server_rc4, decrypted, post_len);
            decrypted_tvb = tvb_new_real_data(decrypted, post_len, post_len);
            tvb_set_child_real_data_tvbuff(tvb, decrypted_tvb);
            proto_tree_add_bytes_format(telnet_tree, hf_telnet_ilo2_encrypted_data,
                                       tvb, offset + post_start, post_len, NULL,
                                       "Encrypted data (%u bytes)", post_len);
            dissect_ilo2_s2c_decrypted(telnet_tree, decrypted_tvb, 0, post_len, ilo2, pinfo);
          }

          ilo2->dvc_active = true;
          offset += len;
          break;
        }
      }

      /* Normal path: decrypt all bytes */
      add_telnet_data_bytes_str(pinfo, &num_info_items, len);
      {
        uint8_t *decrypted = (uint8_t *)wmem_alloc(pinfo->pool, len);
        tvbuff_t *decrypted_tvb;
        tvb_memcpy(tvb, decrypted, offset, len);
        if (from_client) {
          ilo2_rc4_decrypt(&ilo2->client_rc4, decrypted, len);
        } else {
          ilo2_rc4_decrypt(&ilo2->server_rc4, decrypted, len);
        }
        decrypted_tvb = tvb_new_real_data(decrypted, len, len);
        tvb_set_child_real_data_tvbuff(tvb, decrypted_tvb);
        proto_tree_add_bytes_format(telnet_tree, hf_telnet_ilo2_encrypted_data,
                                   tvb, offset, len, NULL, "Encrypted data (%u bytes)", len);
        /* Dissect the decrypted payload */
        if (from_client) {
          dissect_ilo2_c2s_decrypted(telnet_tree, decrypted_tvb, 0, len);
        } else {
          dissect_ilo2_s2c_decrypted(telnet_tree, decrypted_tvb, 0, len, ilo2, pinfo);
        }
      }
      offset += len;
      break;
    }

    iac_offset = find_unescaped_iac(tvb, offset, len);
    if (iac_offset != -1) {
      /*
       * We found an IAC byte.
       * If there's any data before it, add that data to the
       * tree, a line at a time.
       */
      data_len = iac_offset - offset;
      if (data_len > 0) {
        add_telnet_data_bytes_str(pinfo, &num_info_items, data_len);
        if (is_tn3270) {
          next_tvb = tvb_new_subset_length(tvb, offset, data_len);
          call_dissector(tn3270_handle, next_tvb, pinfo, telnet_tree);
        } else if (is_tn5250) {
          next_tvb = tvb_new_subset_length(tvb, offset, data_len);
          call_dissector(tn5250_handle, next_tvb, pinfo, telnet_tree);
        } else if (ilo2->encrypt_enabled && data_len > 0) {
          /* Server→client: scan for ESC [ R in raw plaintext before decrypting */
          if (handle_s2c_esc_r_raw(tvb, telnet_tree, offset, data_len, ilo2, pinfo)) {
            /* ESC [ R found, data handled and encryption activated */
          } else if (ilo2_is_from_client(pinfo, ilo2) || ilo2->server_encryption_active) {
            /* Client→server or encryption already active — decrypt all */
            uint8_t *decrypted = (uint8_t *)wmem_alloc(pinfo->pool, data_len);
            tvbuff_t *decrypted_tvb;
            tvb_memcpy(tvb, decrypted, offset, data_len);
            if (ilo2_is_from_client(pinfo, ilo2)) {
              ilo2_rc4_decrypt(&ilo2->client_rc4, decrypted, data_len);
            } else {
              ilo2_rc4_decrypt(&ilo2->server_rc4, decrypted, data_len);
            }
            decrypted_tvb = tvb_new_real_data(decrypted, data_len, data_len);
            tvb_set_child_real_data_tvbuff(tvb, decrypted_tvb);
            proto_tree_add_bytes_format(telnet_tree, hf_telnet_ilo2_encrypted_data,
                                       tvb, offset, data_len, NULL, "Encrypted data (%u bytes)", data_len);
            /* Dissect the decrypted payload */
            if (ilo2_is_from_client(pinfo, ilo2)) {
              dissect_ilo2_c2s_decrypted(telnet_tree, decrypted_tvb, 0, data_len);
            } else {
              dissect_ilo2_s2c_decrypted(telnet_tree, decrypted_tvb, 0, data_len, ilo2, pinfo);
            }
          } else {
            /* Server→client, no ESC [ R yet — plain text (e.g., "Login Name: ") */
            telnet_add_text(telnet_tree, tvb, offset, data_len);
          }
        } else {
          telnet_add_text(telnet_tree, tvb, offset, data_len);
        }
      }
      /*
       * Now interpret the command.
       */
      offset = telnet_command(pinfo, telnet_tree, tvb, iac_offset, &num_info_items);
    } else {
      /* get more data if tn3270 */
      if (is_tn3270 || is_tn5250) {
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
        return tvb_captured_length(tvb);
      }
      /*
       * We found no IAC byte, so what remains in the buffer
       * is the last of the data in the packet.
       * Add it to the tree, a line at a time, and then quit.
       */
      if (len > 0) {
        add_telnet_data_bytes_str(pinfo, &num_info_items, len);
        if (ilo2->encrypt_enabled && len > 0) {
          /* Server→client: scan for ESC [ R in raw plaintext before decrypting */
          if (handle_s2c_esc_r_raw(tvb, telnet_tree, offset, len, ilo2, pinfo)) {
            /* ESC [ R found, data handled and encryption activated */
          } else if (ilo2_is_from_client(pinfo, ilo2) || ilo2->server_encryption_active) {
            /* Client→server or encryption already active — decrypt all */
            uint8_t *decrypted = (uint8_t *)wmem_alloc(pinfo->pool, len);
            tvbuff_t *decrypted_tvb;
            tvb_memcpy(tvb, decrypted, offset, len);
            if (ilo2_is_from_client(pinfo, ilo2)) {
              ilo2_rc4_decrypt(&ilo2->client_rc4, decrypted, len);
            } else {
              ilo2_rc4_decrypt(&ilo2->server_rc4, decrypted, len);
            }
            decrypted_tvb = tvb_new_real_data(decrypted, len, len);
            tvb_set_child_real_data_tvbuff(tvb, decrypted_tvb);
            proto_tree_add_bytes_format(telnet_tree, hf_telnet_ilo2_encrypted_data,
                                       tvb, offset, len, NULL, "Encrypted data (%u bytes)", len);
            if (ilo2_is_from_client(pinfo, ilo2)) {
              dissect_ilo2_c2s_decrypted(telnet_tree, decrypted_tvb, 0, len);
            } else {
              dissect_ilo2_s2c_decrypted(telnet_tree, decrypted_tvb, 0, len, ilo2, pinfo);
            }
          } else {
            /* Server→client, no ESC [ R yet — plain text (e.g., "Login Name: ") */
            telnet_add_text(telnet_tree, tvb, offset, len);
          }
        } else {
          telnet_add_text(telnet_tree, tvb, offset, len);
        }
      }
      break;
    }
  }
  return tvb_captured_length(tvb);
}

void
proto_register_telnet(void)
{
  static hf_register_info hf[] = {
    { &hf_telnet_cmd,
      { "Command", "telnet.cmd", FT_UINT8, BASE_DEC,
        VALS(cmd_vals), 0, NULL, HFILL }
    },
    { &hf_telnet_subcmd,
      { "Subcommand", "telnet.subcmd", FT_UINT8, BASE_DEC,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_auth_name,
      { "Name", "telnet.auth.name", FT_STRING, BASE_NONE,
        NULL, 0, "Name of user being authenticated", HFILL }
    },
    { &hf_telnet_auth_cmd,
      { "Auth Cmd", "telnet.auth.cmd", FT_UINT8, BASE_DEC,
        VALS(auth_cmd_vals), 0, "Authentication Command", HFILL }
    },
    { &hf_telnet_auth_type,
      { "Auth Type", "telnet.auth.type", FT_UINT8, BASE_DEC,
        VALS(auth_type_vals), 0, "Authentication Type", HFILL }
    },
    { &hf_telnet_auth_mod_cred_fwd,
      { "Cred Fwd", "telnet.auth.mod.cred_fwd", FT_BOOLEAN, 8,
        TFS(&auth_mod_cred_fwd), 0x08, "Modifier: Whether client will forward creds or not", HFILL }
    },
    { &hf_telnet_auth_mod_who,
      { "Who", "telnet.auth.mod.who", FT_BOOLEAN, 8,
        TFS(&tfs_s2c_c2s), 0x01, "Modifier: Who will authenticate", HFILL }
    },
    { &hf_telnet_auth_mod_how,
      { "How", "telnet.auth.mod.how", FT_BOOLEAN, 8,
        TFS(&auth_mod_how), 0x02, "Modifier: Authentication flow", HFILL }
    },
    { &hf_telnet_auth_mod_enc,
      { "Encrypt", "telnet.auth.mod.enc", FT_UINT8, BASE_DEC,
        VALS(auth_mod_enc), 0x14, "Modifier: How to enable Encryption", HFILL }
    },
    { &hf_telnet_auth_krb5_type,
      { "Command", "telnet.auth.krb5.cmd", FT_UINT8, BASE_DEC,
        VALS(auth_krb5_types), 0, "Krb5 Authentication sub-command", HFILL }
    },
    { &hf_telnet_auth_ssl_status,
      { "Status", "telnet.auth.ssl.status", FT_UINT8, BASE_DEC,
        VALS(ssl_auth_status), 0, "SSL authentication status", HFILL }
    },
    { &hf_telnet_auth_data,
      { "Authentication data", "telnet.auth.data", FT_BYTES, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_string_subopt_value,
      { "Value", "telnet.string_subopt.value", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_naws_subopt_width,
      { "Width", "telnet.naws_subopt.width", FT_UINT16, BASE_DEC,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_naws_subopt_height,
      { "Height", "telnet.naws_subopt.height", FT_UINT16, BASE_DEC,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_outmark_subopt_cmd,
      { "Command", "telnet.outmark_subopt.cmd", FT_CHAR, BASE_HEX,
        VALS(telnet_outmark_subopt_cmd_vals), 0, NULL, HFILL }
    },
    { &hf_telnet_outmark_subopt_banner,
      { "Banner", "telnet.outmark_subopt.banner", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_comport_subopt_signature,
      { "Signature", "telnet.comport_subopt.signature", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_comport_subopt_baud_rate,
      { "Baud Rate", "telnet.comport_subopt.baud_rate", FT_UINT32, BASE_DEC,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_comport_subopt_data_size,
      { "Data Size", "telnet.comport_subopt.data_size", FT_UINT8, BASE_DEC,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_comport_subopt_parity,
      { "Parity", "telnet.comport_subopt.parity", FT_UINT16, BASE_DEC,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_comport_subopt_stop,
      { "Stop Bits", "telnet.comport_subopt.stop", FT_UINT16, BASE_DEC,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_comport_subopt_control,
      { "Control", "telnet.comport_subopt.control", FT_UINT16, BASE_DEC,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_comport_linestate,
      { "Linestate", "telnet.comport_subopt.linestate", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_comport_set_linestate_mask,
      { "Set Linestate Mask", "telnet.comport_subopt.set_linestate_mask", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_comport_modemstate,
      { "Modemstate", "telnet.comport_subopt.modemstate", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_comport_set_modemstate_mask,
      { "Set Modemstate Mask", "telnet.comport_subopt.set_modemstate_mask", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_comport_subopt_flow_control_suspend,
      { "Flow Control Suspend", "telnet.comport_subopt.flow_control_suspend", FT_NONE, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_comport_subopt_flow_control_resume,
      { "Flow Control Resume", "telnet.comport_subopt.flow_control_resume", FT_NONE, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_comport_subopt_purge,
      { "Purge", "telnet.comport_subopt.purge", FT_UINT16, BASE_DEC,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_rfc_subopt_cmd,
      { "Command", "telnet.rfc_subopt.cmd", FT_UINT8, BASE_DEC,
        VALS(rfc_opt_vals), 0, NULL, HFILL }
    },
    { &hf_telnet_tabstop,
      { "Tabstop value", "telnet.tabstop", FT_UINT8, BASE_DEC,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_enc_cmd,
      { "Enc Cmd", "telnet.enc.cmd", FT_UINT8, BASE_DEC,
        VALS(enc_cmd_vals), 0, "Encryption command", HFILL }
    },
    { &hf_telnet_enc_type,
      { "Enc Type", "telnet.enc.type", FT_UINT8, BASE_DEC,
        VALS(enc_type_vals), 0, "Encryption type", HFILL }
    },
    { &hf_telnet_enc_type_data,
      { "Type-specific data", "telnet.enc.type_data", FT_BYTES, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_enc_key_id,
      { "Key ID", "telnet.enc.key_id", FT_BYTES, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_data,
      { "Data", "telnet.data", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_option_data,
      { "Option data", "telnet.option_data", FT_BYTES, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_subcommand_data,
      { "Subcommand data", "telnet.subcommand_data", FT_BYTES, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_tn3270_subopt,
      { "Suboption", "telnet.tn3270.subopt", FT_UINT8, BASE_DEC,
        VALS(tn3270_subopt_vals), 0, NULL, HFILL }
    },
    { &hf_tn3270_connect,
      { "Connect", "telnet.tn3270.connect", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_tn3270_is,
      { "Is", "telnet.tn3270.is", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_tn3270_request_string,
      { "Request", "telnet.tn3270.request_string", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_tn3270_reason,
      { "Reason", "telnet.tn3270.reason", FT_UINT8, BASE_DEC,
        VALS(tn3270_reason_vals), 0, NULL, HFILL }
    },
    { &hf_tn3270_request,
      { "Request", "telnet.tn3270.request", FT_UINT8, BASE_DEC,
        VALS(tn3270_request_vals), 0, NULL, HFILL }
    },
    { &hf_tn3270_regime_subopt_value,
      { "Value", "telnet.tn3270.regime_subopt.value", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_tn3270_regime_cmd,
      { "Cmd", "telnet.regime_cmd", FT_UINT8, BASE_DEC,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_starttls,
      { "Follows", "telnet.starttls", FT_UINT8, BASE_DEC,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_vmware_cmd,
      { "VMware Serial Port Proxy Cmd", "telnet.vmware.cmd", FT_UINT8, BASE_DEC,
        VALS(vmware_cmd_vals), 0, "VMware command", HFILL }
    },
    { &hf_telnet_vmware_known_suboption_code,
      { "Suboption", "telnet.vmware.known_suboption_code", FT_UINT8, BASE_DEC,
        VALS(vmware_cmd_vals), 0, NULL, HFILL }
    },
    { &hf_telnet_vmware_unknown_subopt_code,
      { "Code", "telnet.vmware.unknown_suboption_code", FT_UINT8, BASE_DEC,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_vmware_vmotion_sequence,
      { "vMotion sequence", "telnet.vmware.vmotion.sequence", FT_BYTES, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_vmware_vmotion_secret,
      { "vMotion secret", "telnet.vmware.vmotion.secret", FT_BYTES, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_vmware_proxy_direction,
      { "Proxy Direction", "telnet.vmware.proxy.direction", FT_CHAR, BASE_HEX,
        VALS(vmware_proxy_direction_vals), 0, NULL, HFILL }
    },
    { &hf_telnet_vmware_proxy_serviceUri,
      { "Proxy Service URI", "telnet.vmware.proxy.serviceUri", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_vmware_vm_vc_uuid,
      { "VM VC UUID", "telnet.vmware.vm.vc_uuid", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_vmware_vm_bios_uuid,
      { "VM BIOS UUID", "telnet.vmware.vm.bios_uuid", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_vmware_vm_location_uuid,
      { "VM Location UUID", "telnet.vmware.vm.location_uuid", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_vmware_vm_name,
      { "VM name", "telnet.vmware.vm.name", FT_STRING, BASE_NONE,
        NULL, 0, NULL, HFILL }
    },
    { &hf_telnet_ilo2_cmd,
      { "iLO2 Command", "telnet.ilo2.cmd", FT_UINT8, BASE_HEX,
        VALS(ilo2_cmd_vals), 0, "HP iLO2 Command", HFILL }
    },
    { &hf_telnet_ilo2_key_index,
      { "Key Index", "telnet.ilo2.key_index", FT_UINT32, BASE_HEX,
        NULL, 0, "HP iLO2 Encryption Key Index", HFILL }
    },
    { &hf_telnet_ilo2_encrypted_data,
      { "Encrypted Data", "telnet.ilo2.encrypted_data", FT_BYTES, BASE_NONE,
        NULL, 0, "HP iLO2 Encrypted Data", HFILL }
    },
    { &hf_telnet_ilo2_decrypted_data,
      { "Decrypted Data", "telnet.ilo2.decrypted_data", FT_BYTES, BASE_NONE,
        NULL, 0, "HP iLO2 Decrypted Data", HFILL }
    },
    { &hf_telnet_ilo2_mouse_dx,
      { "Mouse DX", "telnet.ilo2.mouse_dx", FT_INT8, BASE_DEC,
        NULL, 0, "HP iLO2 Mouse Delta X", HFILL }
    },
    { &hf_telnet_ilo2_mouse_dy,
      { "Mouse DY", "telnet.ilo2.mouse_dy", FT_INT8, BASE_DEC,
        NULL, 0, "HP iLO2 Mouse Delta Y", HFILL }
    },
    { &hf_telnet_ilo2_mouse_client_x,
      { "Client X", "telnet.ilo2.mouse_client_x", FT_UINT16, BASE_DEC,
        NULL, 0, "HP iLO2 Mouse Absolute Client X", HFILL }
    },
    { &hf_telnet_ilo2_mouse_client_y,
      { "Client Y", "telnet.ilo2.mouse_client_y", FT_UINT16, BASE_DEC,
        NULL, 0, "HP iLO2 Mouse Absolute Client Y", HFILL }
    },
    { &hf_telnet_ilo2_button_mask,
      { "Button Mask", "telnet.ilo2.button_mask", FT_UINT8, BASE_HEX,
        NULL, 0, "HP iLO2 Mouse Button Mask", HFILL }
    },
    { &hf_telnet_ilo2_click_count,
      { "Click Count", "telnet.ilo2.click_count", FT_UINT8, BASE_DEC,
        NULL, 0, "HP iLO2 Mouse Click Count", HFILL }
    },
    { &hf_telnet_ilo2_raw_byte,
      { "Raw Byte", "telnet.ilo2.raw_byte", FT_UINT8, BASE_HEX,
        NULL, 0, "HP iLO2 Raw Mouse Byte", HFILL }
    },
    { &hf_telnet_ilo2_mouse_mode,
      { "Mouse Mode", "telnet.ilo2.mouse_mode", FT_UINT8, BASE_DEC,
        VALS(ilo2_mouse_mode_vals), 0, "HP iLO2 Mouse Mode", HFILL }
    },
    { &hf_telnet_ilo2_decrypted_text,
      { "Decrypted Text", "telnet.ilo2.decrypted_text", FT_STRING, BASE_NONE,
        NULL, 0, "HP iLO2 Decrypted Text Data", HFILL }
    },
    { &hf_telnet_ilo2_dvc_video,
      { "DVC Video", "telnet.ilo2.dvc_video", FT_BYTES, BASE_NONE,
        NULL, 0, "HP iLO2 DVC Video Bitstream", HFILL }
    },
  };
  static int *ett[] = {
    &ett_telnet,
    &ett_telnet_cmd,
    &ett_telnet_subopt,
    &ett_status_subopt,
    &ett_rcte_subopt,
    &ett_olw_subopt,
    &ett_ops_subopt,
    &ett_crdisp_subopt,
    &ett_htstops_subopt,
    &ett_htdisp_subopt,
    &ett_ffdisp_subopt,
    &ett_vtstops_subopt,
    &ett_vtdisp_subopt,
    &ett_lfdisp_subopt,
    &ett_extasc_subopt,
    &ett_bytemacro_subopt,
    &ett_det_subopt,
    &ett_supdupout_subopt,
    &ett_sendloc_subopt,
    &ett_termtype_subopt,
    &ett_tacacsui_subopt,
    &ett_outmark_subopt,
    &ett_tlocnum_subopt,
    &ett_tn3270reg_subopt,
    &ett_x3pad_subopt,
    &ett_naws_subopt,
    &ett_tspeed_subopt,
    &ett_rfc_subopt,
    &ett_linemode_subopt,
    &ett_xdpyloc_subopt,
    &ett_env_subopt,
    &ett_auth_subopt,
    &ett_enc_subopt,
    &ett_newenv_subopt,
    &ett_tn3270e_subopt,
    &ett_xauth_subopt,
    &ett_charset_subopt,
    &ett_rsp_subopt,
    &ett_comport_subopt,
    &ett_starttls_subopt,
    &ett_ilo2,
    &ett_ilo2_cmd,
    &ett_ilo2_decrypted,
  };

  static ei_register_info ei[] = {
      { &ei_telnet_invalid_subcommand, { "telnet.invalid_subcommand", PI_PROTOCOL, PI_WARN, "Invalid subcommand", EXPFILL }},
      { &ei_telnet_invalid_baud_rate, { "telnet.invalid_baud_rate", PI_PROTOCOL, PI_WARN, "Invalid Baud Rate", EXPFILL }},
      { &ei_telnet_invalid_data_size, { "telnet.invalid_data_size", PI_PROTOCOL, PI_WARN, "Invalid Data Size", EXPFILL }},
      { &ei_telnet_invalid_parity, { "telnet.invalid_parity", PI_PROTOCOL, PI_WARN, "Invalid Parity Packet", EXPFILL }},
      { &ei_telnet_invalid_stop, { "telnet.invalid_stop", PI_PROTOCOL, PI_WARN, "Invalid Stop Packet", EXPFILL }},
      { &ei_telnet_invalid_control, { "telnet.invalid_control", PI_PROTOCOL, PI_WARN, "Invalid Control Packet", EXPFILL }},
      { &ei_telnet_invalid_linestate, { "telnet.invalid_linestate", PI_PROTOCOL, PI_WARN, "Invalid linestate", EXPFILL }},
      { &ei_telnet_invalid_modemstate, { "telnet.invalid_modemstate", PI_PROTOCOL, PI_WARN, "Invalid Modemstate", EXPFILL }},
      { &ei_telnet_invalid_purge, { "telnet.invalid_purge", PI_PROTOCOL, PI_WARN, "Invalid Purge Packet", EXPFILL }},
      { &ei_telnet_enc_cmd_unknown, { "telnet.enc.cmd.unknown", PI_PROTOCOL, PI_WARN, "Unknown encryption command", EXPFILL }},
      { &ei_telnet_suboption_length, { "telnet.suboption_length.invalid", PI_PROTOCOL, PI_WARN, "Bogus suboption data", EXPFILL }},
      { &ei_telnet_vmware_unexp_data, { "telnet.vmware.unexpected_data", PI_PROTOCOL, PI_WARN, "Unexpected VMware Serial Port Proxy negotiation data", EXPFILL }},
  };

  expert_module_t* expert_telnet;

  proto_telnet = proto_register_protocol("Telnet", "TELNET", "telnet");
  proto_register_field_array(proto_telnet, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_telnet = expert_register_protocol(proto_telnet);
  expert_register_field_array(expert_telnet, ei, array_length(ei));

  telnet_handle = register_dissector("telnet", dissect_telnet, proto_telnet);
}

void
proto_reg_handoff_telnet(void)
{
  dissector_add_uint_with_preference("tcp.port", TCP_PORT_TELNET, telnet_handle);

  dissector_add_uint("acdr.tls_application", TLS_APP_TELNET, telnet_handle);

  tn3270_handle = find_dissector_add_dependency("tn3270", proto_telnet);
  tn5250_handle = find_dissector_add_dependency("tn5250", proto_telnet);
  tls_handle = find_dissector("tls");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */

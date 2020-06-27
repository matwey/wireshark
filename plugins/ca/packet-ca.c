/*  This file (packet-ca.c) was created by Ron Rechenmacher <ron@fnal.gov> on
    Mar  4, 2006. "TERMS AND CONDITIONS" governing this file are in the README
    or COPYING file. If you do not have such a file, one can be obtained by
    contacting Ron or Fermi Lab in Batavia IL, 60510, phone: 630-840-3000.
    Minor modification by Kazuro Furukawa <kazuro.furukawa@kek.jp>.
    Support for remaining CA fields by Cosylab.
    Minor modification again by Kazuro Furukawa, Apr.16.2011. 
    $RCSfile: packet-ca.c,v $
    rev="$Revision: 1.11 $$Date: 2006/03/08 18:15:54 $";
*/
/*  ca = EPICS (Experiental Physics and Industrial Control System) Channel
    Access protocol
    Ref. http://epics.cosylab.com/cosyjava/JCA-Common/Documentation/CAproto.html
*/
/*  ref. doc/README.plugins
        AND
        http://ethereal.hostingzero.com/docs/edg_html/#ChapterDissection
*/
/*  Remember the tethereal command:
    tethereal -i lo -c 10 -l -V "( port 5064 or port 5065 ) and not port 49879" 2>&1 | awk '/CA/,/^$/'
    and
    tethereal -i lo -c 50 -l "( port 5064 or port 5065 ) and not port 49879" | grep -v Len=0

    Notes:  -l flushes stdout after each packet
            frame number seems to go to stderr (just with -V)
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <gmodule.h>		/* G_MODULE_EXPORT */
#include <epan/packet.h>	/* packet_info */
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/conversation.h>	/* conversation_t */
#include <epan/emem.h>		/* se_alloc */
//#include <epan/dissectors/packet-frame.h> /* show_reported_bounds_error */

#ifndef IPPROTO_TCP
# include <netinet/in.h>		/* IPPROTO_UDP, IPPROTO_TCP */
#endif
#ifndef IPPORT_USERRESERVED     /* caProto.h needs this for CA_*_PORT defs */
# define IPPORT_USERRESERVED	5000
#endif
#include "caProto.h"		/* from EPICS base; CA_PROTO_VERSION */
#include "db_access.h"		/* from EPICS base (stripped down); DBR_STRING  */
#include "caerr.h"		/* from EPICS base (stripped down); ECA_NORMAL */

#define TEST_FLAG(item, val, flagvals) \
if (try_val_to_str(val, flagvals) == NULL) {	\
	expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Illegal flag value!");	\
	proto_item_append_text(item, " [unknown flag value]"); \
}
#define TEST_ZERO(item, val) \
if (val != 0) {	\
	expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Invalid value! Should be 0!");	\
	proto_item_append_text(item, " [should be 0]"); \
}
#define TEST_GE_ZERO(item, val) \
if (val < 0) {	\
	expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Invalid value! Should be >= 0!");	\
	proto_item_append_text(item, " [should be >= 0]"); \
}
#define TEST_EQ(item, val, expected) \
if (val != expected) {	\
	expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Invalid value! Should be %d!", expected);	\
	proto_item_append_text(item, " [should be %d]", expected); \
}


static int			proto_ca=-1;
static dissector_handle_t	ca_handle;
static guint32 const		global_ca_server_port  =CA_SERVER_PORT;
static guint32 const		global_ca_repeater_port=CA_REPEATER_PORT;

/* desegmentation of messages */
static gboolean			ca_desegment=TRUE;

#define INT_STR( xx )	{ xx, #xx }  /* val,string  */
static value_string const cmdIdNames[]=
    {   INT_STR( CA_PROTO_VERSION ),
	INT_STR( CA_PROTO_EVENT_ADD ),
	INT_STR( CA_PROTO_EVENT_CANCEL ),
	INT_STR( CA_PROTO_READ ),
	INT_STR( CA_PROTO_WRITE ),
	INT_STR( CA_PROTO_SNAPSHOT ),
	INT_STR( CA_PROTO_SEARCH ),
	INT_STR( CA_PROTO_BUILD ),
	INT_STR( CA_PROTO_EVENTS_OFF ),
	INT_STR( CA_PROTO_EVENTS_ON ),
	INT_STR( CA_PROTO_READ_SYNC ),
	INT_STR( CA_PROTO_ERROR ),
	INT_STR( CA_PROTO_CLEAR_CHANNEL ),
	INT_STR( CA_PROTO_RSRV_IS_UP ),
	INT_STR( CA_PROTO_NOT_FOUND ),
	INT_STR( CA_PROTO_READ_NOTIFY ),
	INT_STR( CA_PROTO_READ_BUILD ),
	INT_STR( CA_REPEATER_CONFIRM ),
	INT_STR( CA_PROTO_CREATE_CHAN ),
	INT_STR( CA_PROTO_WRITE_NOTIFY ),
	INT_STR( CA_PROTO_CLIENT_NAME ),
	INT_STR( CA_PROTO_HOST_NAME ),
	INT_STR( CA_PROTO_ACCESS_RIGHTS ),
	INT_STR( CA_PROTO_ECHO ),
	INT_STR( CA_REPEATER_REGISTER ),
	INT_STR( CA_PROTO_SIGNAL ),
	INT_STR( CA_PROTO_CREATE_CH_FAIL ),
	INT_STR( CA_PROTO_SERVER_DISCONN ),
	{ 0,  NULL },
    };
static value_string const dataTypes[]=
    {   INT_STR( DBR_STRING ),
	INT_STR( DBR_INT ),
	INT_STR( DBR_SHORT ),
	INT_STR( DBR_FLOAT ),
	INT_STR( DBR_ENUM ),
	INT_STR( DBR_CHAR ),
	INT_STR( DBR_LONG ),
	INT_STR( DBR_DOUBLE ),
	INT_STR( DBR_STS_STRING ),
	INT_STR( DBR_STS_SHORT ),
	INT_STR( DBR_STS_INT ),
	INT_STR( DBR_STS_FLOAT ),
	INT_STR( DBR_STS_ENUM ),
	INT_STR( DBR_STS_CHAR ),
	INT_STR( DBR_STS_LONG ),
	INT_STR( DBR_STS_DOUBLE ),
	INT_STR( DBR_TIME_STRING ),
	INT_STR( DBR_TIME_INT ),
	INT_STR( DBR_TIME_SHORT ),
	INT_STR( DBR_TIME_FLOAT ),
	INT_STR( DBR_TIME_ENUM ),
	INT_STR( DBR_TIME_CHAR ),
	INT_STR( DBR_TIME_LONG ),
	INT_STR( DBR_TIME_DOUBLE ),
	INT_STR( DBR_GR_STRING ),
	INT_STR( DBR_GR_SHORT ),
	INT_STR( DBR_GR_INT ),
	INT_STR( DBR_GR_FLOAT ),
	INT_STR( DBR_GR_ENUM ),
	INT_STR( DBR_GR_CHAR ),
	INT_STR( DBR_GR_LONG ),
	INT_STR( DBR_GR_DOUBLE ),
	INT_STR( DBR_CTRL_STRING ),
	INT_STR( DBR_CTRL_SHORT ),
	INT_STR( DBR_CTRL_INT ),
	INT_STR( DBR_CTRL_FLOAT ),
	INT_STR( DBR_CTRL_ENUM ),
	INT_STR( DBR_CTRL_CHAR ),
	INT_STR( DBR_CTRL_LONG ),
	INT_STR( DBR_CTRL_DOUBLE ),
	{ 0,  NULL },
    };
/*  value,string pairs from
    http://epics.cosylab.com/cosyjava/JCA-Common/Documentation/CAproto.html#secAccessRights */
static value_string const accessRights[]=
    {   { 0,  "No access" },
	{ 1,  "Read access only" },
	{ 2,  "Write access only" },
	{ 3,  "Read and write access" },
	{ 0,  NULL },
    };
static value_string const monitorMask[]=
    {   { 0,  "" },
	{ 1,  "DBE_VALUE" },
	{ 2,  "DBE_LOG" },
	{ 3,  "DBE_LOG,DBE_VALUE" },
	{ 4,  "DBE_ALARM" },
	{ 5,  "DBE_ALARM,DBE_VALUE" },
	{ 6,  "DBE_ALARM,DBE_LOG" },
	{ 7,  "DBE_ALARM,DBE_LOG,DBE_VALUE" },
	{ 0,  NULL },
    };
static value_string const statusCodes[]=
    {   INT_STR( ECA_NORMAL ),
	INT_STR( ECA_MAXIOC ),
	INT_STR( ECA_UKNHOST ),
	INT_STR( ECA_UKNSERV ),
	INT_STR( ECA_SOCK ),
	INT_STR( ECA_CONN ),
	INT_STR( ECA_ALLOCMEM ),
	INT_STR( ECA_UKNCHAN ),
	INT_STR( ECA_UKNFIELD ),
	INT_STR( ECA_TOLARGE ),
	INT_STR( ECA_TIMEOUT ),
	INT_STR( ECA_NOSUPPORT ),
	INT_STR( ECA_STRTOBIG ),
	INT_STR( ECA_DISCONNCHID ),
	INT_STR( ECA_BADTYPE ),
	INT_STR( ECA_CHIDNOTFND ),
	INT_STR( ECA_CHIDRETRY ),
	INT_STR( ECA_INTERNAL ),
	INT_STR( ECA_DBLCLFAIL ),
	INT_STR( ECA_GETFAIL ),
	INT_STR( ECA_PUTFAIL ),
	INT_STR( ECA_ADDFAIL ),
	INT_STR( ECA_BADCOUNT ),
	INT_STR( ECA_BADSTR ),
	INT_STR( ECA_DISCONN ),
	INT_STR( ECA_DBLCHNL ),
	INT_STR( ECA_EVDISALLOW ),
	INT_STR( ECA_BUILDGET ),
	INT_STR( ECA_NEEDSFP ),
	INT_STR( ECA_OVEVFAIL ),
	INT_STR( ECA_BADMONID ),
	INT_STR( ECA_NEWADDR ),
	INT_STR( ECA_NEWCONN ),
	INT_STR( ECA_NOCACTX ),
	INT_STR( ECA_DEFUNCT ),
	INT_STR( ECA_EMPTYSTR ),
	INT_STR( ECA_NOREPEATER ),
	INT_STR( ECA_NOCHANMSG ),
	INT_STR( ECA_DLCKREST ),
	INT_STR( ECA_SERVBEHIND ),
	INT_STR( ECA_NOCAST ),
	INT_STR( ECA_BADMASK ),
	INT_STR( ECA_IODONE ),
	INT_STR( ECA_IOINPROGRESS ),
	INT_STR( ECA_BADSYNCGRP ),
	INT_STR( ECA_PUTCBINPROG ),
	INT_STR( ECA_NORDACCESS ),
	INT_STR( ECA_NOWTACCESS ),
	INT_STR( ECA_ANACHRONISM ),
	INT_STR( ECA_NOSEARCHADDR ),
	INT_STR( ECA_NOCONVERT ),
	INT_STR( ECA_BADCHID ),
	INT_STR( ECA_BADFUNCPTR ),
	INT_STR( ECA_ISATTACHED ),
	INT_STR( ECA_UNAVAILINSERV ),
	INT_STR( ECA_CHANDESTROY ),
	INT_STR( ECA_BADPRIORITY ),
	INT_STR( ECA_NOTTHREADED ),
	INT_STR( ECA_16KARRAYCLIENT ),
	INT_STR( ECA_CONNSEQTMO ),
	INT_STR( ECA_UNRESPTMO ),
	{ 0,  NULL },
    };
static value_string const searchReplyFlags[]=
    { { 10,  "DO_REPLY" },
	{ 5,  "DONT_REPLY" },
	{ 0xA00,  "DO_REPLY (reversed)" },
	{ 0x500,  "DONT_REPLY (reversed)" },
	{ 0,  NULL },
    };

typedef struct _ca_conv_data	/* ca specific conversation data */
{
    struct _ca_conv_data	*next;
    /* major opcodes including extensions (NULL terminated) */
    value_string		opcode_vals[sizeof(cmdIdNames)]; 
    int				sequencenumber;	/* sequencenumber of current packet.	   */
    guint32			iconn_frame;	/* frame # of initial connection request   */
    guint32			iconn_reply;	/* frame # of initial connection reply     */
    gboolean			resync;  /* resynchronization of sequence number performed */
//	guint8 *chanName; /* channel name */
	GHashTable *cid2cn, *sid2cn, *subid2cn; /* CID/SID/subscriptionID to channel name mappings */

    union
    {
	struct
	{   int	first_keycode;
	} GetKeyboardMapping;
    } request;
} ca_conv_data_t;

static ca_conv_data_t		stateinit;
static ca_conv_data_t		*ca_conv_data_list;

/* these are for the hf_register_info links -- NOT for the data values */
static int			hf_ca_cmdId=-1;
static int			hf_ca_paySz=-1;
static int			hf_ca_datTyp=-1;
static int			hf_ca_datCnt=-1;
static int			hf_ca_parm1=-1;
static int			hf_ca_parm2=-1;
//static int			hf_ca_extendedPaySz=-1;
//static int			hf_ca_extendedDatCnt=-1;
static int			hf_ca_tcpPort=-1;
static int			hf_ca_srvrId=-1;
static int			hf_ca_chnId=-1;
static int			hf_ca_minorVer=-1;
static int			hf_ca_srvrProto=-1;
static int			hf_ca_desiredPrio=-1;
static int			hf_ca_userName=-1;
static int			hf_ca_hostName=-1;
static int			hf_ca_chanName=-1;
static int			hf_ca_accRghts=-1;
static int			hf_ca_ioid=-1;
static int			hf_ca_subscriptionId=-1;
static int			hf_ca_evLoVal=-1;
static int			hf_ca_evHiVal=-1;
static int			hf_ca_evToVal=-1;
static int			hf_ca_evMsk=-1;
static int			hf_ca_status=-1;

static int			hf_ca_searchReplyFlag=-1;
static int			hf_ca_reserved=-1;
static int			hf_ca_unused=-1;
static int			hf_ca_clientip=-1;
static int			hf_ca_serverip=-1;
static int			hf_ca_repeaterip=-1;
static int			hf_ca_beaconid=-1;

static int			hf_ca_DBR_STRING=-1;
static int			hf_ca_DBR_DOUBLE=-1;

static int			hf_ca_obsolete=-1;
static int			hf_ca_deprecated=-1;
static int			hf_ca_data=-1;
static int			hf_ca_zero=-1;
static int			hf_ca_undecoded=-1;

static int			hf_ca_channel=-1;

static hf_register_info 	hf[]=
    {   /*                                                                                   prnt base                      */
	{&hf_ca_cmdId,         {"CA Command ID",                  "ca.cmd",        FT_UINT16,BASE_DEC, VALS(cmdIdNames),  0,"",                          HFILL}},
	{&hf_ca_paySz,         {"CA Payload size",                "ca.paySz",      FT_UINT16,BASE_DEC, NULL,              0,"",                          HFILL}},
	{&hf_ca_datTyp,        {"CA Data type",                   "ca.type",       FT_UINT16,BASE_DEC, VALS(dataTypes),   0,"",                          HFILL}},
	{&hf_ca_datCnt,        {"CA Data Count",                  "ca.cnt",        FT_UINT16,BASE_DEC, NULL,              0,"",                          HFILL}},
	{&hf_ca_parm1,         {"CA Parameter 1",                 "ca.p1",         FT_UINT32,BASE_DEC, NULL,              0,"",                          HFILL}},
	{&hf_ca_parm2,         {"CA Parameter 2",                 "ca.p2",         FT_UINT32,BASE_DEC, NULL,              0,"",                          HFILL}},
	{&hf_ca_tcpPort,       {"TCP port of responding server",  "ca.tcpPort",    FT_UINT16,BASE_DEC, NULL,              0,"",                          HFILL}},
	{&hf_ca_srvrId,        {"Temporary SID",                  "ca.srvrId",     FT_UINT32,BASE_HEX, NULL,              0,"",                          HFILL}},
	{&hf_ca_chnId,         {"Channel CID",                    "ca.chnId",      FT_UINT32,BASE_HEX, NULL,              0,"",                          HFILL}},
	{&hf_ca_minorVer,      {"Minor protocol version",         "ca.minorVer",   FT_UINT16,BASE_DEC, NULL,              0,"",                          HFILL}},
	{&hf_ca_srvrProto,     {"Server protocol version",        "ca.srvrVer",    FT_UINT16,BASE_DEC, NULL,              0,"",                          HFILL}},
	{&hf_ca_desiredPrio,   {"Desired Priority",               "ca.desiredPrio",FT_UINT16,BASE_DEC, NULL,              0,"",                          HFILL}},
	{&hf_ca_userName,      {"User name",                      "ca.userName",   FT_STRING,BASE_NONE,NULL,              0,"",                          HFILL}},
	{&hf_ca_hostName,      {"Host name",                      "ca.hostName",   FT_STRING,BASE_NONE,NULL,              0,"",                          HFILL}},
	{&hf_ca_chanName,      {"Channel name",                   "ca.chanName",   FT_STRING,BASE_NONE,NULL,              0,"",                          HFILL}},
	{&hf_ca_accRghts,      {"Access Rights",                  "ca.accRghts",   FT_UINT32,BASE_HEX, VALS(accessRights),0,"",                          HFILL}},
	{&hf_ca_ioid,          {"Client provided IOID",           "ca.ioid",       FT_UINT32,BASE_HEX, NULL,              0,"",                          HFILL}},
	{&hf_ca_subscriptionId,{"Client provided Subscription ID","ca.subscrptId", FT_UINT32,BASE_HEX, NULL,              0,"",                          HFILL}},
	{&hf_ca_evLoVal,       {"Low value",                      "ca.evLo",       FT_FLOAT, BASE_NONE,NULL,              0,"",                          HFILL}},
	{&hf_ca_evHiVal,       {"High value",                     "ca.evHi",       FT_FLOAT, BASE_NONE,NULL,              0,"",                          HFILL}},
	{&hf_ca_evToVal,       {"To value",                       "ca.evTo",       FT_FLOAT, BASE_NONE,NULL,              0,"",                          HFILL}},
	{&hf_ca_evMsk,         {"Monitor mask",                   "ca.evMonMsk",   FT_UINT16,BASE_HEX, VALS(monitorMask), 0,"",                          HFILL}},
	{&hf_ca_status,        {"Status",                         "ca.status",     FT_UINT32,BASE_DEC, VALS(statusCodes), 0,"",                          HFILL}},
	{&hf_ca_searchReplyFlag,        {"Reply",                 "ca.reply",      FT_UINT16,BASE_DEC, VALS(searchReplyFlags), 0,"",                     HFILL}},
	{&hf_ca_reserved,      {"Reserved",                       "ca.reserved",   FT_UINT32,BASE_HEX, NULL,              0,"Should be zero",            HFILL}},
	{&hf_ca_unused,        {"Unused",                         "ca.unused",     FT_UINT16,BASE_HEX, NULL,              0,"",                          HFILL}},
	{&hf_ca_clientip,      {"Client IP address",              "ca.clientip",   FT_IPv4,BASE_NONE,  NULL,              0,"",                          HFILL}},
	{&hf_ca_serverip,      {"Server IP address",              "ca.serverip",   FT_IPv4,BASE_NONE,  NULL,              0,"",                          HFILL}},
	{&hf_ca_repeaterip,    {"Repeater IP address",            "ca.repeaterip", FT_IPv4,BASE_NONE,  NULL,              0,"",                          HFILL}},
	{&hf_ca_beaconid,      {"BeaconID",                       "ca.status",     FT_UINT32,BASE_DEC, NULL,              0,"",                          HFILL}},

	{&hf_ca_DBR_STRING,    {"String data",                    "ca.strDat",     FT_STRING,BASE_NONE,NULL,              0,"",                          HFILL}},
	{&hf_ca_DBR_DOUBLE,    {"Double prec.float data",         "ca.dblDat",     FT_DOUBLE,BASE_NONE,NULL,              0,"",                          HFILL}},

	{&hf_ca_obsolete,      {"Obsolete",                       "ca.deprecated", FT_BYTES, BASE_NONE,NULL,              0,"Obsolete",                  HFILL}},
	{&hf_ca_deprecated,    {"Deprecated",                     "ca.deprecated", FT_BYTES, BASE_NONE,NULL,              0,"Deprecated",                HFILL}},
	{&hf_ca_data,          {"data",                           "ca.data",       FT_NONE,  BASE_NONE,NULL,              0,"formatted data",            HFILL}},
	{&hf_ca_zero,          {"zero",                           "ca.zero",       FT_NONE,  BASE_NONE,NULL,              0,"should be zero",            HFILL}},
	{&hf_ca_undecoded,     {"undecoded",                      "ca.undecoded",  FT_NONE,  BASE_NONE,NULL,              0,"Yet undecoded by dissector",HFILL}},

	{&hf_ca_channel,       {"Corresponding channel",          "ca.channel",    FT_STRING,BASE_NONE,NULL,              0,"",                          HFILL}},
    };

/* Setup protocol subtree array */
static gint 			ett_ca=-1;
static gint 			*ett[]={&ett_ca,};

/*===========================================================================
 *  The main dissection...
 *  google: epics "channel access" protocol packet fields definition
 *  http://epics.cosylab.com/cosyjava/JCA-Common/Documentation/CAproto.html
 *  above also referenced from http://www.aps.anl.gov/epics/docs/ca.php
 */


static ca_conv_data_t *
ca_stateinit( conversation_t *conversation )
{
    ca_conv_data_t	*state;

    state = se_alloc( sizeof(ca_conv_data_t) );
    *state = stateinit; 
    state->next = ca_conv_data_list;
//	state->chanName = NULL;
	state->cid2cn = g_hash_table_new(g_direct_hash, g_direct_equal);
	state->sid2cn = g_hash_table_new(g_direct_hash, g_direct_equal);
	state->subid2cn = g_hash_table_new(g_direct_hash, g_direct_equal);
    ca_conv_data_list = state;

    /* initialise opcodes */

    conversation_add_proto_data(conversation, proto_ca, state);
    return state;
}


static void parse_payload(proto_tree *ca_tree, tvbuff_t *tvb) {
	int Psz = tvb_get_ntohs(tvb,2);
	int datTyp = tvb_get_ntohs(tvb,4);
//	int datCnt = tvb_get_ntohs(tvb,6);
	int offset = 16;
	switch (datTyp) {
	case DBR_STRING:
		proto_tree_add_item( ca_tree, hf_ca_DBR_STRING,tvb,offset, Psz, FALSE );
		offset += Psz;
		break;
	case DBR_DOUBLE:
		proto_tree_add_item( ca_tree, hf_ca_DBR_DOUBLE,tvb,offset, Psz, FALSE );
		offset += Psz;
		break;
	default:
		proto_tree_add_item( ca_tree, hf_ca_data, tvb,offset,Psz,FALSE );
		offset += Psz;
		break;
	}
} /* parse_payload */

static void find_cn_for_cid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ca_tree, ca_conv_data_t *state, guint32 cid) {
	gpointer *cn = g_hash_table_lookup(state->cid2cn, (gpointer)cid);
//	printf("resolving cid %d: %s\n", cid, cn == NULL ? "null" : (char*)cn);
	if (cn == NULL) {
		proto_item *item = proto_tree_add_string(ca_tree, hf_ca_channel, tvb, 0, 0, "[ unable to find channel name for given CID! ]");
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Unable to find channel name for given CID!");
	} else {
		proto_tree_add_string(ca_tree, hf_ca_channel, tvb, 0, 0, (guint8*)cn);
	}
}

static void find_cn_for_sid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ca_tree, ca_conv_data_t *state, guint32 sid) {
	gpointer *cn = g_hash_table_lookup(state->sid2cn, (gpointer)sid);
//	printf("resolving sid %d: %s\n", sid, cn == NULL ? "null" : (char*)cn);
	if (cn == NULL) {
		proto_item *item = proto_tree_add_string(ca_tree, hf_ca_channel, tvb, 0, 0, "[ unable to find channel name for given SID! ]");
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Unable to find channel name for given SID!");
	} else {
		proto_tree_add_string(ca_tree, hf_ca_channel, tvb, 0, 0, (guint8*)cn);
	}
}

static void find_cn_for_subid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ca_tree, ca_conv_data_t *state, guint32 subid) {
	gpointer *cn = g_hash_table_lookup(state->subid2cn, (gpointer)subid);
//	printf("resolving subscriptionid %d: %s\n", subid, cn == NULL ? "null" : (char*)cn);
	if (cn == NULL) {
		proto_item *item = proto_tree_add_string(ca_tree, hf_ca_channel, tvb, 0, 0, "[ unable to find channel name for given SubscriptionID! ]");
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Unable to find channel name for given SubscriptionID!");
	} else {
		proto_tree_add_string(ca_tree, hf_ca_channel, tvb, 0, 0, (guint8*)cn);
	}
}

static void
dissect_ca_request(  tvbuff_t		*tvb
		   , packet_info	*pinfo
		   , proto_tree 	*tree
		   , char const		*sep
		   , ca_conv_data_t	*state )
{
    int		offset=0;  /* needed to keep track of where I am in the hf_ca_... */
    guint16	ca_cmdId;
    guint16	Psz;
    gint	left;
    proto_item	*ti, *item=NULL;
    proto_tree	*ca_tree=NULL;

    ca_cmdId  = tvb_get_ntohs(tvb,0);
    Psz       = tvb_get_ntohs(tvb,2);

    ti      = proto_tree_add_item( tree, proto_ca, tvb, 0, -1, FALSE );
    ca_tree = proto_item_add_subtree( ti, ett_ca );

    if (!((pinfo)->fd->flags.visited))
    {   /* we have not seen packet before. */
		++state->sequencenumber;
		if (ca_cmdId == CA_PROTO_CREATE_CHAN) {
//			state->chanName = tvb_get_string(tvb, 16, Psz);
			g_hash_table_insert(state->cid2cn, (gpointer)tvb_get_ntohl(tvb, 8), tvb_get_string(tvb, 16, Psz));
//			printf("adding cid: %d -> %s\n", tvb_get_ntohl(tvb, 8), tvb_get_string(tvb, 16, Psz));
		} else if (ca_cmdId == CA_PROTO_EVENT_ADD) {
			gpointer *cn = g_hash_table_lookup(state->sid2cn, (gpointer)tvb_get_ntohl(tvb, 8));
			g_hash_table_insert(state->subid2cn, (gpointer)tvb_get_ntohl(tvb, 12), cn);
//			printf("adding subscriptionid: %d -> %s\n", tvb_get_ntohl(tvb, 12), (char*)cn);
		}
    }

    if (check_col(pinfo->cinfo,COL_INFO))
    {   col_append_fstr(  pinfo->cinfo, COL_INFO, "%s %s"
			, sep
			, val_to_str(ca_cmdId,cmdIdNames,"Unknown (0x%04x)") );

    }

    if (tree)
    {   /* we are being asked for details */

	proto_item_append_text(  ti, ", %s %sRequest, cmd: %d (%s) %s:%d -> %s:%d"
			       , (pinfo->ipproto==IPPROTO_TCP)?"tcp":"udp"
			       , (pinfo->destport==global_ca_repeater_port)?"rpr":""
			       , ca_cmdId, val_to_str(ca_cmdId, cmdIdNames,"Unknown (0x%04x)")
			       , ip_to_str(pinfo->net_src.data), pinfo->srcport
			       , ip_to_str(pinfo->net_dst.data), pinfo->destport
			       );


	switch (ca_cmdId)
	{
	// TCP & UDP commands
	case CA_PROTO_VERSION:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
		TEST_ZERO(item, Psz);
	    proto_tree_add_item(ca_tree, hf_ca_desiredPrio, tvb, 4, 2, FALSE);
	    if (pinfo->ipproto == IPPROTO_TCP) {
			proto_tree_add_item(ca_tree, hf_ca_minorVer,tvb, 6, 2, FALSE);
	    } else {
			proto_tree_add_item(ca_tree, hf_ca_unused,tvb, 6, 2, FALSE);
		}
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 8, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 8));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 12, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 12));
	    offset=16;
	    break;
	case CA_PROTO_SEARCH:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
		//TEST_GE_ZERO(item, Psz);
	    item = proto_tree_add_item( ca_tree, hf_ca_searchReplyFlag,tvb, 4, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 4), searchReplyFlags);
		proto_tree_add_item( ca_tree, hf_ca_minorVer, tvb, 6, 2, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_chnId, tvb, 8, 4, FALSE );
	    item = proto_tree_add_item( ca_tree, hf_ca_chnId, tvb, 12, 4, FALSE );
		if (tvb_get_ntohl(tvb, 8) != tvb_get_ntohl(tvb, 12)) {
			expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "CID values do not match!");
			proto_item_append_text(item, " [CID values do not match]"); \
		}
	    proto_tree_add_item( ca_tree, hf_ca_chanName, tvb, 16, Psz, FALSE );
	    offset=16+Psz;
//		find_cn_for_cid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
	    break;
//	case CA_PROTO_NOT_FOUND:
	case CA_PROTO_ECHO:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_reserved, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 8, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 8));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 12, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 12));
	    offset=16;
		break;

	// UDP commands
	case CA_PROTO_RSRV_IS_UP:
//	    proto_tree_add_item( ca_tree, hf_ca_zero, tvb, 4, 12, FALSE );
//	    offset=16;
//	    break;
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_reserved, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
		item = proto_tree_add_item( ca_tree, hf_ca_tcpPort, tvb, 4, 2, FALSE );
		//TEST_GE_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
		proto_tree_add_item(ca_tree, hf_ca_beaconid, tvb, 8, 4, FALSE);
		proto_tree_add_item(ca_tree, hf_ca_serverip, tvb, 12, 4, FALSE);
		offset=16;
		break;
//  case CA_REPEATER_CONFIRM:
	case CA_REPEATER_REGISTER:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_reserved, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 8, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 8));
		proto_tree_add_item(ca_tree, hf_ca_clientip, tvb, 12, 4, FALSE);
	    offset=16;
		break;

	// TCP commands
	case CA_PROTO_EVENT_ADD:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
		TEST_EQ(item, Psz, 16);
	    item = proto_tree_add_item( ca_tree, hf_ca_datTyp, tvb,  4, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 4), dataTypes);
	    item = proto_tree_add_item( ca_tree, hf_ca_datCnt, tvb,  6, 2, FALSE );
		//TEST_GE_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_srvrId,        tvb,  8, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_subscriptionId,tvb, 12, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_evLoVal,       tvb, 16, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_evHiVal,       tvb, 20, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_evToVal,       tvb, 24, 4, FALSE );
	    item = proto_tree_add_item( ca_tree, hf_ca_evMsk,  tvb, 28, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 28), monitorMask);
/*		proto_item *ti;
		guint32 bitmask_value;
		int bitmask_offset;
		int bitmask_size;
		proto_tree *bitmask_tree;
		bitmask_value = ((size == 1) ? (guint32)VALUE8(tvb, *offsetp) :
				 ((size == 2) ? (guint32)VALUE16(tvb, *offsetp) :
				  (guint32)VALUE32(tvb, *offsetp)));
		bitmask_offset = *offsetp;
		bitmask_size = size;
		ti = proto_tree_add_uint(t, hf_x11_##name##_mask, tvb, *offsetp, size, bitmask_value);
		bitmask_tree = proto_item_add_subtree(ti, ett_x11_##name##_mask);
		*offsetp += size; */
	    proto_tree_add_item( ca_tree, hf_ca_zero,     tvb, 30, 2, FALSE );
		find_cn_for_sid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
	    offset=16+16;
	    break;
	case CA_PROTO_EVENT_CANCEL:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint( ca_tree, hf_ca_paySz,  tvb, 2, 2, Psz );
		TEST_ZERO(item, Psz);
	    item = proto_tree_add_item( ca_tree, hf_ca_datTyp, tvb,  4, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 4), dataTypes);
	    item = proto_tree_add_item( ca_tree, hf_ca_datCnt, tvb,  6, 2, FALSE );
		//TEST_GE_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_srvrId,        tvb,  8, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_subscriptionId,tvb, 12, 4, FALSE );
		find_cn_for_sid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
		offset=16;
		break;
	case CA_PROTO_READ: // OBSOLETE
		item = proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "CA_PROTO_READ is obsolete!");
		item = proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
		TEST_ZERO(item, Psz);
	    item = proto_tree_add_item( ca_tree, hf_ca_datTyp, tvb, 4, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 4), dataTypes);
	    proto_tree_add_item( ca_tree, hf_ca_datCnt,   tvb, 6, 2, FALSE );
		//TEST_GE_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_srvrId,   tvb, 8, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_ioid,     tvb, 12, 4, FALSE );
		find_cn_for_sid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
	    offset=16;
	    break;
	case CA_PROTO_WRITE:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
	    item = proto_tree_add_item( ca_tree, hf_ca_datTyp, tvb, 4, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 4), dataTypes);
	    proto_tree_add_item( ca_tree, hf_ca_datCnt,   tvb, 6, 2, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_srvrId,   tvb, 8, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_ioid,     tvb, 12, 4, FALSE );
		parse_payload(ca_tree, tvb);
		find_cn_for_sid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
	    offset=16+Psz;
	    break;
	case CA_PROTO_SNAPSHOT:
	    item = proto_tree_add_item( ca_tree, hf_ca_obsolete,tvb, 0, 16+Psz, FALSE );
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "CA_PROTO_SNAPSHOT is obsolete!");
	    offset=16+Psz;
		break;
	case CA_PROTO_BUILD:
	    item = proto_tree_add_item( ca_tree, hf_ca_obsolete,tvb, 0, 16+Psz, FALSE );
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "CA_PROTO_BUILD is obsolete!");
	    offset=16+Psz;
		break;
	case CA_PROTO_EVENTS_OFF:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_reserved, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 8, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 8));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 12, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 12));
	    offset=16;
		break;
	case CA_PROTO_EVENTS_ON:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_reserved, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 8, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 8));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 12, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 12));
	    offset=16;
		break;
	case CA_PROTO_READ_SYNC:
		item = proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "CA_PROTO_READ_SYNC is obsolete!");
		item = proto_tree_add_uint(ca_tree, hf_ca_reserved, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 8, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 8));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 12, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 12));
	    offset=16;
		break;
//	case CA_PROTO_ERROR:
	case CA_PROTO_CLEAR_CHANNEL:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_reserved, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_srvrId, tvb, 8, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_chnId, tvb, 12, 4, FALSE );
		find_cn_for_cid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 12));
	    offset=16;
		break;
	case CA_PROTO_READ_NOTIFY:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
		TEST_ZERO(item, Psz);
	    item = proto_tree_add_item( ca_tree, hf_ca_datTyp, tvb,  4, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 4), dataTypes);
	    item = proto_tree_add_item( ca_tree, hf_ca_datCnt, tvb,  6, 2, FALSE );
		//TEST_GE_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_srvrId,        tvb,  8, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_ioid,     tvb,12, 4, FALSE );
		find_cn_for_sid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
	    offset=16;
	    break;
	case CA_PROTO_READ_BUILD:
	    item = proto_tree_add_item( ca_tree, hf_ca_obsolete,tvb, 0, 16+Psz, FALSE );
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "CA_PROTO_READ_BUILD is obsolete!");
	    offset=16+Psz;
		break;
	case CA_PROTO_CREATE_CHAN:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_chnId,     tvb, 8, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_minorVer,tvb, 12,4, FALSE );   /* imperically grab 4 bytes, even though it in a 2 byte position above */
	    proto_tree_add_item( ca_tree, hf_ca_chanName,tvb, 16,Psz, FALSE );
		find_cn_for_cid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
	    offset=16+Psz;
	    break;
	case CA_PROTO_WRITE_NOTIFY:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
	    item = proto_tree_add_item( ca_tree, hf_ca_datTyp, tvb, 4, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 4), dataTypes);
	    proto_tree_add_item( ca_tree, hf_ca_datCnt,   tvb, 6, 2, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_srvrId,   tvb, 8, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_ioid,     tvb, 12, 4, FALSE );
		find_cn_for_sid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
		parse_payload(ca_tree, tvb);
	    offset=16+Psz;
	    break;
	case CA_PROTO_CLIENT_NAME:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
		//TEST_GE_ZERO(item, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 8, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 8));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 12, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 12));
	    proto_tree_add_item( ca_tree, hf_ca_userName,tvb, 16,Psz, FALSE );
	    offset=16+Psz;
	    break;
	case CA_PROTO_HOST_NAME:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 8, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 8));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 12, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 12));
	    proto_tree_add_item( ca_tree, hf_ca_hostName,tvb, 16,Psz, FALSE );
	    offset=16+Psz;
	    break;
//	case CA_PROTO_ACCESS_RIGHTS:
	case CA_PROTO_SIGNAL:
	    item = proto_tree_add_item( ca_tree, hf_ca_obsolete,tvb, 0, 16+Psz, FALSE );
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "CA_PROTO_SIGNAL is obsolete!");
	    offset=16+Psz;
		break;
//	case CA_PROTO_CREATE_CH_FAIL:
//	case CA_PROTO_SERVER_DISCONN:
	default:
		item = proto_tree_add_uint(ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId);
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Illegal command id for request message (%d)!", ca_cmdId);
		proto_item_append_text(item, " [illegal command id for request message]");
		offset=2;
	}
    }
	
    if ((left = tvb_reported_length_remaining(tvb, offset)) > 0)
    {   proto_tree_add_item( ca_tree, hf_ca_undecoded, tvb, offset,  left, FALSE);
    }
}   /* dissect_ca_request */


static void
dissect_ca_response(  tvbuff_t		*tvb
		    , packet_info	*pinfo
		    , proto_tree 	*tree
		    , char const	*sep
		    , ca_conv_data_t	*state )
{
    int		offset=0;  /* needed to keep track of where I am in the hf_ca_... */
    guint16	ca_cmdId;
    guint16	Psz;
    int		Psz_bytes;
    gint	left;
    proto_item	*ti, *item=NULL;
    proto_tree	*ca_tree=NULL;
	gpointer *cn;

    ca_cmdId  = tvb_get_ntohs(tvb,0);

    /*  XXX although currently, I know of no response where this payload
        will not be correct, strictly speaking, the EPIC protocol doc
        indicates that some of the responses size are fixed by the protocol
        definitiion (i.e the field is labeled "reserved" and noted "Must be 0."
	(i.e CA_PROTO_VERSION) */
    Psz       = tvb_get_ntohs(tvb,2);
    Psz_bytes = Psz;  /* bytes until further notice */

    ti      = proto_tree_add_item( tree, proto_ca, tvb, 0, -1, FALSE );
    ca_tree = proto_item_add_subtree( ti, ett_ca );

    if (!((pinfo)->fd->flags.visited))
    {   /* we have not seen packet before. */
		++state->sequencenumber;
		switch (ca_cmdId) {
		case CA_PROTO_CREATE_CHAN:
//			state->chanName = tvb_get_string(tvb, 16, Psz);
			cn = g_hash_table_lookup(state->cid2cn, (gpointer)tvb_get_ntohl(tvb, 8));
			if (cn != NULL) {
				g_hash_table_insert(state->sid2cn, (gpointer)tvb_get_ntohl(tvb, 12), cn);
//				printf("adding sid: %d (%s) -> %d\n", tvb_get_ntohl(tvb, 8), (char*)cn, tvb_get_ntohl(tvb, 12));
			}
			break;
//		case CA_PROTO_CLEAR_CHANNEL:
//			printf("SHOULD REMOVE SID & CID: %d, %d\n", tvb_get_ntohl(tvb, 8), tvb_get_ntohl(tvb, 12));
//			g_hash_table_remove(state->sid2cn, (gpointer)tvb_get_ntohl(tvb, 8));
//			g_hash_table_remove(state->cid2cn, (gpointer)tvb_get_ntohl(tvb, 12));
			break;
		case CA_PROTO_EVENT_CANCEL:
//			printf("SHOULD REMOVE SubscriptionID: %d\n", tvb_get_ntohl(tvb, 12));
//			g_hash_table_remove(state->subid2cn, (gpointer)tvb_get_ntohl(tvb, 12));
			break;
		}
    }

    if (check_col(pinfo->cinfo,COL_INFO))
    {   col_append_fstr(  pinfo->cinfo, COL_INFO, "%s %s"
		     , sep, val_to_str(ca_cmdId,cmdIdNames,"Unknown (0x%04x)") );
    }

    if (tree)
    {   /* we are being asked for details */
	proto_item_append_text(  ti, ", %s %sResponse, cmd: %d (%s) %s:%d -> %s:%d"
			       , (pinfo->ipproto==IPPROTO_TCP)?"tcp":"udp"
			       , (pinfo->srcport==global_ca_repeater_port)?"rpr":""
			       , ca_cmdId, val_to_str(ca_cmdId, cmdIdNames,"Unknown (0x%04x)")
			       , ip_to_str(pinfo->net_src.data), pinfo->srcport
			       , ip_to_str(pinfo->net_dst.data), pinfo->destport
			       );


	switch (ca_cmdId)
	{
	// TCP & UDP commands
	case CA_PROTO_VERSION:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_paySz, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_desiredPrio, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		proto_tree_add_item( ca_tree, hf_ca_minorVer,tvb, 6, 2, FALSE );
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 8, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 8));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 12, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 12));
	    offset=16;
		break;
	case CA_PROTO_SEARCH:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
		TEST_EQ(item, Psz, 8);
	    proto_tree_add_item( ca_tree, hf_ca_tcpPort,  tvb, 4, 2, FALSE );
	    item = proto_tree_add_item( ca_tree, hf_ca_datCnt, tvb, 6, 2, FALSE );
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
	    item = proto_tree_add_item( ca_tree, hf_ca_srvrId, tvb, 8, 4, FALSE );
		TEST_EQ(item, tvb_get_ntohl(tvb, 8), 0xffffffff);
	    proto_tree_add_item( ca_tree, hf_ca_chnId,    tvb,12, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_srvrProto,tvb,16, 2, FALSE );
//		find_cn_for_cid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 12));
	    offset=16+8;
	    break;
	case CA_PROTO_NOT_FOUND:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_reserved, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
	    item = proto_tree_add_item( ca_tree, hf_ca_searchReplyFlag,tvb, 4, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 4), searchReplyFlags);
		proto_tree_add_item( ca_tree, hf_ca_minorVer,tvb, 6, 2, FALSE );
		proto_tree_add_item( ca_tree, hf_ca_minorVer, tvb, 6, 2, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_chnId, tvb, 8, 4, FALSE );
	    item = proto_tree_add_item( ca_tree, hf_ca_chnId, tvb, 12, 4, FALSE );
		if (tvb_get_ntohl(tvb, 8) != tvb_get_ntohl(tvb, 12)) {
			expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "CID values do not match!");
			proto_item_append_text(item, " [CID values do not match]"); \
		}
		find_cn_for_cid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
	    offset=16;
		break;
	case CA_PROTO_ECHO:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_reserved, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 8, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 8));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 12, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 12));
	    offset=16;
		break;

	// UDP commands
/*	case CA_PROTO_RSRV_IS_UP:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_reserved, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
	    item = proto_tree_add_item( ca_tree, hf_ca_tcpPort, tvb, 4, 2, FALSE );
		//TEST_GE_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
		proto_tree_add_item(ca_tree, hf_ca_beaconid, tvb, 8, 4, FALSE);
		proto_tree_add_item(ca_tree, hf_ca_serverip, tvb, 12, 4, FALSE);
	    offset=16;
	    break;*/
	case CA_REPEATER_CONFIRM:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_reserved, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 8, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 8));
		proto_tree_add_item(ca_tree, hf_ca_repeaterip, tvb, 12, 4, FALSE);
	    offset=16;
		break;
//	case CA_REPEATER_REGISTER:

	// TCP commands
	case CA_PROTO_EVENT_ADD:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
		//TEST_GE_ZERO(item, Psz);
	    item = proto_tree_add_item( ca_tree, hf_ca_datTyp, tvb,  4, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 4), dataTypes);
	    item = proto_tree_add_item( ca_tree, hf_ca_datCnt, tvb,  6, 2, FALSE );
		//TEST_GE_ZERO(item, tvb_get_ntohs(tvb, 6));
	    item = proto_tree_add_item( ca_tree, hf_ca_status, tvb, 8, 4, FALSE );
		TEST_FLAG(item, tvb_get_ntohl(tvb, 8), statusCodes);
	    proto_tree_add_item( ca_tree, hf_ca_subscriptionId,tvb,12, 4, FALSE );
		parse_payload(ca_tree, tvb);
		find_cn_for_subid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 12));
	    offset=16+Psz;
	    break;
	case CA_PROTO_EVENT_CANCEL:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
		TEST_ZERO(item, Psz);
	    item = proto_tree_add_item( ca_tree, hf_ca_datTyp, tvb,  4, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 4), dataTypes);
	    item = proto_tree_add_item( ca_tree, hf_ca_datCnt, tvb,  6, 2, FALSE );
		//TEST_GE_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_srvrId,        tvb,  8, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_subscriptionId,tvb, 12, 4, FALSE );
		find_cn_for_sid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
		offset=16;
		break;
	case CA_PROTO_READ: // OBSOLETE
		item = proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "CA_PROTO_READ is obsolete!");
		proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
	    item = proto_tree_add_item( ca_tree, hf_ca_datTyp, tvb, 4, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 4), dataTypes);
	    proto_tree_add_item( ca_tree, hf_ca_datCnt,        tvb, 6, 2, FALSE );
		//TEST_GE_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_srvrId,        tvb,  8, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_ioid,     tvb,12, 4, FALSE );
		parse_payload(ca_tree, tvb);
		find_cn_for_sid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
	    offset=16+Psz;
	    break;
//	case CA_PROTO_WRITE:
	case CA_PROTO_SNAPSHOT:
	    item = proto_tree_add_item( ca_tree, hf_ca_obsolete,tvb, 0, 16+Psz, FALSE );
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "CA_PROTO_SNAPSHOT is obsolete!");
	    offset=16+Psz;
		break;
	case CA_PROTO_BUILD:
	    item = proto_tree_add_item( ca_tree, hf_ca_obsolete,tvb, 0, 16+Psz, FALSE );
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "CA_PROTO_BUILD is obsolete!");
	    offset=16+Psz;
		break;
//	case CA_PROTO_EVENTS_OFF:
//	case CA_PROTO_EVENTS_ON:
//	case CA_PROTO_READ_SYNC: // OBSOLETE
	case CA_PROTO_ERROR:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		proto_tree_add_uint(ca_tree, hf_ca_paySz, tvb, 2, 2, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_chnId, tvb, 8, 4, FALSE );
	    item = proto_tree_add_item( ca_tree, hf_ca_status, tvb, 12, 4, FALSE );
		TEST_FLAG(item, tvb_get_ntohl(tvb, 12), statusCodes);
		find_cn_for_cid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
		// FIXME: parse header of the original request and error message
		break;
	case CA_PROTO_CLEAR_CHANNEL:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_reserved, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_srvrId, tvb, 8, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_chnId, tvb, 12, 4, FALSE );
		find_cn_for_cid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 12));
	    offset=16;
		break;
	case CA_PROTO_READ_NOTIFY:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
	    item = proto_tree_add_item( ca_tree, hf_ca_datTyp, tvb,  4, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 4), dataTypes);
	    item = proto_tree_add_item( ca_tree, hf_ca_datCnt, tvb,  6, 2, FALSE );
		//TEST_GE_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_srvrId,        tvb,  8, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_ioid,     tvb,12, 4, FALSE );
		parse_payload(ca_tree, tvb);
		find_cn_for_sid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
	    offset=16+Psz;
	    break;
	case CA_PROTO_READ_BUILD:
	    item = proto_tree_add_item( ca_tree, hf_ca_obsolete,tvb, 0, 16+Psz, FALSE );
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "CA_PROTO_READ_BUILD is obsolete!");
	    offset=16+Psz;
		break;
	case CA_PROTO_CREATE_CHAN:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
		TEST_ZERO(item, Psz);
	    item = proto_tree_add_item( ca_tree, hf_ca_datTyp, tvb, 4, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 4), dataTypes);
	    item = proto_tree_add_item( ca_tree, hf_ca_datCnt, tvb, 6, 2, FALSE );
		//TEST_GE_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_chnId,    tvb, 8, 4, FALSE );
	    proto_tree_add_item( ca_tree, hf_ca_srvrId,   tvb,12, 4, FALSE );
		find_cn_for_cid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
	    offset=16;
	    break;
	case CA_PROTO_WRITE_NOTIFY:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint( ca_tree, hf_ca_paySz, tvb, 2, 2, Psz );
		TEST_ZERO(item, Psz);
	    item = proto_tree_add_item( ca_tree, hf_ca_datTyp, tvb, 4, 2, FALSE );
		TEST_FLAG(item, tvb_get_ntohs(tvb, 4), dataTypes);
	    proto_tree_add_item( ca_tree, hf_ca_datCnt,   tvb, 6, 2, FALSE );
	    item = proto_tree_add_item( ca_tree, hf_ca_status, tvb, 8, 4, FALSE );
		TEST_FLAG(item, tvb_get_ntohl(tvb, 8), statusCodes);
	    proto_tree_add_item( ca_tree, hf_ca_ioid,     tvb, 12, 4, FALSE );
	    offset=16;
	    break;
//	case CA_PROTO_CLIENT_NAME:
//	case CA_PROTO_HOST_NAME:
	case CA_PROTO_ACCESS_RIGHTS:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_paySz, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_chnId,   tvb, 8, 4, FALSE );
	    item = proto_tree_add_item( ca_tree, hf_ca_accRghts,tvb,12, 4, FALSE );
		TEST_FLAG(item, tvb_get_ntohl(tvb, 12), accessRights);
		find_cn_for_cid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
	    offset=16;
		break;
	case CA_PROTO_SIGNAL:
	    item = proto_tree_add_item( ca_tree, hf_ca_obsolete,tvb, 0, 16+Psz, FALSE );
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "CA_PROTO_SIGNAL is obsolete!");
	    offset=16+Psz;
		break;
	case CA_PROTO_CREATE_CH_FAIL:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_reserved, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_chnId,   tvb, 8, 4, FALSE );
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 12, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 12));
		find_cn_for_cid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
	    offset=16;
		break;
	case CA_PROTO_SERVER_DISCONN:
		proto_tree_add_uint( ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId );
		item = proto_tree_add_uint(ca_tree, hf_ca_reserved, tvb, 2, 2, Psz);
		TEST_ZERO(item, Psz);
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 4, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 4));
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 6, 2, FALSE);
		TEST_ZERO(item, tvb_get_ntohs(tvb, 6));
	    proto_tree_add_item( ca_tree, hf_ca_chnId,   tvb, 8, 4, FALSE );
		item = proto_tree_add_item(ca_tree, hf_ca_reserved, tvb, 12, 4, FALSE);
		TEST_ZERO(item, tvb_get_ntohl(tvb, 12));
		find_cn_for_cid(tvb, pinfo, ca_tree, state, tvb_get_ntohl(tvb, 8));
	    offset=16;
		break;
	default:
		item = proto_tree_add_uint(ca_tree, hf_ca_cmdId, tvb, 0, 2, ca_cmdId);
		expert_add_info_format(pinfo, item, PI_MALFORMED, PI_ERROR, "Illegal command id for response message (%d)!", ca_cmdId);
		proto_item_append_text(item, " [illegal command id for response message]");
		offset=2;
	}
    }
	
    if ((left = tvb_reported_length_remaining(tvb, offset)) > 0)
    {   proto_tree_add_item( ca_tree, hf_ca_undecoded, tvb, offset,  left, FALSE);
    }
}   /* dissect_ca_response */



static void
dissect_ca_requests(  tvbuff_t		*tvb
		    , packet_info	*pinfo
		    , proto_tree	*tree )
{
    int			offset=0;
    guint32			length, length_remaining;
    conversation_t	*conversation;
    ca_conv_data_t	*state;
    guint16		ca_command;
    int			payload_bytes;
    tvbuff_t		*next_tvb;
    char const		*sep=NULL;


    while (tvb_reported_length_remaining(tvb, offset) != 0)
    {   /*  We use "tvb_ensure_length_remaining()" to make sure there
	    actually *is* data remaining.
	    This means we're guaranteed that "length_remaining" is
	    positive. */
	length_remaining = tvb_ensure_length_remaining(tvb, offset);

	/*  Can we do reassembly? */
	if (ca_desegment && pinfo->can_desegment)
	{   /*  Yes - is the request header split across
		segment boundaries? */
	    guint32 bytes_wanted=4;  /* enough to get "command" and "payload size" */
	    if (length_remaining < bytes_wanted)
	    {   /*  Yes.  Tell the TCP dissector where the data
		    for this message starts in the data it handed
		    us, and how many more bytes we need, and return. */
		pinfo->desegment_offset = offset;
		pinfo->desegment_len = bytes_wanted - length_remaining;
		break;
	    }
	}

	/*  Get the state for this conversation; create the conversation
	    if we don't have one, and create the state if we don't have
	    any. */
	conversation = find_conversation(  pinfo->fd->num, &pinfo->src
					 , &pinfo->dst, pinfo->ptype
					 , pinfo->srcport, pinfo->destport, 0 );
	if (conversation == NULL)
	{   /*  No - create one. */
	    conversation = conversation_new(  pinfo->fd->num, &pinfo->src
					    , &pinfo->dst, pinfo->ptype
					    , pinfo->srcport, pinfo->destport, 0);
	}
	if ((state = conversation_get_proto_data(conversation, proto_ca))
	    == NULL)
	{   state = ca_stateinit(conversation);
	}

	/*  Get the command and length of the request. */
	ca_command    = tvb_get_ntohs( tvb, offset );
	payload_bytes = tvb_get_ntohs( tvb, offset+2 );

	/*  Can we do reassembly? */
	if (ca_desegment && pinfo->can_desegment)
	{   /*  Yes - is the request header split across
		segment boundaries? */
	    guint32 bytes_wanted=(sizeof(caHdr)+payload_bytes); /* complete "command/message" */
	    if (length_remaining < bytes_wanted)
	    {   /*  Yes.  Tell the TCP dissector where the data
		    for this message starts in the data it handed
		    us, and how many more bytes we need, and return. */
		pinfo->desegment_offset = offset;
		pinfo->desegment_len = bytes_wanted - length_remaining;
		break;
	    }
	}

	/*  Construct a tvbuff containing the amount of the payload
	    we have available.  Make its reported length the
	    amount of data in the request.

	    XXX - if reassembly isn't enabled. the subdissector
	    will throw a BoundsError exception, rather than a
	    ReportedBoundsError exception.  We really want a tvbuff
	    where the length is "length", the reported length is "payload_bytes",
	    and the "if the snapshot length were infinite" length is the
	    minimum of the reported length of the tvbuff handed to us
	    and "payload_bytes", with a new type of exception thrown if the offset
	    is within the reported length but beyond that third length,
	    with that exception getting the "Unreassembled Packet" error. */
	length = length_remaining;
	if (length > (sizeof(caHdr)+payload_bytes))
	{   length = (sizeof(caHdr)+payload_bytes);
	}
	next_tvb = tvb_new_subset( tvb, offset, length, (sizeof(caHdr)+payload_bytes) );

	if (sep == NULL)
	{   /*  We haven't set the column yet; set it.
	     */
	    if (check_col(pinfo->cinfo, COL_INFO))
	    {   col_add_fstr(  pinfo->cinfo, COL_INFO, "%5d > %4d  Requests"
			     , pinfo->srcport, pinfo->destport );
	    }
	    sep = ":";		/*  Initialize the separator. */
	}

	/*  Dissect the ca request.

	    If it gets a (Reported)BoundsError, we can stop, as there's nothing
	    more to see, so we just re-throw it. */
	TRY { dissect_ca_request( next_tvb, pinfo, tree, sep, state ); }
	CATCH(BoundsError)         { RETHROW; }
	CATCH(ReportedBoundsError) { RETHROW; }
	//CATCH(ReportedBoundsError) { show_reported_bounds_error( tvb, pinfo, tree ); }
	ENDTRY;

	offset += (sizeof(caHdr)+payload_bytes);
	sep     = ",";
    }
}   /* dissect_ca_requests */

static void
dissect_ca_responses(  tvbuff_t		*tvb
		     , packet_info	*pinfo
		     , proto_tree	*tree )
{
    int			offset=0;
    guint32		length, length_remaining;
    conversation_t	*conversation;
    ca_conv_data_t	*state;
    guint16		ca_command;
    int			payload_bytes;
    tvbuff_t		*next_tvb;
    char const		*sep=NULL;


    while (tvb_reported_length_remaining(tvb, offset) != 0)
    {   /*  We use "tvb_ensure_length_remaining()" to make sure there
	    actually *is* data remaining.
	    This means we're guaranteed that "length_remaining" is
	    positive. */
	length_remaining = tvb_ensure_length_remaining(tvb, offset);

	/*  Can we do reassembly? */
	if (ca_desegment && pinfo->can_desegment)
	{   /*  Yes - is the request header split across
		segment boundaries? */
	    guint32 bytes_wanted=4;  /* enough to get "command" and "payload size" */
	    if (length_remaining < bytes_wanted)
	    {   /*  Yes.  Tell the TCP dissector where the data
		    for this message starts in the data it handed
		    us, and how many more bytes we need, and return. */
		pinfo->desegment_offset = offset;
		pinfo->desegment_len = bytes_wanted - length_remaining;
		break;
	    }
	}

	/*  Get the state for this conversation; create the conversation
	    if we don't have one, and create the state if we don't have
	    any. */
	conversation = find_conversation(  pinfo->fd->num, &pinfo->src
					 , &pinfo->dst, pinfo->ptype
					 , pinfo->srcport, pinfo->destport, 0 );
	if (conversation == NULL)
	{   /*  No - create one. */
	    conversation = conversation_new(  pinfo->fd->num, &pinfo->src
					    , &pinfo->dst, pinfo->ptype
					    , pinfo->srcport, pinfo->destport, 0);
	}
	if ((state = conversation_get_proto_data(conversation, proto_ca))
	    == NULL)
	{   state = ca_stateinit(conversation);
	}

	/*  Get the command and length of the request. */
	ca_command    = tvb_get_ntohs( tvb, offset );
	payload_bytes = tvb_get_ntohs( tvb, offset+2 );

	/*  Can we do reassembly? */
	if (ca_desegment && pinfo->can_desegment)
	{   /*  Yes - is the request header split across
		segment boundaries? */
	    guint32	bytes_wanted=(sizeof(caHdr)+payload_bytes); /* complete "command/message" */
	    if (length_remaining < bytes_wanted)
	    {   /*  Yes.  Tell the TCP dissector where the data
		    for this message starts in the data it handed
		    us, and how many more bytes we need, and return. */
		pinfo->desegment_offset = offset;
		pinfo->desegment_len = bytes_wanted - length_remaining;
		break;
	    }
	}

	/*  Construct a tvbuff containing the amount of the payload
	    we have available.  Make its reported length the
	    amount of data in the request.

	    XXX - if reassembly isn't enabled. the subdissector
	    will throw a BoundsError exception, rather than a
	    ReportedBoundsError exception.  We really want a tvbuff
	    where the length is "length", the reported length is "payload_bytes",
	    and the "if the snapshot length were infinite" length is the
	    minimum of the reported length of the tvbuff handed to us
	    and "payload_bytes", with a new type of exception thrown if the offset
	    is within the reported length but beyond that third length,
	    with that exception getting the "Unreassembled Packet" error. */
	length = length_remaining;
	if (length > (sizeof(caHdr)+payload_bytes))
	{   length = (sizeof(caHdr)+payload_bytes);
	}
	next_tvb = tvb_new_subset( tvb, offset, length, (sizeof(caHdr)+payload_bytes) );

	if (sep == NULL)
	{   /*  We haven't set the column yet; set it.
	     */
	    if (check_col(pinfo->cinfo, COL_INFO))
	    {   col_add_fstr(  pinfo->cinfo, COL_INFO, "%4d > %5d Responses"
			     , pinfo->srcport, pinfo->destport );
	    }
	    sep = ":";		/*  Initialize the separator. */
	}

	/*  Dissect the ca request.

	    If it gets a (Reported)BoundsError, we can stop, as there's nothing
	    more to see, so we just re-throw it. */
	TRY { dissect_ca_response( next_tvb, pinfo, tree, sep, state ); }
	CATCH(BoundsError)         { RETHROW; }
	CATCH(ReportedBoundsError) { RETHROW; }
//	CATCH(ReportedBoundsError) { show_reported_bounds_error( tvb, pinfo, tree ); }
	ENDTRY;

	offset += (sizeof(caHdr)+payload_bytes);
	sep     = ",";
    }
}   /* dissect_ca_responses */



/* Follow x11 example: Ref. epan/dissectors/packet-x11.c
   except for endianness and separator
*/

static void
dissect_ca(  tvbuff_t		*tvb
	   , packet_info	*pinfo
	   , proto_tree		*tree )
{
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {   
	if (pinfo->ipproto == IPPROTO_TCP)
	{   col_set_str( pinfo->cinfo, COL_PROTOCOL, "CA tcp" );
	}
	else
	{   col_set_str( pinfo->cinfo, COL_PROTOCOL, "CA udp" );
	}
    }
    if (pinfo->match_port == pinfo->destport)
    {   dissect_ca_requests( tvb, pinfo, tree );
    }
    else
    {   dissect_ca_responses( tvb, pinfo, tree );
    }
}

/*===========================================================================*/

void
proto_reg_handoff_ca(void)
{
    static int Initialized=FALSE;

    if (!Initialized)
    {   ca_handle = create_dissector_handle( dissect_ca, proto_ca );
	dissector_add_uint( "udp.port", global_ca_server_port, ca_handle );
	dissector_add_uint( "tcp.port", global_ca_server_port, ca_handle );
	dissector_add_uint( "udp.port", global_ca_repeater_port, ca_handle );
	dissector_add_uint( "tcp.port", global_ca_repeater_port, ca_handle );
	Initialized=TRUE;
    }
}

void
proto_register_ca(void)
{
    module_t *ca_module;

    if (proto_ca == -1)
    {
	proto_ca = proto_register_protocol(  "EPICS Channel Access" /* name (X11 keeps this short also) */
					   , "CA" 	    /* short name */
					   , "ca"	    /* abbrev */
					  );
	proto_register_field_array( proto_ca, hf, array_length(hf) );
	proto_register_subtree_array( ett, array_length(ett) );
    }
    ca_module = prefs_register_protocol( proto_ca, proto_reg_handoff_ca );
}	




/*
 *  With "tab-width: 4" tabs and spaces could get mixed (especially in
 *  environments where c-backspace-function is backward-delete-char-untabify)
 *  which could make things a mess in other "tab-width" environments. (Always
 *  tabifying would work, but require a lot of discipline.)
 *  Local variables:
 *    tab-width: 8
 *    c-tab-always-indent: nil
 *    c-basic-offset: 4
 *    c-file-offsets: ((substatement-open . 0)
                       (statement         . c-lineup-runin-statements)
                       (label             . -1000)
                       (arglist-intro     . c-lineup-arglist-intro-after-paren)
                       (arglist-cont      . c-lineup-arglist-intro-after-paren)
                       (arglist-cont-nonempty . c-lineup-arglist-intro-after-paren)
                       (arglist-close     . c-lineup-arglist-intro-after-paren)
                      )
 *  End:
 */

/* from epics base -- string down */

#ifndef INCLdb_accessh
#define INCLdb_accessh

/* database field types */
#define DBF_STRING      0
#define DBF_INT         1
#define DBF_SHORT       1
#define DBF_FLOAT       2
#define DBF_ENUM        3
#define DBF_CHAR        4
#define DBF_LONG        5
#define DBF_DOUBLE      6
#define DBF_NO_ACCESS   7
#define LAST_TYPE       DBF_DOUBLE
#define VALID_DB_FIELD(x)       ((x >= 0) && (x <= LAST_TYPE))
#define INVALID_DB_FIELD(x)     ((x < 0) || (x > LAST_TYPE))

/* data request buffer types */
#define DBR_STRING      DBF_STRING      
#define DBR_INT         DBF_INT         
#define DBR_SHORT       DBF_INT         
#define DBR_FLOAT       DBF_FLOAT       
#define DBR_ENUM        DBF_ENUM
#define DBR_CHAR        DBF_CHAR
#define DBR_LONG        DBF_LONG
#define DBR_DOUBLE      DBF_DOUBLE
#define DBR_STS_STRING	7
#define	DBR_STS_SHORT	8
#define	DBR_STS_INT	DBR_STS_SHORT	
#define	DBR_STS_FLOAT	9
#define	DBR_STS_ENUM	10
#define	DBR_STS_CHAR	11
#define	DBR_STS_LONG	12
#define	DBR_STS_DOUBLE	13
#define	DBR_TIME_STRING	14
#define	DBR_TIME_INT	15
#define	DBR_TIME_SHORT	15
#define	DBR_TIME_FLOAT	16
#define	DBR_TIME_ENUM	17
#define	DBR_TIME_CHAR	18
#define	DBR_TIME_LONG	19
#define	DBR_TIME_DOUBLE	20
#define	DBR_GR_STRING	21
#define	DBR_GR_SHORT	22
#define	DBR_GR_INT	DBR_GR_SHORT	
#define	DBR_GR_FLOAT	23
#define	DBR_GR_ENUM	24
#define	DBR_GR_CHAR	25
#define	DBR_GR_LONG	26
#define	DBR_GR_DOUBLE	27
#define	DBR_CTRL_STRING	28
#define DBR_CTRL_SHORT	29
#define DBR_CTRL_INT	DBR_CTRL_SHORT	
#define	DBR_CTRL_FLOAT	30
#define DBR_CTRL_ENUM	31
#define	DBR_CTRL_CHAR	32
#define	DBR_CTRL_LONG	33
#define	DBR_CTRL_DOUBLE	34
#define DBR_PUT_ACKT	DBR_CTRL_DOUBLE + 1
#define DBR_PUT_ACKS    DBR_PUT_ACKT + 1
#define DBR_STSACK_STRING DBR_PUT_ACKS + 1
#define DBR_CLASS_NAME DBR_STSACK_STRING + 1
#define	LAST_BUFFER_TYPE	DBR_CLASS_NAME
#define	VALID_DB_REQ(x)	((x >= 0) && (x <= LAST_BUFFER_TYPE))
#define	INVALID_DB_REQ(x)	((x < 0) || (x > LAST_BUFFER_TYPE))


#endif /* INCLdb_accessh */

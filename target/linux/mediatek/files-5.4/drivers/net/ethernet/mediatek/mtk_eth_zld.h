#define MDIO_DEV0	0x0
#define MDIO_DEV7	0x7
#define MDIO_DEV30	0x1e
#define SGMII_CONTROL	0x8
#define STD_AN_ADV	0x4
#define STD_GCTRL	0x9
#define ANEG_MGBT_AN_CTRL	0x20
#define MII_STATUS	0x18
#define MII_ST_LINK	BIT(10)
#define MII_ST_DPX	BIT(3)
#define MII_ST_LINK_S	0xa
#define MII_ST_DPX_S	0x3
#define SPEED10_HALF	BIT(0)
#define SPEED10_FULL	BIT(1)
#define SPEED100_HALF	BIT(2)
#define SPEED100_FULL	BIT(3)
#define SPEED1000_FULL	BIT(4)
#define SPEED2500_FULL	BIT(5)
#define AN_DEFAULT	BIT(6)

#define MT7531_PORT_ID			31
#define MT7531_CREV			0x781C
#define CHIP_NAME_SHIFT			16
#define MT7531_ID			0x7531
#define MT7530_CPU_PORT			6

#define GPY211_PORT_ID			5
#define GPY211_PHYID1			0x67C9

/* Register for port control */
#define MT7530_PCR_P(x)			(0x2004 + ((x) * 0x100))
#define PORT_MATRIX_S			16
#define PORT_MATRIX_M			(0xff << PORT_MATRIX_S)
#define PORT_MATRIX_SET_PORT(x)		(BIT(x) << PORT_MATRIX_S)
#define PORT_MATRIX_CLR_PORT(x)		~(BIT(x) << PORT_MATRIX_S)
#define  PORT_TX_MIR			BIT(9)
#define  PORT_RX_MIR			BIT(8)
#define  PORT_VLAN(x)			((x) & 0x3)

/* Register for port vlan control */
#define MT7530_PVC_P(x)			(0x2010 + ((x) * 0x100))
#define STAG_VPID_S			16
#define VLAN_ATTR_S			6
#define  PORT_SPEC_TAG			BIT(5)
#define  PVC_EG_TAG(x)			(((x) & 0x7) << 8)
#define  PVC_EG_TAG_MASK		PVC_EG_TAG(7)
#define  VLAN_ATTR(x)			(((x) & 0x3) << 6)
#define  VLAN_ATTR_MASK			VLAN_ATTR(3)

/* Register for port port-and-protocol based vlan 1 control */
#define MT7530_PPBV1_P(x)		(0x2014 + ((x) * 0x100))
#define  G0_PORT_VID(x)			(((x) & 0xfff) << 0)
#define  G0_PORT_VID_MASK		G0_PORT_VID(0xfff)
#define  G0_PORT_VID_DEF		G0_PORT_VID(1)

#define MT7530_PMSR_P(x)		(0x3008 + (x) * 0x100)
#define  PMSR_EEE1G			BIT(7)
#define  PMSR_EEE100M			BIT(6)
#define  PMSR_RX_FC			BIT(5)
#define  PMSR_TX_FC			BIT(4)
#define  PMSR_SPEED_1000		BIT(3)
#define  PMSR_SPEED_100			BIT(2)
#define  PMSR_SPEED_10			0x00
#define  PMSR_SPEED_MASK		(PMSR_SPEED_100 | PMSR_SPEED_1000)
#define  PMSR_DPX			BIT(1)
#define  PMSR_LINK			BIT(0)

/* Register for MIB */
#define MT7530_PORT_MIB_COUNTER(x)	(0x4000 + (x) * 0x100)
#define MT7530_MIB_CCR			0x4fe0
#define CCR_MIB_ENABLE			BIT(31)
#define CCR_RX_OCT_CNT_GOOD		BIT(7)
#define CCR_RX_OCT_CNT_BAD		BIT(6)
#define CCR_TX_OCT_CNT_GOOD		BIT(5)
#define CCR_TX_OCT_CNT_BAD		BIT(4)
#define CCR_MIB_FLUSH			(CCR_RX_OCT_CNT_GOOD | \
					 CCR_RX_OCT_CNT_BAD | \
					 CCR_TX_OCT_CNT_GOOD | \
					 CCR_TX_OCT_CNT_BAD)
#define  CCR_MIB_ACTIVATE		(CCR_MIB_ENABLE | \
					 CCR_RX_OCT_CNT_GOOD | \
					 CCR_RX_OCT_CNT_BAD | \
					 CCR_TX_OCT_CNT_GOOD | \
					 CCR_TX_OCT_CNT_BAD)

/* Register for vlan table control */
#define VTCR			0x90
#define VTCR_BUSY			BIT(31)
#define VTCR_INVALID			BIT(16)
#define VTCR_FUNC(x)			(((x) & 0xf) << 12)
#define VTCR_VID			((x) & 0xfff)

/* Register for setup vlan and acl write data */
#define VAWD1			0x94
#define PORT_STAG			BIT(31)
/* Independent VLAN Learning */
#define IVL_MAC				BIT(30)
#define EG_CON				BIT(29)
/* Per VLAN Egress Tag Control */
#define VTAG_EN				BIT(28)
/* VLAN Member Control */
#define PORT_MEM(x)			(((x) & 0xff) << 16)
/* VLAN Entry Valid */
#define VENTRY_VALID			BIT(0)
#define PORT_MEM_SHFT			16
#define PORT_MEM_MASK			0xff0000

#define VAWD2			0x98
#define PORT_ETAG_S(p)			((p) * 2)

/* Values of Egress TAG Control */
#define ETAG_CTRL_UNTAG			0
#define ETAG_CTRL_SWAP			1
#define ETAG_CTRL_TAG			2
#define ETAG_CTRL_STACK			3

#define MT753X_NUM_PORTS	7

enum mt7530_vlan_cmd {
	/* Read/Write the specified VID entry from VAWD register based
	 * on VID.
	 */
	MT7530_VTCR_RD_VID = 0,
	MT7530_VTCR_WR_VID = 1,
};

typedef struct {
	u64 tx_bytes;
	u64 tx_packets;
	u64 tx_skip;
	u64 tx_collisions;
	u64 tx_bcasts;
	u64 tx_drop;
	u64 tx_errs;
	u64 rx_bytes;
	u64 rx_packets;
	u64 rx_bcasts;
	u64 rx_multicasts;
	u64 rx_drop;
	u64 rx_errs;
	u64 rx_overflow;
	u64 rx_fcs_errors;
	u64 rx_short_errors;
	u64 rx_long_errors;
	u64 rx_checksum_errors;
	u64 rx_flow_control_packets;
}zld_mib_counter_t;

#define MIB_DESC(_s, _o, _n)	\
	{			\
		.size = (_s),	\
		.offset = (_o),	\
		.name = (_n),	\
	}

enum mib_info{
	TxDrop = 0,
	TxCRC,
	TxUni,
	TxMulti,
	TxBroad,
	TxCollision,
	TxSingleCol,
	TxMultiCol,
	TxDefer,
	TxLateCol,
	TxExcCol,
	TxPause,
	Tx64Byte,
	Tx65Byte,
	Tx128Byte,
	Tx256Byte,
	Tx512Byte,
	Tx1024Byte,
	TxByte,
	RxDrop,
	RxFiltered,
	RxUni,
	RxMulti,
	RxBroad,
	RxAlignErr,
	RxCRC,
	RxUnderSize,
	RxFragment,
	RxOverSize,
	RxJabber,
	RxPause,
	Rx64Byte,
	Rx65Byte,
	Rx128Byte,
	Rx256Byte,
	Rx512Byte,
	Rx1024Byte,
	RxByte,
	RxCtrlDrop,
	RxIngDrop,
	RxARLDrop,
};

struct mt7530_mib_desc {
	unsigned int size;
	unsigned int offset;
	const char *name;
};

void zld_mii_read(struct net_device *netdev, int port, u16 dev, u16 reg, u32 *data);
void zld_mii_write(struct net_device *netdev, int port, u16 dev, u16 reg, u32 data);
void zld_mt7981_set_port_power_down(struct net_device *netdev, int port);
void zld_mt7981_set_port_power_up(struct net_device *netdev, int port);
void zld_mt7981_set_port_link(struct net_device *netdev, int port, u8 link);
void zld_mt7981_get_port_link(struct net_device *netdev, int port, u32 *link);
void zld_mt7981_mibcounter_reset(struct net_device *dev);
void zld_mt7981_mibcounter_get(struct net_device *dev, int port, zld_mib_counter_t *mib_counter);
void zld_mt753x_reg_read(uint32_t reg, uint32_t *value);
void zld_mt753x_reg_write(uint32_t reg, uint32_t value);
uint32_t get_chip_id(struct net_device *netdev);
void zld_mt7981_get_pvid(struct net_device *netdev, int port, uint32_t *pvid);
void zld_mt7981_set_pvid(struct net_device *netdev, int port, uint32_t pvid);
void zld_mt753x_port_mode_set(int port, uint32_t mode);
void zld_mt753x_port_attr_set(int port, uint32_t attr, uint32_t port_stag);
void zld_mt753x_read_vlan_entry(u32 vid, u32 *member, u32 *etags);
void zld_mt753x_write_vlan_entry(u16 vid, u8 member, u8 etags);

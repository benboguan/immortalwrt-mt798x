#include <linux/trace_seq.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/u64_stats_sync.h>
#include <linux/dma-mapping.h>
#include <linux/netdevice.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/of_mdio.h>
#include <linux/mii.h>

#include "mtk_eth_soc.h"
#include "mtk_eth_dbg.h"
#include "mtk_eth_reset.h"
#include "mtk_eth_zld.h"

/* String, offset, and register size in bytes if different from 4 bytes */
static const struct mt7530_mib_desc mt753x_mibs[] = {
	MIB_DESC(1, 0x00, "TxDrop"),
	MIB_DESC(1, 0x04, "TxCrcErr"),
	MIB_DESC(1, 0x08, "TxUnicast"),
	MIB_DESC(1, 0x0c, "TxMulticast"),
	MIB_DESC(1, 0x10, "TxBroadcast"),
	MIB_DESC(1, 0x14, "TxCollision"),
	MIB_DESC(1, 0x18, "TxSingleCollision"),
	MIB_DESC(1, 0x1c, "TxMultipleCollision"),
	MIB_DESC(1, 0x20, "TxDeferred"),
	MIB_DESC(1, 0x24, "TxLateCollision"),
	MIB_DESC(1, 0x28, "TxExcessiveCollistion"),
	MIB_DESC(1, 0x2c, "TxPause"),
	MIB_DESC(1, 0x30, "TxPktSz64"),
	MIB_DESC(1, 0x34, "TxPktSz65To127"),
	MIB_DESC(1, 0x38, "TxPktSz128To255"),
	MIB_DESC(1, 0x3c, "TxPktSz256To511"),
	MIB_DESC(1, 0x40, "TxPktSz512To1023"),
	MIB_DESC(1, 0x44, "Tx1024ToMax"),
	MIB_DESC(2, 0x48, "TxBytes"),
	MIB_DESC(1, 0x60, "RxDrop"),
	MIB_DESC(1, 0x64, "RxFiltering"),
	MIB_DESC(1, 0x68, "RxUnicast"),
	MIB_DESC(1, 0x6c, "RxMulticast"),
	MIB_DESC(1, 0x70, "RxBroadcast"),
	MIB_DESC(1, 0x74, "RxAlignErr"),
	MIB_DESC(1, 0x78, "RxCrcErr"),
	MIB_DESC(1, 0x7c, "RxUnderSizeErr"),
	MIB_DESC(1, 0x80, "RxFragErr"),
	MIB_DESC(1, 0x84, "RxOverSzErr"),
	MIB_DESC(1, 0x88, "RxJabberErr"),
	MIB_DESC(1, 0x8c, "RxPause"),
	MIB_DESC(1, 0x90, "RxPktSz64"),
	MIB_DESC(1, 0x94, "RxPktSz65To127"),
	MIB_DESC(1, 0x98, "RxPktSz128To255"),
	MIB_DESC(1, 0x9c, "RxPktSz256To511"),
	MIB_DESC(1, 0xa0, "RxPktSz512To1023"),
	MIB_DESC(1, 0xa4, "RxPktSz1024ToMax"),
	MIB_DESC(2, 0xa8, "RxBytes"),
	MIB_DESC(1, 0xb0, "RxCtrlDrop"),
	MIB_DESC(1, 0xb4, "RxIngressDrop"),
	MIB_DESC(1, 0xb8, "RxArlDrop"),
};

extern u32 mt7530_mdio_r32(struct mtk_eth *eth, u32 reg);
extern void mt7530_mdio_w32(struct mtk_eth *eth, u16 reg, u32 val);
extern struct mtk_eth *g_eth;
extern int zld_mt7531_ind_phy_read(int port, int regnum);
extern int zld_mt7531_ind_phy_write(int port, int regnum, u16 data);

void zld_mt753x_reg_read(uint32_t reg, uint32_t *value)
{
	struct mtk_eth *eth = g_eth;

	if (!eth) {
		pr_err("%s, mtk eth retrive fail!\n", __func__);
		return;
	}
	*value = mt7530_mdio_r32(eth, reg);
	return;
}
EXPORT_SYMBOL(zld_mt753x_reg_read);

void zld_mt753x_reg_write(uint32_t reg, uint32_t value)
{
	struct mtk_eth *eth = g_eth;

	if (!eth) {
		pr_err("%s, mtk eth retrive fail!\n", __func__);
		return;
	}
	mt7530_mdio_w32(eth, (u16)reg, value);
	return;
}
EXPORT_SYMBOL(zld_mt753x_reg_write);

void zld_mii_read(struct net_device *netdev, int port, u16 dev, u16 reg, u32 *data)
{
	struct mtk_mac *mac = NULL;
	struct mtk_eth *eth = NULL;
	u32 reg_val = 0;

	if(!( mac = netdev_priv(netdev))){
		pr_err("%s, mtk mac retrive fail!\n", __func__);
		return;
	}
	if(!(eth = mac->hw)){
		pr_err("%s, mtk eth retrive fail!\n", __func__);
		return;
	}
	mutex_lock(&eth->mii_bus->mdio_lock);
	reg_val = _mtk_mdio_read(eth, port, mdiobus_c45_addr(dev, reg));
	mutex_unlock(&eth->mii_bus->mdio_lock);

	*data = reg_val;
	return;
}
EXPORT_SYMBOL(zld_mii_read);

void zld_mii_write(struct net_device *netdev, int port, u16 dev, u16 reg, u32 data)
{
	struct mtk_mac *mac = NULL;
	struct mtk_eth *eth = NULL;

	if(!( mac = netdev_priv(netdev))){
		pr_err("%s, mtk mac retrive fail!\n", __func__);
		return;
	}
	if(!(eth = mac->hw)){
		pr_err("%s, mtk eth retrive fail!\n", __func__);
		return;
	}
	mutex_lock(&eth->mii_bus->mdio_lock);
	_mtk_mdio_write(eth, port, mdiobus_c45_addr(dev, reg), (u16)data);
	mutex_unlock(&eth->mii_bus->mdio_lock);

	return;
}
EXPORT_SYMBOL(zld_mii_write);

uint32_t get_chip_id(struct net_device *netdev)
{
	uint32_t value = 0;

	zld_mt753x_reg_read(MT7531_CREV, &value);
	value >>= CHIP_NAME_SHIFT;
	if (value == MT7531_ID)
		return value;

	zld_mii_read(netdev, GPY211_PORT_ID, MDIO_DEV0, MII_PHYSID1, &value);
	if (value == GPY211_PHYID1)
		return value;

	return value;
}
EXPORT_SYMBOL(get_chip_id);

void zld_mt7981_set_port_power_down(struct net_device *netdev, int port)
{
	u32 reg_val = 0;

	reg_val = get_chip_id(netdev);

	switch (reg_val) {
	case GPY211_PHYID1:
		zld_mii_read(netdev, port, MDIO_DEV0, MII_BMCR, &reg_val);
		reg_val |= BMCR_PDOWN;
		zld_mii_write(netdev, port, MDIO_DEV0, MII_BMCR, reg_val);
		break;
	case MT7531_ID:
		reg_val = zld_mt7531_ind_phy_read(port, MII_BMCR);
		reg_val |= BMCR_PDOWN;
		zld_mt7531_ind_phy_write(port, MII_BMCR, (u16)reg_val);
		break;
	default:
		pr_err("[%s] No Chip or PHY ID found\n", __func__);
		return;
	}
	return;
}
EXPORT_SYMBOL(zld_mt7981_set_port_power_down);

void zld_mt7981_set_port_power_up(struct net_device *netdev, int port)
{
	u32 reg_val = 0;

	reg_val = get_chip_id(netdev);

	switch (reg_val) {
	case GPY211_PHYID1:
		zld_mii_read(netdev, port, MDIO_DEV0, MII_BMCR, &reg_val);
		reg_val &= ~BMCR_PDOWN;
		zld_mii_write(netdev, port, MDIO_DEV0, MII_BMCR, reg_val);
		break;
	case MT7531_ID:
		reg_val = zld_mt7531_ind_phy_read(port, MII_BMCR);
		reg_val &= ~BMCR_PDOWN;
		zld_mt7531_ind_phy_write(port, MII_BMCR, (u16)reg_val);
		break;
	default:
		pr_err("[%s] No Chip or PHY ID found\n", __func__);
		return;
	}
	return;
}
EXPORT_SYMBOL(zld_mt7981_set_port_power_up);

/* BMCR_SPEED10		0x0000 */ /* MSB(bit6) LSB(bit13) 0 0 -> 10Mbit/s   */
/* BMCR_SPEED100	0x2000 */ /* MSB(bit6) LSB(bit13) 0 1 -> 100Mbit/s  */
/* BMCR_SPEED1000	0x0040 */ /* MSB(bit6) LSB(bit13) 1 0 -> 1000Mbit/s */
/* SPEED2500            0x2040 */ /* MSB(bit6) LSB(bit13) 1 1 -> 2500Mbit/s */
/* PMA_CTRL 1.0.5:2 [0 1 1 0] should set for default 2500Mbit/s setting.    */
/* BMCR_ANENABLE	0x1000 */
/* BMCR_ANRESTART	0x0200 */
/* BMCR_FULLDPLX	0x0100 */
void gpy211_set_port_link(struct net_device *netdev, int port, u8 link)
{
	u32 reg_val = 0;

	switch (link) {
	case SPEED10_FULL:
	case SPEED10_HALF:
	case SPEED100_FULL:
	case SPEED100_HALF:
	case AN_DEFAULT:
		/* Apply default for ANEG_MGBT_AN_CTRL, STD_GCTRL, and STD_AN_ADV registers */
		/* mii_mgr_cl45 -s -p 0x5 -d 0x7 -r 0x20 -v 0x40A2 */
		/* mii_mgr_cl45 -s -p 0x5 -d 0x0 -r 0x9 -v 0x300 */
		/* mii_mgr_cl45 -s -p 0x5 -d 0x0 -r 0x4 -v 0x0DE1 */
		zld_mii_write(netdev, port, MDIO_DEV7, ANEG_MGBT_AN_CTRL, 0x40A2);
		zld_mii_write(netdev, port, MDIO_DEV0, STD_GCTRL, 0x300);
		zld_mii_write(netdev, port, MDIO_DEV0, STD_AN_ADV, 0x0DE1);

		switch (link) {
		case SPEED10_FULL:
			/* mii_mgr_cl45 -s -p 0x5 -d 0x0 -r 0x0 -v 0x100 */
			reg_val = (BMCR_SPEED10 | BMCR_FULLDPLX);
			break;
		case SPEED10_HALF:
			/* mii_mgr_cl45 -s -p 0x5 -d 0x0 -r 0x0 -v 0x0 */
			reg_val = BMCR_SPEED10;
			break;
		case SPEED100_FULL:
			/* mii_mgr_cl45 -s -p 0x5 -d 0x0 -r 0x0 -v 0x2100 */
			reg_val = (BMCR_SPEED100 | BMCR_FULLDPLX);
			break;
		case SPEED100_HALF:
			/* mii_mgr_cl45 -s -p 0x5 -d 0x0 -r 0x0 -v 0x2000 */
			reg_val = BMCR_SPEED100;
			break;
		default:
			break;
		}
		/* mii_mgr_cl45 -s -p 0x5 -d 0x0 -r 0x0 -v reg_val */
		zld_mii_write(netdev, port, MDIO_DEV0, MII_BMCR, reg_val);
		break;
	case SPEED1000_FULL:
	case SPEED2500_FULL:
		reg_val = (BMCR_ANENABLE | BMCR_ANRESTART | BMCR_SPEED1000 | BMCR_SPEED100 | BMCR_SPEED10);

		switch (link) {
		case SPEED1000_FULL:
			/* mii_mgr_cl45 -s -p 0x5 -d 0x7 -r 0x20 -v 0x0 */
			/* mii_mgr_cl45 -s -p 0x5 -d 0x0 -r 0x9 -v 0x200 */
			zld_mii_write(netdev, port, MDIO_DEV7, ANEG_MGBT_AN_CTRL, 0x0);
			zld_mii_write(netdev, port, MDIO_DEV0, STD_GCTRL, 0x200);
			break;
		case SPEED2500_FULL:
			/* mii_mgr_cl45 -s -p 0x5 -d 0x7 -r 0x20 -v 0x0082 */
			/* mii_mgr_cl45 -s -p 0x5 -d 0x0 -r 0x9 -v 0x0 */
			zld_mii_write(netdev, port, MDIO_DEV7, ANEG_MGBT_AN_CTRL, 0x0082);
			zld_mii_write(netdev, port, MDIO_DEV0, STD_GCTRL, 0x0);
			break;
		default:
			break;
		}
		/* mii_mgr_cl45 -s -p 0x5 -d 0x0 -r 0x4 -v 0x0C01 */
		/* mii_mgr_cl45 -s -p 0x5 -d 0x0 -r 0x0 -v 0x3240 */
		zld_mii_write(netdev, port, MDIO_DEV0, STD_AN_ADV, 0x0C01);
		zld_mii_write(netdev, port, MDIO_DEV0, MII_BMCR, reg_val);
		break;
	default:
		break;
	}
	/* Force control the SGMII interface to remain in 2.5G speed  */
	/* mii_mgr_cl45 -s -p 0x5 -d 0x1e -r 0x8 -v 0x24e2 */
	zld_mii_write(netdev, port, MDIO_DEV30, SGMII_CONTROL, 0x24e2);

	return;
}

void zld_mt7981_set_port_link(struct net_device *netdev, int port, u8 link)
{
	u32 reg_val = 0;

	reg_val = get_chip_id(netdev);
	switch (reg_val) {
	case GPY211_PHYID1:
		gpy211_set_port_link(netdev, port, link);
		break;
	default:
		pr_err("[%s] No Chip or PHY ID found\n", __func__);
		return;
	}
	return;
}
EXPORT_SYMBOL(zld_mt7981_set_port_link);

void zld_mt7981_get_port_link(struct net_device *netdev, int port, u32 *link)
{
	u32 data = 0;

	data = get_chip_id(netdev);
	switch (data) {
	case GPY211_PHYID1:
		/* Media-Independent Interface Status (Register 0.24) */
		zld_mii_read(netdev, port, MDIO_DEV0, MII_STATUS, &data);
		break;
	case MT7531_ID:
		zld_mt753x_reg_read(MT7530_PMSR_P(port), &data);
		break;
	default:
		break;
	}
	*link = data;
	return;
}
EXPORT_SYMBOL(zld_mt7981_get_port_link);

u64 get_mib_counter(int i, int port)
{
	u32 reg = 0;
	u32 lo = 0;
	u32 hi = 0;
	u64 data = 0;

	reg = MT7530_PORT_MIB_COUNTER(port) + mt753x_mibs[i].offset;

	zld_mt753x_reg_read(reg, &lo);

	data |= lo;
	if (mt753x_mibs[i].size == 2) {
		zld_mt753x_reg_read(reg + 4, &hi);
		data |= (hi << 32);
	}
	return data;
}

void zld_mt7981_mibcounter_reset(struct net_device *dev)
{
	struct mtk_mac *mac = NULL;
	struct mtk_hw_stats *hw_stats = NULL;
	u32 chip_id = 0;

	chip_id = get_chip_id(dev);
	if (chip_id == GPY211_PHYID1) {
		if (!(mac = netdev_priv(dev))) {
			pr_err("%s, mtk mac retrive fail!\n",__func__);
			return;
		}
		if (!(hw_stats = mac->hw_stats)) {
			pr_err("%s, mtk hw status retrive fail!\n",__func__);
			return;
		}
		u64_stats_update_begin(&hw_stats->syncp);
		hw_stats->rx_bytes = 0;
		hw_stats->rx_packets = 0;
		hw_stats->rx_overflow = 0;
		hw_stats->rx_fcs_errors = 0;
		hw_stats->rx_short_errors = 0;
		hw_stats->rx_long_errors = 0;
		hw_stats->rx_checksum_errors = 0;
		hw_stats->rx_flow_control_packets = 0;
		hw_stats->tx_skip = 0;
		hw_stats->tx_collisions = 0;
		hw_stats->tx_bytes = 0;
		hw_stats->tx_packets = 0;
		u64_stats_update_end(&hw_stats->syncp);
	} else if (chip_id == MT7531_ID) {
		zld_mt753x_reg_write(MT7530_MIB_CCR, CCR_MIB_FLUSH);
		zld_mt753x_reg_write(MT7530_MIB_CCR, CCR_MIB_ACTIVATE);
	}

	return;
}
EXPORT_SYMBOL(zld_mt7981_mibcounter_reset);

void zld_mt7981_mibcounter_get(struct net_device *dev, int port, zld_mib_counter_t *mib_counter)
{
	struct mtk_mac *mac = NULL;
	struct mtk_hw_stats *hw_stats = NULL;
	unsigned int start;
	u32 chip_id = 0;

	chip_id = get_chip_id(dev);

	if (chip_id == GPY211_PHYID1) {
		if (!(mac = netdev_priv(dev))) {
			pr_err("%s, mtk mac retrive fail!\n", __func__);
			return;
		}
		if (!(hw_stats = mac->hw_stats)) {
			pr_err("%s, mtk hw status retrive fail!\n", __func__);
			return;
		}

		if (netif_running(dev) && netif_device_present(dev)) {
			if (spin_trylock_bh(&hw_stats->stats_lock)) {
				mtk_stats_update_mac(mac);
				spin_unlock_bh(&hw_stats->stats_lock);
			}
		}
		do {
			start = u64_stats_fetch_begin_irq(&hw_stats->syncp);

			mib_counter->tx_bytes = hw_stats->tx_bytes;
			mib_counter->tx_packets = hw_stats->tx_packets;
			mib_counter->tx_collisions = hw_stats->tx_collisions;
			mib_counter->tx_bcasts = 0;
			mib_counter->tx_drop = 0;
			mib_counter->tx_errs = 0;
			mib_counter->rx_bytes = hw_stats->rx_bytes;
			mib_counter->rx_packets = hw_stats->rx_packets;
			mib_counter->rx_overflow = hw_stats->rx_overflow;
			mib_counter->rx_fcs_errors = hw_stats->rx_fcs_errors;
			mib_counter->rx_short_errors = hw_stats->rx_short_errors;
			mib_counter->rx_long_errors = hw_stats->rx_long_errors;
			mib_counter->rx_checksum_errors = hw_stats->rx_checksum_errors;
			mib_counter->rx_flow_control_packets = hw_stats->rx_flow_control_packets;
			mib_counter->rx_bcasts = 0;
			mib_counter->rx_multicasts = 0;
			mib_counter->rx_drop = 0;
			mib_counter->rx_errs = 0;
		} while (u64_stats_fetch_retry_irq(&hw_stats->syncp, start));
	} else if (chip_id == MT7531_ID) {
		mib_counter->tx_bytes = get_mib_counter(TxByte, port);
		mib_counter->tx_packets = get_mib_counter(Tx64Byte, port) + \
					  get_mib_counter(Tx65Byte, port) + \
					  get_mib_counter(Tx128Byte, port) + \
					  get_mib_counter(Tx256Byte, port) + \
					  get_mib_counter(Tx512Byte, port) + \
					  get_mib_counter(Tx1024Byte, port);
		mib_counter->tx_collisions = get_mib_counter(TxCollision, port);
		mib_counter->tx_bcasts = get_mib_counter(TxBroad, port);
		mib_counter->tx_drop = get_mib_counter(TxDrop, port);
		mib_counter->tx_errs = get_mib_counter(TxCRC, port);

		mib_counter->rx_bytes = get_mib_counter(RxByte, port);
		mib_counter->rx_packets = get_mib_counter(Rx64Byte, port) + \
					  get_mib_counter(Rx65Byte, port) + \
					  get_mib_counter(Rx128Byte, port) + \
					  get_mib_counter(Rx256Byte, port) + \
					  get_mib_counter(Rx512Byte, port) + \
					  get_mib_counter(Rx1024Byte, port);
		mib_counter->rx_bcasts = get_mib_counter(RxBroad, port);
		mib_counter->rx_multicasts = get_mib_counter(RxMulti, port);
		mib_counter->rx_drop = get_mib_counter(RxDrop, port);
		mib_counter->rx_errs = get_mib_counter(RxAlignErr, port) +\
				       get_mib_counter(RxCRC, port) +\
				       get_mib_counter(RxUnderSize, port) +\
				       get_mib_counter(RxOverSize, port) +\
				       get_mib_counter(RxFragment, port) +\
				       get_mib_counter(RxJabber, port);
	}
	return;
}
EXPORT_SYMBOL(zld_mt7981_mibcounter_get);

void zld_mt7981_get_pvid(struct net_device *netdev, int port, uint32_t *pvid)
{
	uint32_t reg_val = 0;

	if (get_chip_id(netdev) == MT7531_ID) {
		zld_mt753x_reg_read(MT7530_PPBV1_P(port), &reg_val);
		*pvid = reg_val & G0_PORT_VID_MASK;
	}
	return;
}
EXPORT_SYMBOL(zld_mt7981_get_pvid);

void zld_mt7981_set_pvid(struct net_device *netdev, int port, uint32_t pvid)
{
	uint32_t reg_val = 0;

	if (get_chip_id(netdev) == MT7531_ID) {
		zld_mt753x_reg_read(MT7530_PPBV1_P(port), &reg_val);
		reg_val &= ~G0_PORT_VID_MASK;
		reg_val |= pvid;
		zld_mt753x_reg_write(MT7530_PPBV1_P(port), reg_val);
	}
	return;
}
EXPORT_SYMBOL(zld_mt7981_set_pvid);

void zld_mt753x_port_mode_set(int port, uint32_t mode)
{
	zld_mt753x_reg_write(MT7530_PCR_P(port), mode);
	return;
}
EXPORT_SYMBOL(zld_mt753x_port_mode_set);

void zld_mt753x_port_attr_set(int port, uint32_t attr, uint32_t port_stag)
{
	uint32_t pvc_mode = 0;

	pvc_mode = (0x8100 << STAG_VPID_S) | (attr << VLAN_ATTR_S) | port_stag;
	zld_mt753x_reg_write(MT7530_PVC_P(port), pvc_mode);
	return;
}
EXPORT_SYMBOL(zld_mt753x_port_attr_set);

int mt753x_vlan_tbl_ctrl(uint32_t cmd, uint32_t vid)
{
	uint32_t reg_val = 0;
	uint32_t i = 0;

	reg_val = VTCR_BUSY | VTCR_FUNC(cmd) | vid;
	zld_mt753x_reg_write(VTCR, reg_val);
	for (i = 0; i < 300; i++) {
		zld_mt753x_reg_read(VTCR, &reg_val);
		if ((reg_val & VTCR_BUSY) == 0)
			break;
		mdelay(1);
	}
	if (i == 300) {
		pr_err("MT7531 read VTCR(0x%x) time out\n", VTCR);
		return -1;
	}

	return 0;
}

void zld_mt753x_read_vlan_entry(u32 vid, u32 *member, u32 *etags)
{
	uint32_t reg_val = 0;

	/* Fetch entry by sending read command in VTCR reg */
	if (mt753x_vlan_tbl_ctrl(MT7530_VTCR_RD_VID, vid))
		return;

	zld_mt753x_reg_read(VAWD1, &reg_val);
	reg_val &= PORT_MEM_MASK;
	reg_val >>= PORT_MEM_SHFT;
	*member = reg_val;

	zld_mt753x_reg_read(VAWD2, &reg_val);
	*etags = reg_val;

	return;
}
EXPORT_SYMBOL(zld_mt753x_read_vlan_entry);

void zld_mt753x_write_vlan_entry(u16 vid, u8 member, u8 etags)
{
	int i = 0;
	uint32_t reg_val = 0;

	/* 1. Set VAWD1 for vlan port membership */
	if(0 != member)
		member |= BIT(MT7530_CPU_PORT);
	reg_val = IVL_MAC | VTAG_EN | VENTRY_VALID |
			((member << PORT_MEM_SHFT) & PORT_MEM_MASK);
	zld_mt753x_reg_write(VAWD1, reg_val);

	/* 2. Set VAWD2 for egress mode */
	/* DSA driver will call "mt7530_hw_vlan_add" to setup (VAWD2) port
	 * egress tag when receive NETDEV_REGISTER event while VLAN interface
	 * has created. Setting egress tag by zysh cli command directly.
	 */
	reg_val = 0;
	for (i = 0; i < MT753X_NUM_PORTS; i++) {
		if (etags & BIT(i))
			reg_val |= ETAG_CTRL_TAG << PORT_ETAG_S(i);
		else
			reg_val |= ETAG_CTRL_UNTAG << PORT_ETAG_S(i);
	}
	reg_val |= ETAG_CTRL_STACK << PORT_ETAG_S(MT7530_CPU_PORT);
	zld_mt753x_reg_write(VAWD2, reg_val);

	/* Flush result to hardware by sending write command in VTCR reg */
	if (mt753x_vlan_tbl_ctrl(MT7530_VTCR_WR_VID, vid))
		return;

	return;
}
EXPORT_SYMBOL(zld_mt753x_write_vlan_entry);

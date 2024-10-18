// SPDX-License-Identifier: GPL-2.0+
#include <linux/bitfield.h>
#include <linux/module.h>
#include <linux/phy.h>

#include <linux/of.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define MDIO_MMD_STD_REG_DEV      (0)

// for MMD_DEV_0 (MDIO_MMD_STD_REG_DEV)
#define STD_CTRL_REG_NUM          (0)
#define STD_STAT_REG_NUM          (1)
#define STD_PHY_MII_STAT_REG_NUM  (24)

// for MMD_DEV_7 (MDIO_MMD_AN)
#define ANEG_RESTART_REG_NUM      (0)
#define ANEG_MGBT_REG_NUM         (32)

void phydev_bind_to_master_dev(void *priv, int unit, struct phy_device *phy);
//extern void phydev_bind_to_master_dev(void *priv, int unit, struct phy_device *phy);

static struct phy_device * gpy_phydev_wan = NULL;
static struct phy_device * gpy_phydev_lan5 = NULL;

static int phydev_wan_proc_show(struct seq_file *m, void *v)
{
	int mode = phy_read_mmd(gpy_phydev_wan, MDIO_MMD_STD_REG_DEV, STD_PHY_MII_STAT_REG_NUM);
	int speed = 0;

	switch (mode & 0x7) {
	case 0:
		speed = 10;
		break;
	case 1:
		speed = 100;
		break;
	case 2:
		speed = 1000;
		break;
	case 4:
		speed = 2500;
		break;
	default:
		break;
	}

	seq_printf(m, "link:%s speed:%d duplex:%s\n",
			   ((mode & 0x400) != 0) ? "up":"down",
			   speed,
			   ((mode & 0x8) != 0) ? "full":"half");

	return 0;
}

static int phydev_lan5_proc_show(struct seq_file *m, void *v)
{
	int mode = phy_read_mmd(gpy_phydev_lan5, MDIO_MMD_STD_REG_DEV, STD_PHY_MII_STAT_REG_NUM);
	int speed = 0;

	switch (mode & 0x7) {
	case 0:
		speed = 10;
		break;
	case 1:
		speed = 100;
		break;
	case 2:
		speed = 1000;
		break;
	case 4:
		speed = 2500;
		break;
	default:
		break;
	}

	seq_printf(m, "link:%s speed:%d duplex:%s\n",
			   ((mode & 0x400) != 0) ? "up":"down",
			   speed,
			   ((mode & 0x8) != 0) ? "full":"half");

	return 0;
}

static int phydev_wan_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, phydev_wan_proc_show, inode->i_private);
}

static int phydev_lan5_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, phydev_lan5_proc_show, inode->i_private);
}

static void phy_wan_linkrate_ability(bool abi_2500, bool abi_1000, bool abi_100, bool abi_10)
{
	int data = 0;

	// 2.5G negotiation cap;
	data = phy_read_mmd(gpy_phydev_wan, MDIO_MMD_AN, ANEG_MGBT_REG_NUM);
	if (abi_2500)
	{
		// bit[5] = 1; bit[7] = 1
		data = (data | 0xa0);
	}
	else
	{
		// bit[5] = 0; bit[7] = 0; register_data_length = 16
		data = (data & 0xff5f);
	}
	phy_write_mmd(gpy_phydev_wan, MDIO_MMD_AN, ANEG_MGBT_REG_NUM, data);

	// 1000M cap
	data = phy_read(gpy_phydev_wan, 9);
	if (abi_1000)
	{
		// bit[8] = 1; bit[9] = 1
		data = (data | 0x300);
	}
	else
	{
		// bit[8] = 0; bit[9] = 0
		data = (data & 0xfffffcff);
	}
	phy_write(gpy_phydev_wan, 9, data);

	data = phy_read(gpy_phydev_wan, 4);
	// 100M cap
	if (abi_100)
	{
		// bit[7] = 1; bit[8] = 1
		data = (data | 0x180);
	}
	else
	{
		// bit[7] = 0; bit[8] = 0
		data = (data & 0xfffffe7f);
	}
	// 10M cap
	if (abi_10)
	{
		// bit[5] = 1; bit[6] = 1
		data = (data | 0x60);
	}
	else
	{
		// bit[5] = 0; bit[6] = 0
		data = (data & 0xffffff9f);
	}
	phy_write(gpy_phydev_wan, 4, data);
}

static void phy_lan5_linkrate_ability(bool abi_2500, bool abi_1000, bool abi_100, bool abi_10)
{
	int data = 0;

	// 2.5G negotiation cap;
	data = phy_read_mmd(gpy_phydev_lan5, MDIO_MMD_AN, ANEG_MGBT_REG_NUM);
	if (abi_2500)
	{
		// bit[5] = 1; bit[7] = 1
		data = (data | 0xa0);
	}
	else
	{
		// bit[5] = 0; bit[7] = 0; register_data_length = 16
		data = (data & 0xff5f);
	}
	phy_write_mmd(gpy_phydev_lan5, MDIO_MMD_AN, ANEG_MGBT_REG_NUM, data);

	// 1000M cap
	data = phy_read(gpy_phydev_lan5, 9);
	if (abi_1000)
	{
		// bit[8] = 1; bit[9] = 1
		data = (data | 0x300);
	}
	else
	{
		// bit[8] = 0; bit[9] = 0
		data = (data & 0xfffffcff);
	}
	phy_write(gpy_phydev_lan5, 9, data);

	data = phy_read(gpy_phydev_lan5, 4);
	// 100M cap
	if (abi_100)
	{
		// bit[7] = 1; bit[8] = 1
		data = (data | 0x180);
	}
	else
	{
		// bit[7] = 0; bit[8] = 0
		data = (data & 0xfffffe7f);
	}
	// 10M cap
	if (abi_10)
	{
		// bit[5] = 1; bit[6] = 1
		data = (data | 0x60);
	}
	else
	{
		// bit[5] = 0; bit[6] = 0
		data = (data & 0xffffff9f);
	}
	phy_write(gpy_phydev_lan5, 4, data);
}


static ssize_t phydev_wan_proc_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *pos)
{
	char kbuf[32] = {0};
	int link = 0, mode = 0, data = 0, ret = 0;

	if (count > 0) {
		if (copy_from_user(kbuf, buffer, count > 32 ? 32 : count))
			return -EFAULT;

		ret = sscanf(kbuf, "link:%d mode:%d\n", &link, &mode);
		if (ret < 1)
		{
			return -EFAULT;
		}

		data = phy_read_mmd(gpy_phydev_wan, MDIO_MMD_STD_REG_DEV, STD_CTRL_REG_NUM);

		if (1 == link)
		{
			// just force power on; no mode input
			if (1 == ret)
			{
				// force power on; bit[11] = 0;
				data = data & 0xf7ff;
				phy_write_mmd(gpy_phydev_wan, MDIO_MMD_STD_REG_DEV, STD_CTRL_REG_NUM, data);
				return count;
			}
			// set auto mode or force mode
			else
			{
				// linkUp; enable auto negotiation;
				data = (data | 0x1000) & 0xf7ff;
				phy_write_mmd(gpy_phydev_wan, MDIO_MMD_STD_REG_DEV, STD_CTRL_REG_NUM, data);

				switch (mode) {
				case 0:
					// enable all ability
					phy_wan_linkrate_ability(1, 1, 1, 1);
					break;
				case 2500:
					// disable 1000M/100M/10M negotiation cap
					phy_wan_linkrate_ability(1, 0, 0, 0);
					break;
				case 1000:
					// disable 2.5G/100M/10M negotiation cap
					phy_wan_linkrate_ability(0, 1, 0, 0);
					break;
				case 100:
					// disable 2.5G/1000M/10M negotiation cap
					phy_wan_linkrate_ability(0, 0, 1, 0);
					break;
				case 10:
					// disable 2.5G/1000M/100M negotiation cap
					phy_wan_linkrate_ability(0, 0, 0, 1);
					break;
				default:
					return count;
				}
			}

			// restart auto negotiation; (register 7.0)
			data = phy_read_mmd(gpy_phydev_wan, MDIO_MMD_AN, ANEG_RESTART_REG_NUM);
			data = (data | 0x200);
			phy_write_mmd(gpy_phydev_wan, MDIO_MMD_AN, ANEG_RESTART_REG_NUM, data);

		}
		else if (0 == link)
		{
			// force power off; bit[11] = 1;
			data = data | 0x800;
			phy_write_mmd(gpy_phydev_wan, MDIO_MMD_STD_REG_DEV, STD_CTRL_REG_NUM, data);
		}
	}

	return count;
}

static ssize_t phydev_lan5_proc_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *pos)
{
	char kbuf[32] = {0};
	int link = 0, mode = 0, data = 0, ret = 0;

	if (count > 0) {
		if (copy_from_user(kbuf, buffer, count > 32 ? 32 : count))
			return -EFAULT;

		ret = sscanf(kbuf, "link:%d mode:%d\n", &link, &mode);
		if (ret < 1)
		{
			return -EFAULT;
		}

		data = phy_read_mmd(gpy_phydev_lan5, MDIO_MMD_STD_REG_DEV, STD_CTRL_REG_NUM);

		if (1 == link)
		{
			// just force power on; no mode input
			if (1 == ret)
			{
				// force power on; bit[11] = 0;
				data = data & 0xf7ff;
				phy_write_mmd(gpy_phydev_lan5, MDIO_MMD_STD_REG_DEV, STD_CTRL_REG_NUM, data);
				return count;
			}
			// set auto mode or force mode
			else
			{
				// linkUp; enable auto negotiation;
				data = (data | 0x1000) & 0xf7ff;
				phy_write_mmd(gpy_phydev_lan5, MDIO_MMD_STD_REG_DEV, STD_CTRL_REG_NUM, data);

				switch (mode) {
				case 0:
					// enable all ability
					phy_lan5_linkrate_ability(1, 1, 1, 1);
					break;
				case 2500:
					// disable 1000M/100M/10M negotiation cap
					phy_lan5_linkrate_ability(1, 0, 0, 0);
					break;
				case 1000:
					// disable 2.5G/100M/10M negotiation cap
					phy_lan5_linkrate_ability(0, 1, 0, 0);
					break;
				case 100:
					// disable 2.5G/1000M/10M negotiation cap
					phy_lan5_linkrate_ability(0, 0, 1, 0);
					break;
				case 10:
					// disable 2.5G/1000M/100M negotiation cap
					phy_lan5_linkrate_ability(0, 0, 0, 1);
					break;
				default:
					return count;
				}
			}

			// restart auto negotiation; (register 7.0)
			data = phy_read_mmd(gpy_phydev_lan5, MDIO_MMD_AN, ANEG_RESTART_REG_NUM);
			data = (data | 0x200);
			phy_write_mmd(gpy_phydev_lan5, MDIO_MMD_AN, ANEG_RESTART_REG_NUM, data);

		}
		else if (0 == link)
		{
			// force power off; bit[11] = 1;
			data = data | 0x800;
			phy_write_mmd(gpy_phydev_lan5, MDIO_MMD_STD_REG_DEV, STD_CTRL_REG_NUM, data);
		}
	}

	return count;
}

static const struct file_operations wan_proc_fops = {
	.open  = phydev_wan_proc_open,
	.read  = seq_read,
	.write  = phydev_wan_proc_write,
	.llseek  = seq_lseek,
	.release = single_release,
};

static const struct file_operations lan5_proc_fops = {
	.open  = phydev_lan5_proc_open,
	.read  = seq_read,
	.write  = phydev_lan5_proc_write,
	.llseek  = seq_lseek,
	.release = single_release,
};

static void create_wan_procfs(void)
{
	proc_create("wan_phy", 0x0644, NULL, &wan_proc_fops);
}


static void create_lan5_procfs(void)
{
	proc_create("lan5_phy", 0x0644, NULL, &lan5_proc_fops);
}

static void gpy211_phy_wan_start_work(u32 mac_unit)
{
	create_wan_procfs();
	phydev_bind_to_master_dev(gpy_phydev_wan->mdio.bus->priv, mac_unit, gpy_phydev_wan);
}

static void gpy211_phy_lan5_start_work(void)
{
	create_lan5_procfs();
}

static int gpy211_phy_config_init(struct phy_device *phydev)
{
	return 0;
}

int gpy211_phy_probe(struct phy_device *phydev)
{
	int sgmii_reg;
	u32 partner_mac;
	u32 partner_switch_port;

	struct device_node * node = phydev->mdio.dev.of_node;

	if (0 == of_property_read_u32(node, "partner_gmac", &partner_mac))
	{
		sgmii_reg = phy_read_mmd(phydev, MDIO_MMD_VEND1, 8);

		/* set force 2.5G sgmii and disable auto-negotiation;  */
		phy_write_mmd(phydev, MDIO_MMD_VEND1, 8, 0x24e2);

		gpy_phydev_wan = phydev;

		gpy211_phy_wan_start_work(partner_mac);
	}
	else if (0 == of_property_read_u32(node, "partner_switch_port", &partner_switch_port))
	{
		sgmii_reg = phy_read_mmd(phydev, MDIO_MMD_VEND1, 8);

		/* set force 2.5G sgmii and disable auto-negotiation;  */
		phy_write_mmd(phydev, MDIO_MMD_VEND1, 8, 0x24e2);

		if (5 == partner_switch_port)
		{
			gpy_phydev_lan5 = phydev;
			gpy211_phy_lan5_start_work();
		}
	}
	else
	{
		sgmii_reg = phy_read_mmd(phydev, MDIO_MMD_VEND1, 8);

		/* set force 2.5G sgmii and disable auto-negotiation;  */
		phy_write_mmd(phydev, MDIO_MMD_VEND1, 8, 0x24e2);

	}

	return 0;
}

static int gpy211_get_features(struct phy_device *phydev)
{
	int ret;

	ret = genphy_read_abilities(phydev);
	if (ret)
		return ret;

	/* GPY211 with rate adaption supports 100M/1G/2.5G speed. */
	linkmode_clear_bit(ETHTOOL_LINK_MODE_10baseT_Half_BIT,
			   phydev->supported);
	linkmode_clear_bit(ETHTOOL_LINK_MODE_10baseT_Full_BIT,
			   phydev->supported);
	linkmode_set_bit(ETHTOOL_LINK_MODE_2500baseX_Full_BIT,
			 phydev->supported);

	return 0;
}

static int gpy211_get_link(struct phy_device *phy)
{
	int mode = phy_read_mmd(phy, MDIO_MMD_STD_REG_DEV, STD_PHY_MII_STAT_REG_NUM);

	phy->link = (mode & 0x400) ? 1 : 0;

	switch (mode & 0x7) {
	case 0:
		phy->speed = SPEED_10;
		break;
	case 1:
		phy->speed= SPEED_100;
		break;
	case 2:
		phy->speed = SPEED_1000;
		break;
	case 4:
		phy->speed = SPEED_2500;
		break;
	default:
		break;
	}

	phy->duplex = ((mode & 0x8) != 0) ? DUPLEX_FULL : DUPLEX_HALF;

	return 0;
}

static struct phy_driver gpy211_phy_driver[] = {
	{
		PHY_ID_MATCH_MODEL(0x67c9de0a),
		.name		= "Intel GPY211 PHY",
		.config_init	= gpy211_phy_config_init,
		.probe		= gpy211_phy_probe,
		.get_features	= gpy211_get_features,
		.read_status	= gpy211_get_link,
	}
};

module_phy_driver(gpy211_phy_driver);

static struct mdio_device_id __maybe_unused gpy211_phy_tbl[] = {
	{ PHY_ID_MATCH_VENDOR(0x67c9de00) },
	{ }
};

MODULE_DESCRIPTION("Intel GPY211 PHY driver with rate adaption");
MODULE_AUTHOR("Landen Chao <landen.chao@mediatek.com>");
MODULE_LICENSE("GPL");

MODULE_DEVICE_TABLE(mdio, gpy211_phy_tbl);

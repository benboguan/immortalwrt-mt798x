/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2018 MediaTek Inc.
 * Author: Weijie Gao <weijie.gao@mediatek.com>
 */

#ifndef _MT753X_SWCONFIG_H_
#define _MT753X_SWCONFIG_H_

#ifdef CONFIG_SWCONFIG
#include <linux/switch.h>
#include "mt753x.h"

#define MDIO_DEV0	0x0
#define MDIO_DEV7	0x7
#define MDIO_DEV30	0x1e
#define SGMII_CONTROL	0x8
#define STD_AN_ADV	0x4
#define STD_GCTRL	0x9
#define ANEG_MGBT_AN_CTRL	0x20
#define MII_STATUS	0x18
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

#define GPY211_PORT_ID			5
#define GPY211_PHYID1			0x67C9

int mt753x_swconfig_init(struct gsw_mt753x *gsw);
void mt753x_swconfig_destroy(struct gsw_mt753x *gsw);
#else
static inline int mt753x_swconfig_init(struct gsw_mt753x *gsw)
{
	mt753x_apply_vlan_config(gsw);

	return 0;
}

static inline void mt753x_swconfig_destroy(struct gsw_mt753x *gsw)
{
}
#endif

#endif /* _MT753X_SWCONFIG_H_ */

/*
 * Copyright (c) 2026 Google LLC
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * MPU layout for the replayer.
 *
 * The SoC ships a single MPU region covering the whole of SRAM, and for a
 * CONFIG_XIP=n image Zephyr deliberately leaves that region executable (see
 * REGION_RAM_ATTR in arm_mpu_v8.h) because the code lives there too. That
 * gives up write xor execute: the parser writes into buffers which sit in
 * executable memory, and the code the bootrom verified stays writable.
 *
 * This splits SRAM in two instead:
 *
 *   __rom_region_start .. __rom_region_end   the image: read only, executable
 *   _image_ram_start   .. end of SRAM        data: writable, never executable
 *
 * For a XIP build this falls back to what the SoC does, since there the code
 * is in flash, which is mapped read only anyway.
 *
 * This file defines mpu_config, which soc/raspberrypi/rpi_pico/rp2350 defines
 * as well. Zephyr links its libraries with --whole-archive, so the two would
 * collide; CMakeLists.txt drops the SoC's file from the build.
 */

#include <hardware/regs/addressmap.h>

#include <zephyr/arch/arm/mpu/arm_mpu.h>
#include <zephyr/arch/arm/mpu/arm_mpu_mem_cfg.h>
#include <zephyr/linker/linker-defs.h>
#include <zephyr/sys/util.h>

#define RP2350_BOOTROM_REGION_SIZE KB(32)

#if !IS_ENABLED(CONFIG_XIP)

/*
 * These take the address one past the end of the region instead of a size,
 * and skip REGION_LIMIT_ADDR(): the boundaries below come from the linker, and
 * the compiler cannot mask a relocation at compile time. The masking is not
 * needed, region_init() masks both the base and the limit before writing them
 * to the MPU.
 */

/* Read only and executable: the image itself. */
#define REGION_IMAGE_ATTR(end)                                                                     \
	{                                                                                          \
		.rbar = P_RO_U_RO_Msk | NON_SHAREABLE_Msk,                                         \
		.mair_idx = MPU_MAIR_INDEX_SRAM,                                                   \
		.r_limit = (end) - 1,                                                              \
	}

/* Writable and never executable: everything else. */
#define REGION_DATA_ATTR(end)                                                                      \
	{                                                                                          \
		.rbar = NOT_EXEC | P_RW_U_NA_Msk | NON_SHAREABLE_Msk,                              \
		.mair_idx = MPU_MAIR_INDEX_SRAM,                                                   \
		.r_limit = (end) - 1,                                                              \
	}

/* Read only and nonexecutable */
#define REGION_FLASH_XN_ATTR(end)                                                                  \
	{                                                                                          \
		.rbar = NOT_EXEC | P_RO_U_NA_Msk | NON_SHAREABLE_Msk,                              \
		.mair_idx = MPU_MAIR_INDEX_FLASH,                                                  \
		.r_limit = (end) - 1,                                                              \
	}

#define IMAGE_START ((uint32_t)__rom_region_start)
#define IMAGE_END ((uint32_t)__rom_region_end)
#define DATA_START ((uint32_t)_image_ram_start)
#define DATA_END (DT_CHOSEN_SRAM_ADDR + DT_CHOSEN_SRAM_SIZE)

#endif /* !CONFIG_XIP */

static const struct arm_mpu_region mpu_regions[] = {
#if IS_ENABLED(CONFIG_RPI_PICO_USE_ROMFUNC)
	MPU_REGION_ENTRY("BOOTROM", ROM_BASE,
			 REGION_FLASH_ATTR(ROM_BASE, RP2350_BOOTROM_REGION_SIZE)),
#endif

#if IS_ENABLED(CONFIG_XIP)
	/* Flash @ CS0n, holding the code. */
	MPU_REGION_ENTRY("FLASH_0", CONFIG_FLASH_BASE_ADDRESS,
			 REGION_FLASH_ATTR(CONFIG_FLASH_BASE_ADDRESS, KB(CONFIG_FLASH_SIZE))),

	/* Main SRAM. */
	MPU_REGION_ENTRY("SRAM_0", DT_CHOSEN_SRAM_ADDR,
			 REGION_RAM_ATTR(DT_CHOSEN_SRAM_ADDR, DT_CHOSEN_SRAM_SIZE)),
#else
	MPU_REGION_ENTRY("XIP", XIP_BASE, REGION_FLASH_XN_ATTR(SRAM_BASE)),
	MPU_REGION_ENTRY("IMAGE", IMAGE_START, REGION_IMAGE_ATTR(IMAGE_END)),
	MPU_REGION_ENTRY("SRAM_DATA", DATA_START, REGION_DATA_ATTR(DATA_END)),
#endif
};

const struct arm_mpu_config mpu_config = {
	.num_regions = ARRAY_SIZE(mpu_regions),
	.mpu_regions = mpu_regions,
};

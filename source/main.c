/*
 * Copyright (c) 2018 naehrwert
 *
 * Copyright (c) 2018-2023 CTCaer
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdlib.h>

#include <bdk.h>

#include "config.h"
#include "gfx/logos.h"
#include "gfx/tui.h"
#include "hos/hos.h"
#include "hos/secmon_exo.h"
#include <ianos/ianos.h>
#include <libs/compr/blz.h>
#include <libs/fatfs/ff.h>
#include "storage/emummc.h"


hekate_config h_cfg;
boot_cfg_t __attribute__((section ("._boot_cfg"))) b_cfg;
const volatile ipl_ver_meta_t __attribute__((section ("._ipl_version"))) ipl_ver = {
	.magic = BL_MAGIC,
	//.version = (BL_VER_MJ + '0') | ((BL_VER_MN + '0') << 8) | ((BL_VER_HF + '0') << 16) | ((BL_VER_RL) << 24),
	.version = 0,
	.rcfg.rsvd_flags   = 0,
	.rcfg.bclk_t210    = BPMP_CLK_LOWER_BOOST,
	.rcfg.bclk_t210b01 = BPMP_CLK_DEFAULT_BOOST
};

volatile nyx_storage_t *nyx_str = (nyx_storage_t *)NYX_STORAGE_ADDR;



/*
static void _check_power_off_from_hos()
{
	// Power off on alarm wakeup from HOS shutdown. For modchips/dongles.
	u8 hos_wakeup = i2c_recv_byte(I2C_5, MAX77620_I2C_ADDR, MAX77620_REG_IRQTOP);

	// Clear RTC interrupts.
	(void)i2c_recv_byte(I2C_5, MAX77620_RTC_I2C_ADDR, MAX77620_RTC_RTCINT_REG);

	// Stop the alarm, in case we injected and powered off too fast.
	max77620_rtc_stop_alarm();

	// Handle RTC wake up.
	if (hos_wakeup & MAX77620_IRQ_TOP_RTC_MASK)
	{
		if (h_cfg.autohosoff == 1)
		{
			render_static_bootlogo();

			if (display_get_decoded_panel_id() != PANEL_SAM_AMS699VC01)
			{
				// Slow fading for LCD panels.
				display_backlight_brightness(10,  5000);
				display_backlight_brightness(100, 25000);
				msleep(600);
				display_backlight_brightness(0,   20000);
			}
			else
			{
				// Blink 3 times for OLED panel.
				for (u32 i = 0; i < 3; i++)
				{
					msleep(150);
					display_backlight_brightness(100, 0);
					msleep(150);
					display_backlight_brightness(0,   0);
				}
			}
		}
		power_set_state(POWER_OFF_RESET);
	}
}
*/ 

// This is a safe and unused DRAM region for our payloads.
#define RELOC_META_OFF      0x7C
#define PATCHED_RELOC_SZ    0x94
#define PATCHED_RELOC_STACK 0x40007000
#define PATCHED_RELOC_ENTRY 0x40010000
#define EXT_PAYLOAD_ADDR    0xC0000000
#define RCM_PAYLOAD_ADDR    (EXT_PAYLOAD_ADDR + ALIGN(PATCHED_RELOC_SZ, 0x10))
#define COREBOOT_END_ADDR   0xD0000000
#define COREBOOT_VER_OFF    0x41
#define CBFS_DRAM_EN_ADDR   0x4003E000
#define  CBFS_DRAM_MAGIC    0x4452414D // "DRAM"

static void *coreboot_addr;

static void _reloc_patcher(u32 payload_dst, u32 payload_src, u32 payload_size)
{
	memcpy((u8 *)payload_src, (u8 *)IPL_LOAD_ADDR, PATCHED_RELOC_SZ);

	reloc_meta_t *relocator = (reloc_meta_t *)(payload_src + RELOC_META_OFF);

	relocator->start = payload_dst - ALIGN(PATCHED_RELOC_SZ, 0x10);
	relocator->stack = PATCHED_RELOC_STACK;
	relocator->end   = payload_dst + payload_size;
	relocator->ep    = payload_dst;

	if (payload_size == 0x7000)
	{
		memcpy((u8 *)(payload_src + ALIGN(PATCHED_RELOC_SZ, 0x10)), coreboot_addr, 0x7000); // Bootblock.
		*(vu32 *)CBFS_DRAM_EN_ADDR = CBFS_DRAM_MAGIC;
	}
}



int launch_payload(char *path, bool clear_screen)
{
	if (clear_screen)
		gfx_clear_grey(0x1B);
	gfx_con_setpos(0, 0);
	if (!path)
		return 1;

	if (sd_mount())
	{
		FIL fp;
		if (f_open(&fp, path, FA_READ))
		{
			gfx_con.mute = false;
			EPRINTFARGS("Payload file is missing!\n(%s)", path);

			goto out;
		}

		// Read and copy the payload to our chosen address
		void *buf;
		u32 size = f_size(&fp);

		if (size < 0x30000)
			buf = (void *)RCM_PAYLOAD_ADDR;
		else
		{
			coreboot_addr = (void *)(COREBOOT_END_ADDR - size);
			buf = coreboot_addr;
			if (h_cfg.t210b01)
			{
				f_close(&fp);

				gfx_con.mute = false;
				EPRINTF("Coreboot not allowed on Mariko!");

				goto out;
			}
		}

		if (f_read(&fp, buf, size, NULL))
		{
			f_close(&fp);

			goto out;
		}

		f_close(&fp);

		sd_end();

		if (size < 0x30000)
		{
			_reloc_patcher(PATCHED_RELOC_ENTRY, EXT_PAYLOAD_ADDR, ALIGN(size, 0x10));

		hw_deinit(false);
		}
		else
		{
			_reloc_patcher(PATCHED_RELOC_ENTRY, EXT_PAYLOAD_ADDR, 0x7000);

			// Get coreboot seamless display magic.
			u32 magic = 0;
			char *magic_ptr = buf + COREBOOT_VER_OFF;
			memcpy(&magic, magic_ptr + strlen(magic_ptr) - 4, 4);
			hw_deinit(true);
		}

		// Some cards (Sandisk U1), do not like a fast power cycle. Wait min 100ms.
		sdmmc_storage_init_wait_sd();

		void (*ext_payload_ptr)() = (void *)EXT_PAYLOAD_ADDR;

		// Launch our payload.
		(*ext_payload_ptr)();
	}

out:
	sd_end();
	return 1;
}



#define EXCP_EN_ADDR   0x4003FFFC
#define  EXCP_MAGIC       0x30505645 // "EVP0".
#define EXCP_TYPE_ADDR 0x4003FFF8
#define  EXCP_TYPE_RESET  0x545352   // "RST".
#define  EXCP_TYPE_UNDEF  0x464455   // "UDF".
#define  EXCP_TYPE_PABRT  0x54424150 // "PABT".
#define  EXCP_TYPE_DABRT  0x54424144 // "DABT".
#define  EXCP_TYPE_WDT    0x544457   // "WDT".
#define EXCP_LR_ADDR   0x4003FFF4

#define PSTORE_LOG_OFFSET 0x180000
#define PSTORE_RAM_SIG    0x43474244 // "DBGC".

typedef struct _pstore_buf {
	u32 sig;
	u32 start;
	u32 size;
} pstore_buf_t;

static void _show_errors()
{
	u32 *excp_lr = (u32 *)EXCP_LR_ADDR;
	u32 *excp_type = (u32 *)EXCP_TYPE_ADDR;
	u32 *excp_enabled = (u32 *)EXCP_EN_ADDR;

	u32 panic_status = hw_rst_status & 0xFFFFF;

	// Check for exception error.
	if (*excp_enabled == EXCP_MAGIC)
		h_cfg.errors |= ERR_EXCEPTION;

	// Check for L4T kernel panic.
	if (PMC(APBDEV_PMC_SCRATCH37) == PMC_SCRATCH37_KERNEL_PANIC_MAGIC)
	{
		// Set error and clear flag.
		h_cfg.errors |= ERR_L4T_KERNEL;
		PMC(APBDEV_PMC_SCRATCH37) = 0;
	}

	// Check for watchdog panic.
	if (hw_rst_reason == PMC_RST_STATUS_WATCHDOG && panic_status &&
		panic_status <= 0xFF && panic_status != 0x20 && panic_status != 0x21)
	{
		h_cfg.errors |= ERR_PANIC_CODE;
	}

	// Check if we had a panic while in CFW.
	secmon_exo_check_panic();

	// Handle errors.
	if (h_cfg.errors)
	{
		gfx_clear_grey(0x1B);
		gfx_con_setpos(0, 0);
		display_backlight_brightness(150, 1000);

		if (h_cfg.errors & ERR_SD_BOOT_EN)
		{
			WPRINTF("Failed to init or mount SD!\n");

			// Clear the module bits as to not cram the error screen.
			h_cfg.errors &= ~(ERR_LIBSYS_LP0 | ERR_LIBSYS_MTC);
		}


		if (h_cfg.errors & ERR_EXCEPTION)
		{
			WPRINTFARGS("hekate exception occurred (LR %08X):\n", *excp_lr);
			switch (*excp_type)
			{
			case EXCP_TYPE_WDT:
				WPRINTF("Hang detected in LP0/Minerva!");
				break;
			case EXCP_TYPE_RESET:
				WPRINTF("RESET");
				break;
			case EXCP_TYPE_UNDEF:
				WPRINTF("UNDEF");
				break;
			case EXCP_TYPE_PABRT:
				WPRINTF("PABRT");
				break;
			case EXCP_TYPE_DABRT:
				WPRINTF("DABRT");
				break;
			}
			gfx_puts("\n");

			// Clear the exception.
			*excp_enabled = 0;
			*excp_type = 0;
		}

		if (h_cfg.errors & ERR_L4T_KERNEL)
		{
			WPRINTF("L4T Kernel panic occurred!\n");
			if (!(h_cfg.errors & ERR_SD_BOOT_EN))
			{
				if (!sd_save_to_file((void *)PSTORE_ADDR, PSTORE_SZ, "L4T_panic.bin"))
					WPRINTF("PSTORE saved to L4T_panic.bin");
				pstore_buf_t *buf = (pstore_buf_t *)(PSTORE_ADDR + PSTORE_LOG_OFFSET);
				if (buf->sig == PSTORE_RAM_SIG && buf->size && buf->size < 0x80000)
				{
					u32 log_offset = PSTORE_ADDR + PSTORE_LOG_OFFSET + sizeof(pstore_buf_t);
					if (!sd_save_to_file((void *)log_offset, buf->size, "L4T_panic.txt"))
						WPRINTF("Log saved to L4T_panic.txt");
				}
			}
			gfx_puts("\n");
		}

		if (h_cfg.errors & ERR_PANIC_CODE)
		{
			u32 r = (hw_rst_status >> 20) & 0xF;
			u32 g = (hw_rst_status >> 24) & 0xF;
			u32 b = (hw_rst_status >> 28) & 0xF;
			r = (r << 16) | (r << 20);
			g = (g << 8)  | (g << 12);
			b = (b << 0)  | (b << 4);
			u32 color = r | g | b;

			WPRINTF("HOS panic occurred!\n");
			gfx_printf("Color: %k####%k, Code: %02X\n\n", color, TXT_CLR_DEFAULT, panic_status);
		}

		WPRINTF("Press any key...");

		msleep(1000); // Guard against injection VOL+.
		btn_wait();
		msleep(500);  // Guard against force menu VOL-.
	}
}

static void _check_low_battery()
{
	if (h_cfg.devmode)
		goto out;

	int enough_battery;
	int batt_volt = 0;
	int charge_status = 0;

	// Enable charger in case it's disabled.
	bq24193_enable_charger();

	bq24193_get_property(BQ24193_ChargeStatus, &charge_status);
	max17050_get_property(MAX17050_AvgVCELL,   &batt_volt);

	enough_battery = charge_status ? 3300 : 3100;

	// If battery voltage is enough, exit.
	if (batt_volt > enough_battery || !batt_volt)
		goto out;

	// Prepare battery icon resources.
	u8 *battery_res = malloc(ALIGN(BATTERY_EMPTY_SIZE, SZ_4K));
	blz_uncompress_srcdest(battery_icons_blz, BATTERY_EMPTY_BLZ_SIZE, battery_res, BATTERY_EMPTY_SIZE);

	u8 *battery_icon     = malloc(0x95A); // 21x38x3
	u8 *charging_icon    = malloc(0x2F4); // 21x12x3
	u8 *no_charging_icon = zalloc(0x2F4);

	memcpy(charging_icon, battery_res, 0x2F4);
	memcpy(battery_icon, battery_res + 0x2F4, 0x95A);

	u32 battery_icon_y_pos  = 1280 - 16 - BATTERY_EMPTY_BATT_HEIGHT;
	u32 charging_icon_y_pos = 1280 - 16 - BATTERY_EMPTY_BATT_HEIGHT - 12 - BATTERY_EMPTY_CHRG_HEIGHT;
	free(battery_res);

	charge_status = !charge_status;

	u32 timer = 0;
	bool screen_on = false;
	while (true)
	{
		bpmp_msleep(250);

		// Refresh battery stats.
		int current_charge_status = 0;
		bq24193_get_property(BQ24193_ChargeStatus, &current_charge_status);
		max17050_get_property(MAX17050_AvgVCELL, &batt_volt);
		enough_battery = current_charge_status ? 3300 : 3100;

		// If battery voltage is enough, exit.
		if (batt_volt > enough_battery)
			break;

		// Refresh charging icon.
		if (screen_on && (charge_status != current_charge_status))
		{
			if (current_charge_status)
				gfx_set_rect_rgb(charging_icon,    BATTERY_EMPTY_WIDTH, BATTERY_EMPTY_CHRG_HEIGHT, 16, charging_icon_y_pos);
			else
				gfx_set_rect_rgb(no_charging_icon, BATTERY_EMPTY_WIDTH, BATTERY_EMPTY_CHRG_HEIGHT, 16, charging_icon_y_pos);
		}

		// Check if it's time to turn off display.
		if (screen_on && timer < get_tmr_ms())
		{
			// If battery is not charging, power off.
			if (!current_charge_status)
			{
				max77620_low_battery_monitor_config(true);

				// Handle full hw deinit and power off.
				power_set_state(POWER_OFF_RESET);
			}

			// If charging, just disable display.
			display_end();
			screen_on = false;
		}

		// Check if charging status changed or Power button was pressed and enable display.
		if ((charge_status != current_charge_status) || (btn_wait_timeout_single(0, BTN_POWER) & BTN_POWER))
		{
			if (!screen_on)
			{
				display_init();
				u32 *fb = display_init_window_a_pitch();
				gfx_init_ctxt(fb, 720, 1280, 720);

				gfx_set_rect_rgb(battery_icon,         BATTERY_EMPTY_WIDTH, BATTERY_EMPTY_BATT_HEIGHT, 16, battery_icon_y_pos);
				if (current_charge_status)
					gfx_set_rect_rgb(charging_icon,    BATTERY_EMPTY_WIDTH, BATTERY_EMPTY_CHRG_HEIGHT, 16, charging_icon_y_pos);
				else
					gfx_set_rect_rgb(no_charging_icon, BATTERY_EMPTY_WIDTH, BATTERY_EMPTY_CHRG_HEIGHT, 16, charging_icon_y_pos);

				display_backlight_pwm_init();
				display_backlight_brightness(100, 1000);

				screen_on = true;
			}

			timer = get_tmr_ms() + 15000;
		}

		// Check if forcefully continuing.
		if (btn_read_vol() == (BTN_VOL_UP | BTN_VOL_DOWN))
			break;

		charge_status = current_charge_status;
	}

	if (screen_on)
		display_end();

	free(battery_icon);
	free(charging_icon);
	free(no_charging_icon);

out:
	// Re enable Low Battery Monitor shutdown.
	max77620_low_battery_monitor_config(true);
}

static void _r2c_get_config_t210b01()
{
	rtc_reboot_reason_t rr;
	if (!max77620_rtc_get_reboot_reason(&rr))
		return;

	// Check if reason is actually set.
	if (rr.dec.reason != REBOOT_REASON_NOP)
	{
		// Clear boot storage.
		memset(&b_cfg, 0, sizeof(boot_cfg_t));

		// Enable boot storage.
		b_cfg.boot_cfg |= BOOT_CFG_AUTOBOOT_EN;
	}

	switch (rr.dec.reason)
	{
	case REBOOT_REASON_NOP:
		break;
	case REBOOT_REASON_REC:
		PMC(APBDEV_PMC_SCRATCH0) |= PMC_SCRATCH0_MODE_RECOVERY;
	case REBOOT_REASON_SELF:
		b_cfg.autoboot      = rr.dec.autoboot_idx;
		b_cfg.autoboot_list = rr.dec.autoboot_list;
		break;
	case REBOOT_REASON_MENU:
		break;
	case REBOOT_REASON_UMS:
		b_cfg.extra_cfg |= EXTRA_CFG_NYX_UMS;
		b_cfg.ums = rr.dec.ums_idx;
		break;
	case REBOOT_REASON_PANIC:
		PMC(APBDEV_PMC_SCRATCH37) = PMC_SCRATCH37_KERNEL_PANIC_MAGIC;
		break;
	}
}



static void _mouse() {
	
static const char asciimouse[] =	
"\n"
"\n"
"\n"
"	                                                                     \n"
"           ******                                                       \n"
"           *    *                                      *********        \n"
"          **     *                                ********* ** *        \n"
"          *      *                               **            **       \n"
"          *      *                               *             **       \n"
"          *  **   *                  ******** ***               *       \n"
"          *  *    *     ************* ****      **  ****       **       \n"
"          *     ***** **                          *   **        *       \n"
"          **    *** *                             **  *         *       \n"
"           *****                                    *         **        \n"
"             ***       *******          ******      ***********         \n"
"             *       ***      *        **    *      *                   \n"
"            *         **  *    *      *      *      *                   \n"
"            **        *        *     *   *   *       *                  \n"
"            **        ***     **     *      **       *                  \n"
"            **           *****       ***    *        *                  \n"
"             *                    *     *****        *                  \n"
"             *                    *                  *                  \n"
"             **        ****       *                  *                  \n"
"              *            ****                      *                  \n"
"     *        **               ***   ******          *                  \n"
"     **        **                * ***               *                  \n"
"      *         **               ***                *                   \n"
"      **          **                                *                   \n"
"       *           **                               *                   \n"
"       **          *******                         * *        *         \n"
"        **        **      *******          *** ** ****       **         \n"
"         ***     **             ******* * *  ********      ***          \n"
"           *******                      ** ***      *    ****           \n"
"                *                                   *******             \n"
"               **                                    *                  \n"
"               **                                   **                  \n"
"               *                                    **                  \n"
"               *                                    *                   \n"
"               **                                   *                   \n"
"               **                                  **                   \n"
"                *                                  **                   \n"
"          ** ****                                  **         **       *\n"
"       **********                                   *    ************** \n"
"   ** **       *                                   *******              \n"
"  **  *       **                                   ***                  \n"
"              ***                                  *                    \n"
"               ***                                **                    \n"
"               ****                               **                    \n"
"                ****                             ***                    \n"
"                   *****                     ******                     \n"
"                     ********* * ************ ****                      \n"
"                        ********* * *          * *******                \n"
"                                                       *                \n"
"                                                        ****            \n"
"														                 \n"
"                                                                        \n";

	gfx_clear_grey(0x1B);
	gfx_con_setpos(0, 0);
	gfx_con.fntsz = 14;
	gfx_printf(asciimouse, TXT_CLR_CYAN_L, TXT_CLR_TURQUOISE, TXT_CLR_CYAN_L, TXT_CLR_DEFAULT);
	usleep(3000); //3 secs?  
	//btn_wait();
																		 	
}


static void boot_to_ams() {
    

	sd_mount();
	if (!f_stat("atmosphere/reboot_payload.bin", NULL)) {
		launch_payload("atmosphere/reboot_payload.bin", false);
	} else {
		EPRINTF("I can't find reboot_payload.bin!");
	}

}


power_state_t STATE_POWER_OFF           = POWER_OFF_RESET;
power_state_t STATE_REBOOT_RCM          = REBOOT_RCM;
power_state_t STATE_REBOOT_BYPASS_FUSES = REBOOT_BYPASS_FUSES;

ment_t ment_top[] = {
	
	
	MDEF_HANDLER("Boot to AMS", boot_to_ams),
	MDEF_CAPTION("---------------", TXT_CLR_GREY_DM),	
	MDEF_HANDLER_EX("Reboot (OFW)", &STATE_REBOOT_BYPASS_FUSES, power_set_state_ex),
	MDEF_HANDLER_EX("Reboot (RCM)", &STATE_REBOOT_RCM,          power_set_state_ex),
	MDEF_HANDLER_EX("Power off",    &STATE_POWER_OFF,           power_set_state_ex),
	MDEF_CAPTION("---------------", TXT_CLR_GREY_DM),
	MDEF_HANDLER("About Mouse", _mouse),





	MDEF_END()
};

menu_t menu_top = { ment_top, "Mouse", 0, 0 };

extern void pivot_stack(u32 stack_top);

void ipl_main()
{
	// Do initial HW configuration. This is compatible with consecutive reruns without a reset.
	hw_init();

	// Pivot the stack under IPL. (Only max 4KB is needed).
	pivot_stack(IPL_LOAD_ADDR);

	// Place heap at a place outside of L4T/HOS configuration and binaries.
	heap_init((void *)IPL_HEAP_START);

#ifdef DEBUG_UART_PORT
	uart_send(DEBUG_UART_PORT, (u8 *)"hekate: Hello!\r\n", 16);
	uart_wait_xfer(DEBUG_UART_PORT, UART_TX_IDLE);
#endif

	// Check if battery is enough.
	_check_low_battery();

	// Set bootloader's default configuration.
	set_default_configuration();

	// Prep RTC regs for read. Needed for T210B01 R2P.
	max77620_rtc_prep_read();

	// Initialize display.
	display_init();

	// Overclock BPMP.
	bpmp_clk_rate_set(h_cfg.t210b01 ? ipl_ver.rcfg.bclk_t210b01 : ipl_ver.rcfg.bclk_t210);

	// Mount SD Card.
	h_cfg.errors |= !sd_mount() ? ERR_SD_BOOT_EN : 0;

	// Check if watchdog was fired previously.
	if (watchdog_fired())
		goto skip_lp0_minerva_config;

	// Enable watchdog protection to avoid SD corruption based hanging in LP0/Minerva config.
	watchdog_start(5000000 / 2, TIMER_FIQENABL_EN); // 5 seconds.

	// Save sdram lp0 config.
	void *sdram_params = h_cfg.t210b01 ? sdram_get_params_t210b01() : sdram_get_params_patched();
	if (!ianos_loader("bootloader/sys/libsys_lp0.bso", DRAM_LIB, sdram_params))
		h_cfg.errors |= ERR_LIBSYS_LP0;

	// Train DRAM and switch to max frequency.
	if (minerva_init((minerva_str_t *)&nyx_str->minerva)) //!TODO: Add Tegra210B01 support to minerva.
		h_cfg.errors |= ERR_LIBSYS_MTC;

	// Disable watchdog protection.
	watchdog_end();

skip_lp0_minerva_config:
	// Initialize display window, backlight and gfx console.
	u32 *fb = display_init_window_a_pitch();
	gfx_init_ctxt(fb, 720, 1280, 720);
	gfx_con_init();

	display_backlight_pwm_init();
	display_backlight_brightness(230, 1000);

	// Get R2C config from RTC.
	if (h_cfg.t210b01)
		_r2c_get_config_t210b01();

	// Show exceptions, HOS errors, library errors and L4T kernel panics.
	_show_errors();


	// Failed to launch Nyx, unmount SD Card.
	sd_end();

	// Set ram to a freq that doesn't need periodic training.
	minerva_change_freq(FREQ_800);

	while (true) {
		_mouse();
		boot_to_ams();
		//tui_do_menu(&menu_top);
	}
	
	// Halt BPMP if we managed to get out of execution.
	while (true)
		bpmp_halt();
}

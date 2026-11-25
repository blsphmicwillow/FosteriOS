// SPDX-License-Identifier: GPL-2.0
/*
 * ntpersonality -- the first piece of FosteriOS's in-kernel NT personality.
 *
 * FosteriOS keeps the Linux kernel (drivers, filesystems, scheduler, hardware
 * support) and grows NT semantics inside it. M0 is deliberately small: prove
 * that a module can
 *
 *   1. load and identify itself,
 *   2. expose state through /proc/forsteri_nt, and
 *   3. claim PE images through the Linux binfmt hook.
 *
 * The loader itself (mapping sections, PEB/TEB, ntdll hand-off) is M1/M2. Until
 * then a recognised PE returns -ENOEXEC, which is exactly what an unimplemented
 * format should do: it is visible, logged, and harmless.
 */

#include <linux/binfmts.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/types.h>
#include <linux/unaligned.h>
#include <linux/version.h>
#include <generated/utsrelease.h>

#define NTP_VERSION "0.0.1"
#define NTP_PROC "forsteri_nt"

#define PE_DOS_MAGIC 0x5a4d	/* "MZ" little-endian */
#define PE_NT_SIGNATURE 0x00004550	/* "PE\0\0" little-endian */
#define PE_E_LFANEW 0x3c

static unsigned int pe_seen;

/*
 * True when buf starts with a DOS header whose e_lfanew points at a PE
 * signature that fits inside the buffer. Linux hands us BINPRM_BUF_SIZE bytes
 * (256), which is enough for the DOS header, e_lfanew and the signature.
 */
static bool ntp_is_pe(const unsigned char *buf, size_t len, u32 *pe_off)
{
	u32 off;

	if (len < PE_E_LFANEW + sizeof(u32))
		return false;
	if (get_unaligned_le16(buf) != PE_DOS_MAGIC)
		return false;

	off = get_unaligned_le32(buf + PE_E_LFANEW);
	if (off > len - sizeof(u32))
		return false;
	if (get_unaligned_le32(buf + off) != PE_NT_SIGNATURE)
		return false;

	*pe_off = off;
	return true;
}

static int ntp_pe_load_binary(struct linux_binprm *bprm)
{
	u32 pe_off;

	if (!ntp_is_pe(bprm->buf, BINPRM_BUF_SIZE, &pe_off))
		return -ENOEXEC;

	pe_seen++;
	pr_info("ntpersonality: PE image recognised: %s (e_lfanew=%u)\n",
		bprm->filename, pe_off);

	/*
	 * M1 replaces this with a real image loader. Returning -ENOEXEC keeps
	 * execve() honest: the kernel tried, nothing was mapped, the caller
	 * gets a normal "exec format error".
	 */
	return -ENOEXEC;
}

static struct linux_binfmt ntp_pe_binfmt = {
	.module = THIS_MODULE,
	.load_binary = ntp_pe_load_binary,
};

static int ntp_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "name       ntpersonality\n");
	seq_printf(m, "version    %s\n", NTP_VERSION);
	seq_printf(m, "stage      M0 hooks; M2 map/PEB library linked, not active\n");
	seq_printf(m, "linux      %s\n", UTS_RELEASE);
	seq_printf(m, "pe_seen    %u\n", pe_seen);
	seq_printf(m, "binfmt     registered\n");
	return 0;
}

static int __init ntp_init(void)
{
	pr_info("ntpersonality: loading %s on Linux %s\n", NTP_VERSION,
		UTS_RELEASE);

	register_binfmt(&ntp_pe_binfmt);

	if (!proc_create_single(NTP_PROC, 0444, NULL, ntp_proc_show)) {
		pr_err("ntpersonality: could not create /proc/%s\n", NTP_PROC);
		unregister_binfmt(&ntp_pe_binfmt);
		return -ENOMEM;
	}

	pr_info("ntpersonality: ready; /proc/%s\n", NTP_PROC);
	return 0;
}

static void __exit ntp_exit(void)
{
	remove_proc_entry(NTP_PROC, NULL);
	unregister_binfmt(&ntp_pe_binfmt);
	pr_info("ntpersonality: unloaded\n");
}

module_init(ntp_init);
module_exit(ntp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Forsteri OS");
MODULE_DESCRIPTION("NT personality skeleton for FosteriOS (M0; M2 map/PEB library)");
MODULE_VERSION(NTP_VERSION);

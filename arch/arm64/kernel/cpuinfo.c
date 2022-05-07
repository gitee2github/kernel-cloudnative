// SPDX-License-Identifier: GPL-2.0-only
/*
 * Record and handle CPU attributes.
 *
 * Copyright (C) 2014 ARM Ltd.
 */
#include <asm/arch_timer.h>
#include <asm/cache.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/cpufeature.h>
#include <asm/fpsimd.h>

#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/compat.h>
#include <linux/elf.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/personality.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/delay.h>

/*
 * In case the boot CPU is hotpluggable, we record its initial state and
 * current state separately. Certain system registers may contain different
 * values depending on configuration at or after reset.
 */
DEFINE_PER_CPU(struct cpuinfo_arm64, cpu_data);
static struct cpuinfo_arm64 boot_cpu_data;

static const char *icache_policy_str[] = {
	[ICACHE_POLICY_VPIPT]		= "VPIPT",
	[ICACHE_POLICY_RESERVED]	= "RESERVED/UNKNOWN",
	[ICACHE_POLICY_VIPT]		= "VIPT",
	[ICACHE_POLICY_PIPT]		= "PIPT",
};

unsigned long __icache_flags;

static const char *const hwcap_str[] = {
	[KERNEL_HWCAP_FP]		= "fp",
	[KERNEL_HWCAP_ASIMD]		= "asimd",
	[KERNEL_HWCAP_EVTSTRM]		= "evtstrm",
	[KERNEL_HWCAP_AES]		= "aes",
	[KERNEL_HWCAP_PMULL]		= "pmull",
	[KERNEL_HWCAP_SHA1]		= "sha1",
	[KERNEL_HWCAP_SHA2]		= "sha2",
	[KERNEL_HWCAP_CRC32]		= "crc32",
	[KERNEL_HWCAP_ATOMICS]		= "atomics",
	[KERNEL_HWCAP_FPHP]		= "fphp",
	[KERNEL_HWCAP_ASIMDHP]		= "asimdhp",
	[KERNEL_HWCAP_CPUID]		= "cpuid",
	[KERNEL_HWCAP_ASIMDRDM]		= "asimdrdm",
	[KERNEL_HWCAP_JSCVT]		= "jscvt",
	[KERNEL_HWCAP_FCMA]		= "fcma",
	[KERNEL_HWCAP_LRCPC]		= "lrcpc",
	[KERNEL_HWCAP_DCPOP]		= "dcpop",
	[KERNEL_HWCAP_SHA3]		= "sha3",
	[KERNEL_HWCAP_SM3]		= "sm3",
	[KERNEL_HWCAP_SM4]		= "sm4",
	[KERNEL_HWCAP_ASIMDDP]		= "asimddp",
	[KERNEL_HWCAP_SHA512]		= "sha512",
	[KERNEL_HWCAP_SVE]		= "sve",
	[KERNEL_HWCAP_ASIMDFHM]		= "asimdfhm",
	[KERNEL_HWCAP_DIT]		= "dit",
	[KERNEL_HWCAP_USCAT]		= "uscat",
	[KERNEL_HWCAP_ILRCPC]		= "ilrcpc",
	[KERNEL_HWCAP_FLAGM]		= "flagm",
	[KERNEL_HWCAP_SSBS]		= "ssbs",
	[KERNEL_HWCAP_SB]		= "sb",
	[KERNEL_HWCAP_PACA]		= "paca",
	[KERNEL_HWCAP_PACG]		= "pacg",
	[KERNEL_HWCAP_DCPODP]		= "dcpodp",
	[KERNEL_HWCAP_SVE2]		= "sve2",
	[KERNEL_HWCAP_SVEAES]		= "sveaes",
	[KERNEL_HWCAP_SVEPMULL]		= "svepmull",
	[KERNEL_HWCAP_SVEBITPERM]	= "svebitperm",
	[KERNEL_HWCAP_SVESHA3]		= "svesha3",
	[KERNEL_HWCAP_SVESM4]		= "svesm4",
	[KERNEL_HWCAP_FLAGM2]		= "flagm2",
	[KERNEL_HWCAP_FRINT]		= "frint",
	[KERNEL_HWCAP_SVEI8MM]		= "svei8mm",
	[KERNEL_HWCAP_SVEF32MM]		= "svef32mm",
	[KERNEL_HWCAP_SVEF64MM]		= "svef64mm",
	[KERNEL_HWCAP_SVEBF16]		= "svebf16",
	[KERNEL_HWCAP_I8MM]		= "i8mm",
	[KERNEL_HWCAP_BF16]		= "bf16",
	[KERNEL_HWCAP_DGH]		= "dgh",
	[KERNEL_HWCAP_RNG]		= "rng",
	[KERNEL_HWCAP_BTI]		= "bti",
	[KERNEL_HWCAP_MTE]		= "mte",
	[KERNEL_HWCAP_ECV]		= "ecv",
	[KERNEL_HWCAP_AFP]		= "afp",
	[KERNEL_HWCAP_RPRES]		= "rpres",
};

#ifdef CONFIG_AARCH32_EL0
#define COMPAT_KERNEL_HWCAP(x)	const_ilog2(COMPAT_HWCAP_ ## x)
static const char *const compat_hwcap_str[] = {
	[COMPAT_KERNEL_HWCAP(SWP)]	= "swp",
	[COMPAT_KERNEL_HWCAP(HALF)]	= "half",
	[COMPAT_KERNEL_HWCAP(THUMB)]	= "thumb",
	[COMPAT_KERNEL_HWCAP(26BIT)]	= NULL,	/* Not possible on arm64 */
	[COMPAT_KERNEL_HWCAP(FAST_MULT)] = "fastmult",
	[COMPAT_KERNEL_HWCAP(FPA)]	= NULL,	/* Not possible on arm64 */
	[COMPAT_KERNEL_HWCAP(VFP)]	= "vfp",
	[COMPAT_KERNEL_HWCAP(EDSP)]	= "edsp",
	[COMPAT_KERNEL_HWCAP(JAVA)]	= NULL,	/* Not possible on arm64 */
	[COMPAT_KERNEL_HWCAP(IWMMXT)]	= NULL,	/* Not possible on arm64 */
	[COMPAT_KERNEL_HWCAP(CRUNCH)]	= NULL,	/* Not possible on arm64 */
	[COMPAT_KERNEL_HWCAP(THUMBEE)]	= NULL,	/* Not possible on arm64 */
	[COMPAT_KERNEL_HWCAP(NEON)]	= "neon",
	[COMPAT_KERNEL_HWCAP(VFPv3)]	= "vfpv3",
	[COMPAT_KERNEL_HWCAP(VFPV3D16)]	= NULL,	/* Not possible on arm64 */
	[COMPAT_KERNEL_HWCAP(TLS)]	= "tls",
	[COMPAT_KERNEL_HWCAP(VFPv4)]	= "vfpv4",
	[COMPAT_KERNEL_HWCAP(IDIVA)]	= "idiva",
	[COMPAT_KERNEL_HWCAP(IDIVT)]	= "idivt",
	[COMPAT_KERNEL_HWCAP(VFPD32)]	= NULL,	/* Not possible on arm64 */
	[COMPAT_KERNEL_HWCAP(LPAE)]	= "lpae",
	[COMPAT_KERNEL_HWCAP(EVTSTRM)]	= "evtstrm",
};

#define COMPAT_KERNEL_HWCAP2(x)	const_ilog2(COMPAT_HWCAP2_ ## x)
static const char *const compat_hwcap2_str[] = {
	[COMPAT_KERNEL_HWCAP2(AES)]	= "aes",
	[COMPAT_KERNEL_HWCAP2(PMULL)]	= "pmull",
	[COMPAT_KERNEL_HWCAP2(SHA1)]	= "sha1",
	[COMPAT_KERNEL_HWCAP2(SHA2)]	= "sha2",
	[COMPAT_KERNEL_HWCAP2(CRC32)]	= "crc32",
};
#endif /* CONFIG_AARCH32_EL0 */

struct id_part {
    const int id;
    const char* name;
};

static const struct id_part arm_part[] = {
    { 0x810, "ARM810" },
    { 0x920, "ARM920" },
    { 0x922, "ARM922" },
    { 0x926, "ARM926" },
    { 0x940, "ARM940" },
    { 0x946, "ARM946" },
    { 0x966, "ARM966" },
    { 0xa20, "ARM1020" },
    { 0xa22, "ARM1022" },
    { 0xa26, "ARM1026" },
    { 0xb02, "ARM11 MPCore" },
    { 0xb36, "ARM1136" },
    { 0xb56, "ARM1156" },
    { 0xb76, "ARM1176" },
    { 0xc05, "Cortex-A5" },
    { 0xc07, "Cortex-A7" },
    { 0xc08, "Cortex-A8" },
    { 0xc09, "Cortex-A9" },
    { 0xc0d, "Cortex-A17" },	/* Originally A12 */
    { 0xc0f, "Cortex-A15" },
    { 0xc0e, "Cortex-A17" },
    { 0xc14, "Cortex-R4" },
    { 0xc15, "Cortex-R5" },
    { 0xc17, "Cortex-R7" },
    { 0xc18, "Cortex-R8" },
    { 0xc20, "Cortex-M0" },
    { 0xc21, "Cortex-M1" },
    { 0xc23, "Cortex-M3" },
    { 0xc24, "Cortex-M4" },
    { 0xc27, "Cortex-M7" },
    { 0xc60, "Cortex-M0+" },
    { 0xd01, "Cortex-A32" },
    { 0xd03, "Cortex-A53" },
    { 0xd04, "Cortex-A35" },
    { 0xd05, "Cortex-A55" },
    { 0xd06, "Cortex-A65" },
    { 0xd07, "Cortex-A57" },
    { 0xd08, "Cortex-A72" },
    { 0xd09, "Cortex-A73" },
    { 0xd0a, "Cortex-A75" },
    { 0xd0b, "Cortex-A76" },
    { 0xd0c, "Neoverse-N1" },
    { 0xd0d, "Cortex-A77" },
    { 0xd0e, "Cortex-A76AE" },
    { 0xd13, "Cortex-R52" },
    { 0xd20, "Cortex-M23" },
    { 0xd21, "Cortex-M33" },
    { 0xd41, "Cortex-A78" },
    { 0xd42, "Cortex-A78AE" },
    { 0xd4a, "Neoverse-E1" },
    { 0xd4b, "Cortex-A78C" },
    { -1, "unknown" },
};

static const struct id_part brcm_part[] = {
    { 0x0f, "Brahma B15" },
    { 0x100, "Brahma B53" },
    { 0x516, "ThunderX2" },
    { -1, "unknown" },
};

static const struct id_part dec_part[] = {
    { 0xa10, "SA110" },
    { 0xa11, "SA1100" },
    { -1, "unknown" },
};

static const struct id_part cavium_part[] = {
    { 0x0a0, "ThunderX" },
    { 0x0a1, "ThunderX 88XX" },
    { 0x0a2, "ThunderX 81XX" },
    { 0x0a3, "ThunderX 83XX" },
    { 0x0af, "ThunderX2 99xx" },
    { -1, "unknown" },
};

static const struct id_part apm_part[] = {
    { 0x000, "X-Gene" },
    { -1, "unknown" },
};

static const struct id_part qcom_part[] = {
    { 0x00f, "Scorpion" },
    { 0x02d, "Scorpion" },
    { 0x04d, "Krait" },
    { 0x06f, "Krait" },
    { 0x201, "Kryo" },
    { 0x205, "Kryo" },
    { 0x211, "Kryo" },
    { 0x800, "Falkor V1/Kryo" },
    { 0x801, "Kryo V2" },
    { 0xc00, "Falkor" },
    { 0xc01, "Saphira" },
    { -1, "unknown" },
};

static const struct id_part samsung_part[] = {
    { 0x001, "exynos-m1" },
    { -1, "unknown" },
};

static const struct id_part nvidia_part[] = {
    { 0x000, "Denver" },
    { 0x003, "Denver 2" },
    { 0x004, "Carmel" },
    { -1, "unknown" },
};

static const struct id_part marvell_part[] = {
    { 0x131, "Feroceon 88FR131" },
    { 0x581, "PJ4/PJ4b" },
    { 0x584, "PJ4B-MP" },
    { -1, "unknown" },
};

static const struct id_part faraday_part[] = {
    { 0x526, "FA526" },
    { 0x626, "FA626" },
    { -1, "unknown" },
};

static const struct id_part intel_part[] = {
    { 0x200, "i80200" },
    { 0x210, "PXA250A" },
    { 0x212, "PXA210A" },
    { 0x242, "i80321-400" },
    { 0x243, "i80321-600" },
    { 0x290, "PXA250B/PXA26x" },
    { 0x292, "PXA210B" },
    { 0x2c2, "i80321-400-B0" },
    { 0x2c3, "i80321-600-B0" },
    { 0x2d0, "PXA250C/PXA255/PXA26x" },
    { 0x2d2, "PXA210C" },
    { 0x411, "PXA27x" },
    { 0x41c, "IPX425-533" },
    { 0x41d, "IPX425-400" },
    { 0x41f, "IPX425-266" },
    { 0x682, "PXA32x" },
    { 0x683, "PXA930/PXA935" },
    { 0x688, "PXA30x" },
    { 0x689, "PXA31x" },
    { 0xb11, "SA1110" },
    { 0xc12, "IPX1200" },
    { -1, "unknown" },
};

static const struct id_part fujitsu_part[] = {
    { 0x001, "A64FX" },
    { -1, "unknown" },
};

static const struct id_part hisi_part[] = {
    { 0xd01, "Kunpeng-920" },	/* aka tsv110 */
    { -1, "unknown" },
};

static const struct id_part phytium_part[] = {
    { 0x663, "S250/64 C100" },
    { -1, "unknown" },
};

static const struct id_part unknown_part[] = {
    { -1, "unknown" },
};

struct hw_impl {
   const int    id;
   const struct id_part     *parts;
   const char   *name;
};

static const struct hw_impl hw_implementer[] = {
    { 0x41, arm_part,     "ARM" },
    { 0x42, brcm_part,    "Broadcom" },
    { 0x43, cavium_part,  "Cavium" },
    { 0x44, dec_part,     "DEC" },
    { 0x46, fujitsu_part, "FUJITSU" },
    { 0x48, hisi_part,    "HiSilicon" },
    { 0x4e, nvidia_part,  "Nvidia" },
    { 0x50, apm_part,     "APM" },
    { 0x51, qcom_part,    "Qualcomm" },
    { 0x53, samsung_part, "Samsung" },
    { 0x56, marvell_part, "Marvell" },
    { 0x66, faraday_part, "Faraday" },
    { 0x69, intel_part,   "Intel" },
    { 0x70, phytium_part,  "Phytium" },
    { -1,   unknown_part, "unknown" },
};

static int c_show(struct seq_file *m, void *v)
{
	int i, j, impl, part;
	const struct id_part *parts = NULL;
	bool aarch32 = personality(current->personality) == PER_LINUX32;

	for_each_online_cpu(i) {
		struct cpuinfo_arm64 *cpuinfo = &per_cpu(cpu_data, i);
		u32 midr = cpuinfo->reg_midr;

		/*
		 * glibc reads /proc/cpuinfo to determine the number of
		 * online processors, looking for lines beginning with
		 * "processor".  Give glibc what it expects.
		 */
		seq_printf(m, "processor\t: %d\n", i);
		if (aarch32) {
			seq_printf(m, "model name\t: ARMv8 Processor rev %d (%s)\n",
				   MIDR_REVISION(midr), COMPAT_ELF_PLATFORM);
		} else {
			for (impl = 0; hw_implementer[impl].id != -1; impl++) {
				if (hw_implementer[impl].id == MIDR_IMPLEMENTOR(midr)) {
					parts = hw_implementer[impl].parts;
					break;
				}
			}
			for (part = 0; parts && parts[part].id != -1; part++) {
				if (parts[part].id == MIDR_PARTNUM(midr)) {
					seq_printf(m, "model name\t: %s,%s\n",
						   (char *) hw_implementer[impl].name, (char *) parts[part].name);
					break;
				}
			}
		}

		seq_printf(m, "BogoMIPS\t: %lu.%02lu\n",
			   loops_per_jiffy / (500000UL/HZ),
			   loops_per_jiffy / (5000UL/HZ) % 100);

		/*
		 * Dump out the common processor features in a single line.
		 * Userspace should read the hwcaps with getauxval(AT_HWCAP)
		 * rather than attempting to parse this, but there's a body of
		 * software which does already (at least for 32-bit).
		 */
		seq_puts(m, "Features\t:");
		if (aarch32) {
#ifdef CONFIG_AARCH32_EL0
			for (j = 0; j < ARRAY_SIZE(compat_hwcap_str); j++) {
				if (a32_elf_hwcap & (1 << j)) {
					/*
					 * Warn once if any feature should not
					 * have been present on arm64 platform.
					 */
					if (WARN_ON_ONCE(!compat_hwcap_str[j]))
						continue;

					seq_printf(m, " %s", compat_hwcap_str[j]);
				}
			}

			for (j = 0; j < ARRAY_SIZE(compat_hwcap2_str); j++)
				if (a32_elf_hwcap2 & (1 << j))
					seq_printf(m, " %s", compat_hwcap2_str[j]);
#endif /* CONFIG_AARCH32_EL0 */
		} else {
			for (j = 0; j < ARRAY_SIZE(hwcap_str); j++)
				if (cpu_have_feature(j))
					seq_printf(m, " %s", hwcap_str[j]);
		}
		seq_puts(m, "\n");

		seq_printf(m, "CPU implementer\t: 0x%02x\n",
			   MIDR_IMPLEMENTOR(midr));
		seq_printf(m, "CPU architecture: 8\n");
		seq_printf(m, "CPU variant\t: 0x%x\n", MIDR_VARIANT(midr));
		seq_printf(m, "CPU part\t: 0x%03x\n", MIDR_PARTNUM(midr));
		seq_printf(m, "CPU revision\t: %d\n\n", MIDR_REVISION(midr));
	}

	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void c_stop(struct seq_file *m, void *v)
{
}

const struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= c_show
};


static struct kobj_type cpuregs_kobj_type = {
	.sysfs_ops = &kobj_sysfs_ops,
};

/*
 * The ARM ARM uses the phrase "32-bit register" to describe a register
 * whose upper 32 bits are RES0 (per C5.1.1, ARM DDI 0487A.i), however
 * no statement is made as to whether the upper 32 bits will or will not
 * be made use of in future, and between ARM DDI 0487A.c and ARM DDI
 * 0487A.d CLIDR_EL1 was expanded from 32-bit to 64-bit.
 *
 * Thus, while both MIDR_EL1 and REVIDR_EL1 are described as 32-bit
 * registers, we expose them both as 64 bit values to cater for possible
 * future expansion without an ABI break.
 */
#define kobj_to_cpuinfo(kobj)	container_of(kobj, struct cpuinfo_arm64, kobj)
#define CPUREGS_ATTR_RO(_name, _field)						\
	static ssize_t _name##_show(struct kobject *kobj,			\
			struct kobj_attribute *attr, char *buf)			\
	{									\
		struct cpuinfo_arm64 *info = kobj_to_cpuinfo(kobj);		\
										\
		if (info->reg_midr)						\
			return sprintf(buf, "0x%016x\n", info->reg_##_field);	\
		else								\
			return 0;						\
	}									\
	static struct kobj_attribute cpuregs_attr_##_name = __ATTR_RO(_name)

CPUREGS_ATTR_RO(midr_el1, midr);
CPUREGS_ATTR_RO(revidr_el1, revidr);

static struct attribute *cpuregs_id_attrs[] = {
	&cpuregs_attr_midr_el1.attr,
	&cpuregs_attr_revidr_el1.attr,
	NULL
};

static const struct attribute_group cpuregs_attr_group = {
	.attrs = cpuregs_id_attrs,
	.name = "identification"
};

static int cpuid_cpu_online(unsigned int cpu)
{
	int rc;
	struct device *dev;
	struct cpuinfo_arm64 *info = &per_cpu(cpu_data, cpu);

	dev = get_cpu_device(cpu);
	if (!dev) {
		rc = -ENODEV;
		goto out;
	}
	rc = kobject_add(&info->kobj, &dev->kobj, "regs");
	if (rc)
		goto out;
	rc = sysfs_create_group(&info->kobj, &cpuregs_attr_group);
	if (rc)
		kobject_del(&info->kobj);
out:
	return rc;
}

static int cpuid_cpu_offline(unsigned int cpu)
{
	struct device *dev;
	struct cpuinfo_arm64 *info = &per_cpu(cpu_data, cpu);

	dev = get_cpu_device(cpu);
	if (!dev)
		return -ENODEV;
	if (info->kobj.parent) {
		sysfs_remove_group(&info->kobj, &cpuregs_attr_group);
		kobject_del(&info->kobj);
	}

	return 0;
}

static int __init cpuinfo_regs_init(void)
{
	int cpu, ret;

	for_each_possible_cpu(cpu) {
		struct cpuinfo_arm64 *info = &per_cpu(cpu_data, cpu);

		kobject_init(&info->kobj, &cpuregs_kobj_type);
	}

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "arm64/cpuinfo:online",
				cpuid_cpu_online, cpuid_cpu_offline);
	if (ret < 0) {
		pr_err("cpuinfo: failed to register hotplug callbacks.\n");
		return ret;
	}
	return 0;
}
device_initcall(cpuinfo_regs_init);

static void cpuinfo_detect_icache_policy(struct cpuinfo_arm64 *info)
{
	unsigned int cpu = smp_processor_id();
	u32 l1ip = CTR_L1IP(info->reg_ctr);

	switch (l1ip) {
	case ICACHE_POLICY_PIPT:
		break;
	case ICACHE_POLICY_VPIPT:
		set_bit(ICACHEF_VPIPT, &__icache_flags);
		break;
	case ICACHE_POLICY_RESERVED:
	case ICACHE_POLICY_VIPT:
		/* Assume aliasing */
		set_bit(ICACHEF_ALIASING, &__icache_flags);
		break;
	}

	pr_info("Detected %s I-cache on CPU%d\n", icache_policy_str[l1ip], cpu);
}

static void __cpuinfo_store_cpu(struct cpuinfo_arm64 *info)
{
	info->reg_cntfrq = arch_timer_get_cntfrq();
	/*
	 * Use the effective value of the CTR_EL0 than the raw value
	 * exposed by the CPU. CTR_EL0.IDC field value must be interpreted
	 * with the CLIDR_EL1 fields to avoid triggering false warnings
	 * when there is a mismatch across the CPUs. Keep track of the
	 * effective value of the CTR_EL0 in our internal records for
	 * acurate sanity check and feature enablement.
	 */
	info->reg_ctr = read_cpuid_effective_cachetype();
	info->reg_dczid = read_cpuid(DCZID_EL0);
	info->reg_midr = read_cpuid_id();
	info->reg_revidr = read_cpuid(REVIDR_EL1);

	info->reg_id_aa64dfr0 = read_cpuid(ID_AA64DFR0_EL1);
	info->reg_id_aa64dfr1 = read_cpuid(ID_AA64DFR1_EL1);
	info->reg_id_aa64isar0 = read_cpuid(ID_AA64ISAR0_EL1);
	info->reg_id_aa64isar1 = read_cpuid(ID_AA64ISAR1_EL1);
	info->reg_id_aa64isar2 = read_cpuid(ID_AA64ISAR2_EL1);
	info->reg_id_aa64mmfr0 = read_cpuid(ID_AA64MMFR0_EL1);
	info->reg_id_aa64mmfr1 = read_cpuid(ID_AA64MMFR1_EL1);
	info->reg_id_aa64mmfr2 = read_cpuid(ID_AA64MMFR2_EL1);
	info->reg_id_aa64pfr0 = read_cpuid(ID_AA64PFR0_EL1);
	info->reg_id_aa64pfr1 = read_cpuid(ID_AA64PFR1_EL1);
	info->reg_id_aa64zfr0 = read_cpuid(ID_AA64ZFR0_EL1);

	/* Update the 32bit ID registers only if AArch32 is implemented */
	if (id_aa64pfr0_32bit_el0(info->reg_id_aa64pfr0)) {
		info->reg_id_dfr0 = read_cpuid(ID_DFR0_EL1);
		info->reg_id_dfr1 = read_cpuid(ID_DFR1_EL1);
		info->reg_id_isar0 = read_cpuid(ID_ISAR0_EL1);
		info->reg_id_isar1 = read_cpuid(ID_ISAR1_EL1);
		info->reg_id_isar2 = read_cpuid(ID_ISAR2_EL1);
		info->reg_id_isar3 = read_cpuid(ID_ISAR3_EL1);
		info->reg_id_isar4 = read_cpuid(ID_ISAR4_EL1);
		info->reg_id_isar5 = read_cpuid(ID_ISAR5_EL1);
		info->reg_id_isar6 = read_cpuid(ID_ISAR6_EL1);
		info->reg_id_mmfr0 = read_cpuid(ID_MMFR0_EL1);
		info->reg_id_mmfr1 = read_cpuid(ID_MMFR1_EL1);
		info->reg_id_mmfr2 = read_cpuid(ID_MMFR2_EL1);
		info->reg_id_mmfr3 = read_cpuid(ID_MMFR3_EL1);
		info->reg_id_mmfr4 = read_cpuid(ID_MMFR4_EL1);
		info->reg_id_mmfr5 = read_cpuid(ID_MMFR5_EL1);
		info->reg_id_pfr0 = read_cpuid(ID_PFR0_EL1);
		info->reg_id_pfr1 = read_cpuid(ID_PFR1_EL1);
		info->reg_id_pfr2 = read_cpuid(ID_PFR2_EL1);

		info->reg_mvfr0 = read_cpuid(MVFR0_EL1);
		info->reg_mvfr1 = read_cpuid(MVFR1_EL1);
		info->reg_mvfr2 = read_cpuid(MVFR2_EL1);
	}

	if (IS_ENABLED(CONFIG_ARM64_SVE) &&
	    id_aa64pfr0_sve(info->reg_id_aa64pfr0))
		info->reg_zcr = read_zcr_features();

	cpuinfo_detect_icache_policy(info);
}

void cpuinfo_store_cpu(void)
{
	struct cpuinfo_arm64 *info = this_cpu_ptr(&cpu_data);
	__cpuinfo_store_cpu(info);
	update_cpu_features(smp_processor_id(), info, &boot_cpu_data);
}

void __init cpuinfo_store_boot_cpu(void)
{
	struct cpuinfo_arm64 *info = &per_cpu(cpu_data, 0);
	__cpuinfo_store_cpu(info);

	boot_cpu_data = *info;
	init_cpu_features(&boot_cpu_data);
}

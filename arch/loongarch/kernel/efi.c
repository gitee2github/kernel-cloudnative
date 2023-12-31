// SPDX-License-Identifier: GPL-2.0
/*
 * EFI initialization
 *
 * Author: Jianmin Lv <lvjianmin@loongson.cn>
 *         Huacai Chen <chenhuacai@loongson.cn>
 *
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/acpi.h>
#include <linux/efi.h>
#include <linux/efi-bgrt.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/io.h>
#include <asm/pgalloc.h>
#include <linux/kobject.h>
#include <linux/memblock.h>
#include <linux/reboot.h>
#include <linux/uaccess.h>

#include <asm/early_ioremap.h>
#include <asm/efi.h>
#include <asm/tlb.h>
#include <asm/loongson.h>
#include "legacy_boot.h"

static unsigned long efi_nr_tables;
static unsigned long efi_config_table;

static efi_system_table_t *efi_systab;
static efi_config_table_type_t arch_tables[] __initdata = {{},};
static __initdata pgd_t *pgd_efi;

static int __init efimap_populate_hugepages(
		unsigned long start, unsigned long end,
		pgprot_t prot)
{
	unsigned long addr;
	unsigned long next;
	pmd_t entry;
	pud_t *pud;
	pmd_t *pmd;

	for (addr = start; addr < end; addr = next) {
		next = pmd_addr_end(addr, end);
		pud = pud_offset((p4d_t *)pgd_efi + pgd_index(addr), addr);
		if (pud_none(*pud)) {
			void *p = memblock_alloc_low(PAGE_SIZE, PAGE_SIZE);
			if (!p)
				return -1;
			pmd_init(p);
			pud_populate(&init_mm, pud, p);
		}
		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd)) {
			entry = pfn_pmd((addr >> PAGE_SHIFT), prot);
			entry = pmd_mkhuge(entry);
			set_pmd_at(&init_mm, addr, pmd, entry);
		}
	}
	return 0;
}

static void __init efi_map_pgt(void)
{
	unsigned long node;
	unsigned long start, end;
	unsigned long start_pfn, end_pfn;

	pgd_efi = memblock_alloc_low(PAGE_SIZE, PAGE_SIZE);
	if (!pgd_efi) {
		pr_err("alloc efi pgd failed!\n");
		return;
	}
	pgd_init(pgd_efi);
	csr_write64((long)pgd_efi, LOONGARCH_CSR_PGDL);

	/* Low Memory, Cached */
	efimap_populate_hugepages(0, SZ_256M, PAGE_KERNEL);

	for_each_node_mask(node, node_possible_map) {
		/* MMIO Registers, Uncached */
		efimap_populate_hugepages(SZ_256M | (node << 44),
				SZ_512M | (node << 44), PAGE_KERNEL_SUC);

		get_pfn_range_for_nid(node, &start_pfn, &end_pfn);
		start = ALIGN_DOWN(start_pfn << PAGE_SHIFT, PMD_SIZE);
		end = ALIGN(end_pfn << PAGE_SHIFT, PMD_SIZE);

		/* System memory, Cached */
		efimap_populate_hugepages(node ? start : SZ_512M, end, PAGE_KERNEL);
	}
}

static int __init efimap_free_pgt(unsigned long start, unsigned long end)
{
	unsigned long addr;
	unsigned long next;
	pud_t *pud;
	pmd_t *pmd;

	for (addr = start; addr < end; addr = next) {
		next = pmd_addr_end(addr, end);

		pud = pud_offset((p4d_t *)pgd_efi + pgd_index(addr), addr);
		if (!pud_present(*pud))
			continue;
		pmd = pmd_offset(pud, addr);
		memblock_free_early(virt_to_phys((void *)pmd), PAGE_SIZE);
		pud_clear(pud);
	}
	return 0;
}

static void __init efi_unmap_pgt(void)
{
	unsigned long node;
	unsigned long start, end;
	unsigned long start_pfn, end_pfn;

	for_each_node_mask(node, node_possible_map) {
		get_pfn_range_for_nid(node, &start_pfn, &end_pfn);
		start = ALIGN_DOWN(start_pfn << PAGE_SHIFT, PMD_SIZE);
		end = ALIGN(end_pfn << PAGE_SHIFT, PMD_SIZE);

		/* Free pagetable memory */
		efimap_free_pgt(start, end);
	}

	memblock_free_early(virt_to_phys((void *)pgd_efi), PAGE_SIZE);
	csr_write64((long)invalid_pg_dir, LOONGARCH_CSR_PGDL);
	local_flush_tlb_all();

	return;
}

/*
 * set_virtual_map() - create a virtual mapping for the EFI memory map and call
 * efi_set_virtual_address_map enter virtual for runtime service
 *
 * This function populates the virt_addr fields of all memory region descriptors
 * in @memory_map whose EFI_MEMORY_RUNTIME attribute is set. Those descriptors
 * are also copied to @runtime_map, and their total count is returned in @count.
 */
static int __init set_virtual_map(void)
{
	efi_status_t status;
	int count = 0;
	unsigned int size;
	unsigned long attr;
	efi_runtime_services_t *rt;
	efi_set_virtual_address_map_t *svam;
	efi_memory_desc_t *in, runtime_map[32];

	if (efi_bp)
		return EFI_SUCCESS;

	size = sizeof(efi_memory_desc_t);

	for_each_efi_memory_desc(in) {
		attr = in->attribute;
		if (!(attr & EFI_MEMORY_RUNTIME))
			continue;

		if (attr & (EFI_MEMORY_WB | EFI_MEMORY_WT))
			in->virt_addr = TO_CACHE(in->phys_addr);
		else
			in->virt_addr = TO_UNCACHE(in->phys_addr);

		memcpy(&runtime_map[count++], in, size);
	}

	rt = early_memremap_ro((unsigned long)efi_systab->runtime, sizeof(*rt));

	/* Install the new virtual address map */
	svam = rt->set_virtual_address_map;

	efi_map_pgt();

	status = svam(size * count, size, efi.memmap.desc_version,
			(efi_memory_desc_t *)TO_PHYS((unsigned long)runtime_map));

	efi_unmap_pgt();
	return 0;
}

void __init efi_runtime_init(void)
{
	efi_status_t status;

	if (!efi_enabled(EFI_BOOT))
		return;

	if (efi_runtime_disabled()) {
		pr_info("EFI runtime services will be disabled.\n");
		return;
	}

	if (!efi_systab->runtime)
		return;

	status = set_virtual_map();
	if (status < 0)
		return;

	efi.runtime = (efi_runtime_services_t *)efi_systab->runtime;
	efi.runtime_version = (unsigned int)efi.runtime->hdr.revision;

	efi_native_runtime_setup();
	set_bit(EFI_RUNTIME_SERVICES, &efi.flags);
}

void __init loongson_efi_init(void)
{
	int size;
	void *config_tables;

	if (efi_system_table)
		efi_systab = (efi_system_table_t *)early_memremap_ro(efi_system_table, sizeof(*efi_systab));
	else
		efi_systab = (efi_system_table_t *)efi_bp->systemtable;

	if (!efi_systab) {
		pr_err("Can't find EFI system table.\n");
		return;
	}

	set_bit(EFI_64BIT, &efi.flags);
	efi_nr_tables	 = efi_systab->nr_tables;
	efi_config_table = (unsigned long)efi_systab->tables;

	size = sizeof(efi_config_table_t);
	config_tables = early_memremap(efi_config_table, efi_nr_tables * size);
	efi_config_parse_tables(config_tables, efi_systab->nr_tables, arch_tables);
	early_memunmap(config_tables, efi_nr_tables * size);

	if (screen_info.orig_video_isVGA == VIDEO_TYPE_EFI)
		memblock_reserve(screen_info.lfb_base, screen_info.lfb_size);
}

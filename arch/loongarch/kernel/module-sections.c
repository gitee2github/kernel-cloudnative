// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/elf.h>
#include <linux/kernel.h>
#include <linux/module.h>

Elf_Addr module_emit_got_entry(struct module *mod, Elf_Addr val)
{
	struct mod_section *got_sec = &mod->arch.got;
	int i = got_sec->num_entries;
	struct got_entry *got = get_got_entry(val, got_sec);

	if (got)
		return (Elf_Addr)got;

	/* There is no GOT entry for val yet, create a new one. */
	got = (struct got_entry *)got_sec->shdr->sh_addr;
	got[i] = emit_got_entry(val);

	got_sec->num_entries++;
	if (got_sec->num_entries > got_sec->max_entries) {
		/*
		 * This may happen when the module contains a GOT_HI20 without
		 * a paired GOT_LO12. Such a module is broken, reject it.
		 */
		pr_err("%s: module contains bad GOT relocation\n", mod->name);
		return 0;
	}

	return (Elf_Addr)&got[i];
}

Elf_Addr module_emit_plt_entry(struct module *mod, Elf_Addr val)
{
	int nr;
	struct mod_section *plt_sec = &mod->arch.plt;
	struct mod_section *plt_idx_sec = &mod->arch.plt_idx;
	struct plt_entry *plt = get_plt_entry(val, plt_sec, plt_idx_sec);
	struct plt_idx_entry *plt_idx;

	if (plt)
		return (Elf_Addr)plt;

	nr = plt_sec->num_entries;

	/* There is no duplicate entry, create a new one */
	plt = (struct plt_entry *)plt_sec->shdr->sh_addr;
	plt[nr] = emit_plt_entry(val);
	plt_idx = (struct plt_idx_entry *)plt_idx_sec->shdr->sh_addr;
	plt_idx[nr] = emit_plt_idx_entry(val);

	plt_sec->num_entries++;
	plt_idx_sec->num_entries++;
	BUG_ON(plt_sec->num_entries > plt_sec->max_entries);

	return (Elf_Addr)&plt[nr];
}

static int is_rela_equal(const Elf_Rela *x, const Elf_Rela *y)
{
	return x->r_info == y->r_info && x->r_addend == y->r_addend;
}

static bool duplicate_rela(const Elf_Rela *rela, int idx)
{
	int i;

	for (i = 0; i < idx; i++) {
		if (is_rela_equal(&rela[i], &rela[idx]))
			return true;
	}

	return false;
}

static void count_max_entries(Elf_Rela *relas, int num,
			      unsigned int *plts, unsigned int *gots)
{
	unsigned int i, type;

	for (i = 0; i < num; i++) {
		type = ELF_R_TYPE(relas[i].r_info);
		switch (type) {
		case R_LARCH_SOP_PUSH_PLT_PCREL:
		case R_LARCH_B26:
			if (!duplicate_rela(relas, i))
				(*plts)++;
			break;
		case R_LARCH_GOT_PC_HI20:
			if (!duplicate_rela(relas, i))
				(*gots)++;
			break;
		default:
			/* Do nothing. */
			break;
		}
	}
}

int module_frob_arch_sections(Elf_Ehdr *ehdr, Elf_Shdr *sechdrs,
			      char *secstrings, struct module *mod)
{
	unsigned int i, num_plts = 0, num_gots = 0;

	/*
	 * Find the empty .plt sections.
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(secstrings + sechdrs[i].sh_name, ".got"))
			mod->arch.got.shdr = sechdrs + i;
		else if (!strcmp(secstrings + sechdrs[i].sh_name, ".plt"))
			mod->arch.plt.shdr = sechdrs + i;
		else if (!strcmp(secstrings + sechdrs[i].sh_name, ".plt.idx"))
			mod->arch.plt_idx.shdr = sechdrs + i;
	}

	if (!mod->arch.got.shdr) {
		pr_err("%s: module GOT section(s) missing\n", mod->name);
		return -ENOEXEC;
	}
	if (!mod->arch.plt.shdr) {
		pr_err("%s: module PLT section(s) missing\n", mod->name);
		return -ENOEXEC;
	}
	if (!mod->arch.plt_idx.shdr) {
		pr_err("%s: module PLT.IDX section(s) missing\n", mod->name);
		return -ENOEXEC;
	}

	/* Calculate the maxinum number of entries */
	for (i = 0; i < ehdr->e_shnum; i++) {
		int num_rela = sechdrs[i].sh_size / sizeof(Elf_Rela);
		Elf_Rela *relas = (void *)ehdr + sechdrs[i].sh_offset;
		Elf_Shdr *dst_sec = sechdrs + sechdrs[i].sh_info;

		if (sechdrs[i].sh_type != SHT_RELA)
			continue;

		/* ignore relocations that operate on non-exec sections */
		if (!(dst_sec->sh_flags & SHF_EXECINSTR))
			continue;

		count_max_entries(relas, num_rela, &num_plts, &num_gots);
	}

	mod->arch.got.shdr->sh_type = SHT_NOBITS;
	mod->arch.got.shdr->sh_flags = SHF_ALLOC;
	mod->arch.got.shdr->sh_addralign = L1_CACHE_BYTES;
	mod->arch.got.shdr->sh_size = (num_gots + 1) * sizeof(struct got_entry);
	mod->arch.got.num_entries = 0;
	mod->arch.got.max_entries = num_gots;

	mod->arch.plt.shdr->sh_type = SHT_NOBITS;
	mod->arch.plt.shdr->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
	mod->arch.plt.shdr->sh_addralign = L1_CACHE_BYTES;
	mod->arch.plt.shdr->sh_size = (num_plts + 1) * sizeof(struct plt_entry);
	mod->arch.plt.num_entries = 0;
	mod->arch.plt.max_entries = num_plts;

	mod->arch.plt_idx.shdr->sh_type = SHT_NOBITS;
	mod->arch.plt_idx.shdr->sh_flags = SHF_ALLOC;
	mod->arch.plt_idx.shdr->sh_addralign = L1_CACHE_BYTES;
	mod->arch.plt_idx.shdr->sh_size = (num_plts + 1) * sizeof(struct plt_idx_entry);
	mod->arch.plt_idx.num_entries = 0;
	mod->arch.plt_idx.max_entries = num_plts;

	return 0;
}

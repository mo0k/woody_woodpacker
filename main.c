#include <stdio.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FILE 2
#define ADD_SIZE(phdr) ((phdr->p_memsz - phdr->p_filesz))
#define PAGE_SIZE 4096
#define OPSIZE sizeof(shellcode)-1
//#define OPSIZE 0

unsigned char shellcode[] = 
"\x57\x56\x50\x52\xe8\x0e\x00\x00\x00\x2e\x2e\x2e\x2e\x57\x4f\x4f"
"\x44\x59\x2e\x2e\x2e\x2e\x0a\x5e\x48\x31\xff\x48\x31\xc0\xb0\x01"
"\x66\xbf\x01\x00\x48\x31\xd2\xb2\x0e\x0f\x05\x5a\x58\x5e\x5f";

#define SIZE_JMP sizeof(jump) -1
char jump[] = "\xe9\xff\xff\xff\xff";

#define PADSIZE PAGE_SIZE-(OPSIZE+SIZE_JMP)
unsigned char padding[PADSIZE];

#define SIZE_INJECT OPSIZE + PADSIZE + SIZE_JMP


typedef struct 
{
	void		*addr;
	size_t		size;
}				t_map;

typedef struct 
{
	struct stat	s;
	int 		fd;
	t_map		map;
}				t_file;

typedef struct 
{
	int			*fd[MAX_FILE];
	t_map		*map[MAX_FILE];
}				t_garbage; 

t_garbage g_garbage_info;

void	set_garbage(t_file *file)
{
	static int i = 0;

	g_garbage_info.fd[i] = &file->fd;
	g_garbage_info.map[i] = &file->map;
	++i;
}

int		exit_prog(int ret_value, char *message)
{
	/* loop for munmap all memory */
	int i = -1;
	while (g_garbage_info.map[++i] != 0)
	{
		munmap(g_garbage_info.map[i]->addr,
				g_garbage_info.map[i]->size);
		g_garbage_info.map[i]->addr = 0;
	}
	/* loop for close all fd */
	i = -1;
	while (g_garbage_info.fd[++i] != 0)
	{
		close(*g_garbage_info.fd[i]);
		g_garbage_info.fd[i] = 0;
	}
	if (message)
		printf("%s", message);
	exit(ret_value);
}

void	init_binary(t_file *file, char *path)
{
	memset(file, 0, sizeof(file));
	set_garbage(file);

	/* Open file */
	file->fd = open(path, O_RDONLY);
	if (file->fd == -1)
		exit_prog(2, "Error fstat\n");
	printf("__ Ouverture %s\n", path);

	/* Get stat file */
	if (fstat(file->fd, &file->s) == -1)
		exit_prog(3, "Error fstat\n");
	printf("file size fstat:%zd\n", file->s.st_size);
	file->map.size = file->s.st_size;
	printf("__ Stats %s\n", path);

	/* Load file */
	file->map.addr = mmap(	0, 
							file->map.size,
							PROT_READ | PROT_WRITE,
							MAP_PRIVATE,
							file->fd,
							0 );
	if (file->map.addr == MAP_FAILED)
		exit_prog(4, "Error mmap\n");
	printf("__ Chargement en memoire %s\n", path);
}

void 	print_elf64_hdr(Elf64_Ehdr *elf_hdr)
{
	printf("\n __INFO ELF64 HEADER__\n");
	printf("|\n");
	printf("| NBR prg_hdr:\t0x%02x\n", elf_hdr->e_phnum);
	printf("| OFF prg_hdr:\t0x%02x\n", elf_hdr->e_phoff);
	printf("| NBR sect_hdr:\t0x%02x\n", elf_hdr->e_shnum);
	printf("| OFF sect_hdr:\t0x%02x\n", elf_hdr->e_shoff);
	printf("| IDX strtable:\t0x%02x\n", elf_hdr->e_shstrndx);
	printf("|__\n");
}

Elf64_Phdr *get_xpload(void *ptr)
{
	Elf64_Ehdr	*ehdr;
	Elf64_Phdr	*phdr;
	uint16_t 	i;

	ehdr = (Elf64_Ehdr*)ptr;
	phdr = (Elf64_Phdr*)(ptr + ehdr->e_phoff);
	i = 0;
	while(i < ehdr->e_phnum)
	{
		if (phdr->p_type == PT_LOAD && phdr->p_flags | PF_X)
			return (phdr);
		++i;
		phdr += 1;
	}
	return (0);
}

Elf64_Phdr *get_last_pload(void *ptr, uint8_t *flag_bss)
{
	Elf64_Ehdr	*ehdr;
	Elf64_Phdr	*phdr;
	Elf64_Phdr	*phdr_next;
	uint16_t 	i;

	ehdr = (Elf64_Ehdr*)ptr;
	phdr = (Elf64_Phdr*)(ptr + ehdr->e_phoff);
	i = 0;
	while(i < ehdr->e_phnum)
	{
		if (i != ehdr->e_phnum - 1)
			phdr_next = phdr + 1;
		if (phdr->p_type == PT_LOAD && phdr_next->p_type != PT_LOAD)
		{
			if (phdr->p_filesz != phdr->p_memsz)
				*flag_bss = 1;
			return (phdr);
		}
		++i;
		phdr += 1;
	}
	return (0);
}

Elf64_Shdr *get_bss_shdr(void *ptr)
{
	Elf64_Ehdr	*ehdr;
	Elf64_Shdr	*shdr;
	uint16_t 	i;
	char 		*string;

	ehdr = (Elf64_Ehdr*)ptr;
	shdr = (Elf64_Shdr*)(ptr + ehdr->e_shoff);
	string = ptr + shdr[ehdr->e_shstrndx].sh_offset;
	i = 0;
	while(i < ehdr->e_shnum)
	{
		if (!strcmp(".bss", string + shdr->sh_name))
			return (shdr);
		++i;
		shdr += 1;
	}
	return (0);
}

void	add_bss(int fd, size_t bss_size)
{
	char	*buff;

	lseek(fd, 0, SEEK_CUR);
	buff = malloc(bss_size);
	if (!buff)
		exit(100);
	memset(buff, 0, bss_size);
	write(fd, buff, bss_size);
	free(buff);
}

void 	create_binay_packed(t_file *file, void *pload_end, size_t bss_size, uint8_t flag_bss)
{
	int		fd;

	fd = open("new", O_RDWR | O_CREAT, 0755);
	if (fd == -1)
		exit_prog(1, "open new binary");
	lseek(fd, 0, SEEK_SET);
	printf("len:%ld\n", pload_end - file->map.addr);
	write(fd, file->map.addr, pload_end - file->map.addr);
	//if (flag_bss)
	//	add_bss(fd, bss_size);

	lseek(fd, 0, SEEK_CUR);
	//add opcode
	//printf("size shellcode:%zd\n", OPCODESZ );
	write(fd, shellcode, OPSIZE);
	
	lseek(fd, 0, SEEK_CUR);
	write(fd, jump, 5);

	memset(padding, 0, PADSIZE);
	lseek(fd, 0, SEEK_CUR);
	write(fd, padding, PADSIZE);
	
	lseek(fd, 0, SEEK_CUR);
	printf("LEN:%d, padding len:%zd, op len:%zd\n", SIZE_INJECT, PADSIZE, OPSIZE);
	write(fd,
			pload_end,
			(file->map.addr + file->map.size) - pload_end);
	close(fd);
	printf("fin d'ecriture\n");
}

void 	set_shstrndx(void *ptr, int new_size)
{
	//add bss size in offset of shstrndx section header
	Elf64_Shdr *shdr;
	shdr = (Elf64_Shdr*)(ptr + ((Elf64_Ehdr*)(ptr))->e_shoff);
	shdr[((Elf64_Ehdr*)(ptr))->e_shstrndx].sh_offset += new_size;
}

void 	set_new_config(void *ptr, Elf64_Phdr *phdr, int bss_size)
{
	//modif e_entry;
	((Elf64_Ehdr*)(ptr))->e_entry = phdr->p_offset + phdr->p_memsz;

	set_shstrndx(ptr, bss_size + SIZE_INJECT);

	//add size in offset of first section header
	((Elf64_Ehdr*)(ptr))->e_shoff += bss_size + SIZE_INJECT;

	//modif size last PLOAD
	phdr->p_memsz += SIZE_INJECT;
	phdr->p_filesz = phdr->p_memsz;

	//add right X
	phdr->p_flags |= PF_X;
}

/*
	Elf64_Ehdr 	*ehdr;
	Elf64_Phdr 	*phdr;
	Elf64_Shdr 	*shdr;
	uint8_t		flag_bss;
	int 		bss_size;
	void		*pload_end;

	close(file->fd);
	ehdr = (Elf64_Ehdr*)(file->map.addr);
	print_elf64_hdr(ehdr);
	phdr = get_last_pload(file->map.addr, &flag_bss);

	bss_size = ADD_SIZE(phdr); // +opcode_size
	
	pload_end = file->map.addr + phdr->p_offset + phdr->p_filesz;
	
	set_new_config(file->map.addr, phdr, bss_size);

	

	printf("PHDR:%p\tbss:%d\n", phdr, flag_bss);
	create_binay_packed(file, pload_end, bss_size, flag_bss);
*/

void	set_phdr_offset(Elf64_Phdr *phdr, uint64_t offset, uint16_t phnum)
{
	int i;
	//uint16_t offset;

	//i = (cur_phdr - first_phdr) / sizeof(Elf64_Phdr);
	//printf("index:%d\n", i);
	//offset = phdr[i].p_offset;
	///i += 1;
	for(i = 0; i < phnum; ++i)
	{
		printf("phdr[i].p_offset:0x%x\toffset:0x%x\n", phdr[i].p_offset, offset);
		if (phdr[i].p_offset > offset)
		{
			printf("GOOOOO\n");
			printf("phdr[i].p_offset:0x%x\n", phdr[i].p_offset);
			phdr[i].p_offset += SIZE_INJECT;
			printf("phdr[i].p_offset:0x%x\n", phdr[i].p_offset);
		}
	}
}

void	set_shdr_offset(Elf64_Shdr *shdr, uint64_t offset, uint16_t shnum)
{
	int i;
	//uint16_t offset;

	//i = (cur_phdr - first_phdr) / sizeof(Elf64_Phdr);
	//printf("index:%d\n", i);
	//offset = phdr[i].p_offset;
	///i += 1;
	for(i = 0; i < shnum; ++i)
	{
		printf("shdr[i].s_offset:0x%x\toffset:0x%x\n", shdr[i].sh_offset, offset);
		if (shdr[i].sh_offset > offset)
		{
			printf("shdr[i].p_offset:0x%x\n", shdr[i].sh_offset);
			shdr[i].sh_offset += SIZE_INJECT;
			printf("shdr[i].p_offset:0x%x\n", shdr[i].sh_offset);
		}
	}
}

void	wwp_elf64(t_file *file)
{

	Elf64_Ehdr 	*ehdr;
	Elf64_Phdr 	*phdr;
	Elf64_Shdr 	*shdr;
	void		*split;
	int 		orign_entry;

	close(file->fd);
	ehdr = (Elf64_Ehdr*)(file->map.addr);

	//Recupere prog header avec les droit execution
	phdr = get_xpload(file->map.addr);
	printf("phdr:%p\n", phdr);
	if (phdr)
	{
		//uint64_t tmp_offset;
		//tmp_offset = (phdr + 1)->p_offset;
		printf("HEOOOOOO\n");
		orign_entry = ehdr->e_entry;
		ehdr->e_entry = phdr->p_offset + phdr->p_filesz;
		int jmp_addr;
		//jmp_addr = orign_entry - (ehdr->e_entry + SIZE_INJECT);
		jmp_addr = orign_entry - (ehdr->e_entry + OPSIZE + SIZE_JMP);
		memmove(jump + 1, &jmp_addr, sizeof(int));
		// Sauvegarde du pointeur de fin du segment PLOAD 
		printf("p_offset:%d\n", (phdr + 1)->p_offset);
		split = file->map.addr + phdr->p_offset + phdr->p_filesz;

		set_phdr_offset(file->map.addr + ehdr->e_phoff,
						phdr->p_offset + phdr->p_memsz,
						ehdr->e_phnum);
		set_shdr_offset(file->map.addr + ehdr->e_shoff,
						phdr->p_offset + phdr->p_memsz,
						ehdr->e_shnum);
		printf("avant ehdr->e_shoff:0x%x\n",ehdr->e_shoff);
		ehdr->e_shoff += SIZE_INJECT;
		printf("apres ehdr->e_shoff:0x%x\n",ehdr->e_shoff);
		//phdr->p_memsz = tmp_offset;
		//printf("phdr->p_memsz:0x%x\n", phdr->p_memsz);
		phdr->p_memsz += SIZE_INJECT;
		//printf("phdr->p_memsz:0x%x\n", phdr->p_memsz);
		phdr->p_filesz += SIZE_INJECT;

		phdr->p_flags |= PF_W;

	}
	create_binay_packed(file, split, 0, 0);
}

int		main(int ac, char **av)
{
	t_file orign_file;
	t_file new_file;

	printf("sizeof(Elf64_Shdr):%zd\n", sizeof(Elf64_Shdr));
	printf("sizeof(Elf64_Phdr):%zd\n", sizeof(Elf64_Phdr));
	memset(&new_file, 0, sizeof(new_file));
	memset(&g_garbage_info, 0, sizeof(t_garbage));
	set_garbage(&new_file);

	/* Check input */
	if (ac != 2)
		exit_prog(1, "./wwwp elf_file\n");

	init_binary(&orign_file, av[1]);
	wwp_elf64(&orign_file);

	exit_prog(0, 0);

	return (0);
}
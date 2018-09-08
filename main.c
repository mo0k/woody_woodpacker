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

unsigned char shellcode[] =  //print WOODY
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
	while (++i < MAX_FILE)
	{
		munmap(g_garbage_info.map[i]->addr,
				g_garbage_info.map[i]->size);
		g_garbage_info.map[i]->addr = 0;
	}
	/* loop for close all fd */
	i = -1;
	while (++i < MAX_FILE)
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
		exit_prog(2, "Error open\n");
	printf("__ Ouverture %s\n", path);

	/* Get stat file */
	if (fstat(file->fd, &file->s) == -1)
		exit_prog(3, "Error fstat\n");
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

void 	create_binay_packed(t_file *file, void *pload_end)
{
	int		fd;

	fd = open("new", O_RDWR | O_CREAT, 0755);
	if (fd == -1)
		exit_prog(1, "open new binary");
	lseek(fd, 0, SEEK_SET);
	printf("len:%ld\n", pload_end - file->map.addr);
	write(fd, file->map.addr, pload_end - file->map.addr);
	write(fd, shellcode, OPSIZE);
	write(fd, jump, 5);
	memset(padding, 0, PADSIZE);
	write(fd, padding, PADSIZE);
	printf("__    LEN:%d, padding len:%zd, op len:%zd\n", SIZE_INJECT, PADSIZE, OPSIZE);
	write(fd, pload_end, (file->map.addr + file->map.size) - pload_end);
	close(fd);
	printf("__ Binaire '%s' creer\n", "new");
}

void	set_phdr_offset(Elf64_Phdr *phdr, uint64_t offset, uint16_t phnum)
{
	int i;

	printf("__ Modification des entetes de segment\n");
	for(i = 0; i < phnum; ++i)
	{
		if (phdr[i].p_offset > offset)
			phdr[i].p_offset += SIZE_INJECT;
	}
}

void	set_shdr_offset(Elf64_Shdr *shdr, uint64_t offset, uint16_t shnum)
{
	int i;

	printf("__ Modification des entetes de section\n");
	for(i = 0; i < shnum; ++i)
	{
		if (shdr[i].sh_offset > offset)
			shdr[i].sh_offset += SIZE_INJECT;
	}
}

void	wwp_elf64(t_file *file)
{

	Elf64_Ehdr 	*ehdr;
	Elf64_Phdr 	*phdr;
	Elf64_Shdr 	*shdr;
	void		*split;
	int 		orign_entry;
	int 		jmp_addr;

	close(file->fd);
	ehdr = (Elf64_Ehdr*)(file->map.addr);

	//Recupere prog header avec les droit execution
	phdr = get_xpload(file->map.addr);
	printf("phdr:%p\n", phdr);
	if (phdr)
	{
		orign_entry = ehdr->e_entry;
		ehdr->e_entry = phdr->p_offset + phdr->p_filesz;
		jmp_addr = orign_entry - (ehdr->e_entry + OPSIZE + SIZE_JMP);
		memmove(jump + 1, &jmp_addr, sizeof(int));

		// Sauvegarde du pointeur de fin du segment PLOAD 
		printf("p_offset:%d\n", (phdr + 1)->p_offset);
		split = file->map.addr + phdr->p_offset + phdr->p_filesz;

		//fix new values
		set_phdr_offset(file->map.addr + ehdr->e_phoff,
						phdr->p_offset + phdr->p_memsz,
						ehdr->e_phnum);
		set_shdr_offset(file->map.addr + ehdr->e_shoff,
						phdr->p_offset + phdr->p_memsz,
						ehdr->e_shnum);
		ehdr->e_shoff += SIZE_INJECT;
		phdr->p_memsz += SIZE_INJECT;
		phdr->p_filesz += SIZE_INJECT;
		phdr->p_flags |= PF_W;
	}
	create_binay_packed(file, split);
}

int		main(int ac, char **av)
{
	t_file orign_file;
	t_file new_file;

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
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

unsigned char shellcode1[] =  //print WOODY
"\x57\x56\x50\x52\xe8\x0e\x00\x00\x00\x2e\x2e\x2e\x2e\x57\x4f\x4f"
"\x44\x59\x2e\x2e\x2e\x2e\x0a\x5e\x48\x31\xff\x48\x31\xc0\xb0\x01"
"\x66\xbf\x01\x00\x48\x31\xd2\xb2\x0e\x0f\x05\x5a\x58\x5e\x5f";
unsigned char shellcode[] =  
"\x57\x4f\x4f\x44\x59\x0a\x57\x56\x52\x50\xbf\x01\x00\x00\x00\x48\x8d\x35\xea\xff\xff\xff\xba\x06\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\x58\x5a\x5e\x5f";
char jump[] = "\xe9\xff\xff\xff\xff";


#define SIZE_JMP sizeof(jump) -1
#define SIZE_WOODY 6
#define SIZE_INJECT OPSIZE + SIZE_JMP

#define PADSIZE PAGE_SIZE-(OPSIZE+SIZE_JMP)
unsigned char padding[PADSIZE];


#define NB_FILE 2
enum e_file
{
	ORIGN,
	PACKED
};

typedef struct 
{
	void		*addr;
	size_t		size;
}				t_map;

typedef struct 
{
	struct stat	s;
	int 		fd;
	char 	*name;
	t_map		map;
}				t_file;

typedef struct
{
	char **name1;
}		t_name;

typedef struct 
{
	t_map		map[MAX_FILE];
	t_name	name[MAX_FILE];
	int			*fd[MAX_FILE];
}				t_garbage; 

t_garbage g_garbage_info;

void	set_garbage(enum e_file type ,t_file *file)
{
	//static int i = 0;
	printf("set_garbage\n");
	g_garbage_info.fd[type] = &file->fd;
	g_garbage_info.map[type] = file->map;
	g_garbage_info.name[type].name1 = &file->name;
	printf("g_garbage_info.map[%s]->addr:%p\n",type ? "PACKED" : "ORIGN" , g_garbage_info.map[type].addr);
	printf("g_garbage_info.map[%s]:%p\n",type ? "PACKED" : "ORIGN" , &g_garbage_info.map[type]);

	//++i;
}

int		exit_prog(int ret_value, char *message)
{
	/* loop for munmap all memory */
	int i = -1;
	while (++i < MAX_FILE)
	{
		if (g_garbage_info.map[i].addr != 0)
		{
			munmap(g_garbage_info.map[i].addr, g_garbage_info.map[i].size);
			g_garbage_info.map[i].addr = 0;
		}
	}
	/* loop for close all fd */
	i = -1;
	while (++i < MAX_FILE)
	{
		if (*g_garbage_info.fd[i] > 0)
		{
			close(*g_garbage_info.fd[i]);
			*g_garbage_info.fd[i] = 0;
		}
	}
	free(*g_garbage_info.name[PACKED].name1);
	*g_garbage_info.name[PACKED].name1 = 0;
	if (message)
		printf("%s", message);
	exit(ret_value);
}

void	init_binary(t_file *file, char *path)
{
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
	file->name = path;

}

void 	print_elf64_hdr(Elf64_Ehdr *elf_hdr)
{
	printf("\n __INFO ELF64 HEADER__\n");
	printf("|\n");
	printf("| NBR prg_hdr:\t0x%02x\n", elf_hdr->e_phnum);
	printf("| OFF prg_hdr:\t0x%02lx\n", elf_hdr->e_phoff);
	printf("| NBR sect_hdr:\t0x%02x\n", elf_hdr->e_shnum);
	printf("| OFF sect_hdr:\t0x%02lx\n", elf_hdr->e_shoff);
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
		//if (phdr->p_type == PT_LOAD)
			//printf("PLOAD\n");
		if (phdr->p_type == PT_LOAD && phdr->p_flags & PF_X)
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

static void		inject_in_ploadx(int fd, t_file *file, void *pload_end)
{
	printf("__ Ecriture de la premier partie\n");
	write(fd, file->map.addr, pload_end - file->map.addr );
	printf("__ Ecriture du shellcode\n");
	write(fd, shellcode, OPSIZE);
	printf("__ Ecriture du jump\n");
	write(fd, jump, SIZE_JMP);
	printf("__ Ecriture de la derniere partie\n");
	write(fd, pload_end  + OPSIZE + SIZE_JMP, (file->map.addr + file->map.size) - (pload_end + OPSIZE + SIZE_JMP));
	printf("file[PACKED].addr:%p\n",file[PACKED].map.addr);

}

char 	*get_name_packed(t_file *file)
{
	static char 	*addname = "_packed";
	char 	*buf;
	char 	*ptr;

	ptr = strrchr(file->name, '/');
	ptr = (ptr == NULL) ? file->name : ptr + 1;
	buf = (char*)malloc((ptr ? strlen(ptr)  : 0) + strlen(addname) + 1);
	strcpy(buf, ptr ? ptr : "");
	strcat(buf, addname);
	return (buf);
}

void 	create_binay_packed(t_file *file, void *pload_end, void *flag_in_ploadx)
{
	file[PACKED].name = get_name_packed(&file[ORIGN]);
	printf("file[PACKED].name:%s\n",file[PACKED].name);
	printf("file[PACKED].addr:%p\n",file[PACKED].map.addr);
	printf("g_garbage_info.map[PACKED]->addr:%p\n",g_garbage_info.map[PACKED].addr);

	file[PACKED].fd = open(file[PACKED].name, O_RDWR | O_CREAT, 0755);
	//free(bin_packed_name);
	if (file[PACKED].fd == -1)
		exit_prog(1, "open new binary");
	if (flag_in_ploadx)
	{
		printf("__ Inject between plaod method\n");
		inject_in_ploadx(file[PACKED].fd, &file[ORIGN], pload_end);
	}
	else
	{
		printf("__ NO_PACKED\n");
	}
	close(file[PACKED].fd);
	printf("__ Binaire packed\n\n");
	printf("file[PACKED].addr:%p\n",file[PACKED].map.addr);
	printf("garbage file[PACKED].addr:%p\n",g_garbage_info.map[PACKED].addr);

}

void	set_phdr_offset(Elf64_Phdr *phdr, uint64_t offset, uint16_t phnum)
{
	int i;

	printf("__ Modification des entetes de segment\n");
	for(i = 0; i < phnum; ++i)
	{
		if (phdr[i].p_offset > offset)
		{
			phdr[i].p_offset += SIZE_INJECT;
			//phdr[i].p_vaddr += SIZE_INJECT;
			//phdr[i].p_paddr += SIZE_INJECT;
		}
	}
}

void	set_shdr_offset(Elf64_Shdr *shdr, uint64_t offset, uint16_t shnum)
{

	int i;

	printf("__ Modification des entetes de section\n");
	for(i = 0; i < shnum; ++i)
	{
		if (shdr[i].sh_offset > offset)
		{
			shdr[i].sh_offset += SIZE_INJECT;
			//shdr[i].sh_addr += SIZE_INJECT;
		}
	}
}

Elf64_Phdr	*get_next_pload(Elf64_Phdr *first, Elf64_Phdr *current, uint16_t phnum)
{
	int position;
	position = current - first;
	if (position < phnum && (current + 1)->p_type == PT_LOAD)
		return (current + 1);
	else
		return (0);
}

void	wwp_elf64(t_file *file)
{

	Elf64_Ehdr 	*ehdr;
	Elf64_Phdr 	*phdr;
	Elf64_Phdr 	*phdr_next;
	Elf64_Shdr 	*shdr;
	void				*split;
	int 				orign_entry;
	int 				jmp_addr;

	close(file[ORIGN].fd);
	file[ORIGN].fd = 0;

	ehdr = (Elf64_Ehdr*)(file[ORIGN].map.addr);
	phdr = get_xpload(file[ORIGN].map.addr);
	if (phdr)
	{
		phdr_next = get_next_pload(file[ORIGN].map.addr + ehdr->e_phoff,  phdr, ehdr->e_phnum);
		orign_entry = ehdr->e_entry;
		ehdr->e_entry = phdr->p_vaddr + phdr->p_filesz  + SIZE_WOODY;
		jmp_addr = orign_entry - (ehdr->e_entry + (OPSIZE + SIZE_JMP - SIZE_WOODY))  ;
		memmove(jump + 1, &jmp_addr, sizeof(int));
		split = file[ORIGN].map.addr + phdr->p_offset + phdr->p_filesz;

		//fix new values
		/*set_phdr_offset(file->map.addr + ehdr->e_phoff,
						phdr->p_offset + phdr->p_memsz,
						ehdr->e_phnum);
		set_shdr_offset(file->map.addr + ehdr->e_shoff,
						phdr->p_offset + phdr->p_memsz,
						ehdr->e_shnum);
		ehdr->e_shoff += SIZE_INJECT;
		phdr->p_memsz += SIZE_INJECT;
		phdr->p_filesz += SIZE_INJECT;*/
		//phdr->p_flags |= PF_W;
		//phdr->p_flags |= PF_X;
	}
	printf("g_garbage_info.map[PACKED]->addr:%p\n",g_garbage_info.map[PACKED].addr);

	create_binay_packed(&file[ORIGN], split, (void*)phdr_next);	
}

int		main(int ac, char **av)
{
	t_file file[NB_FILE];

	memset(&file[PACKED], 0, sizeof(t_file));
	memset(&file[ORIGN], 0, sizeof(t_file));
	memset(&g_garbage_info, 0, sizeof(t_garbage));
	set_garbage(ORIGN, &file[ORIGN]);
	set_garbage(PACKED, &file[PACKED]);
	printf("file[PACKED]:%p\n", &file[PACKED]);
	printf("file[ORIGN]:%p\n", &file[ORIGN]);

	/* Check input */
	if (ac != 2)
		exit_prog(1, "./wwwp elf_file\n");

	printf("file[ORIGN]:%p\n", &file[ORIGN]);
	init_binary(&file[ORIGN], av[1]);
	//set_garbage(&orign_file);
	wwp_elf64(file);
	printf("file[PACKED].addr:%p\n",g_garbage_info.map[PACKED].addr);

	exit_prog(0, 0);

	return (0);
}
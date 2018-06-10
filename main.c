#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>

struct key128_ctx {
        uint8_t key[11][16];
};

void expand_key128(struct key128_ctx *ctx, uint8_t *key);
void ft_encrypt(void *src, uint8_t *key); //ecrypt 128bits
void ft_decrypt(void *src, uint8_t *key); //decrypt 128bits

int 	open_file(void **ptr, size_t *ptr_size, char *filepath, int flag_open);


int main(int ac, char **av)
{
	unsigned char str[150] = "Romain CARETTE";

	uint8_t key[16] = {0x3c,0x4f,0xcf,0x09,0x88
						,0x15,0xf7,0xab,0xa6,0xd2,
						0xae,0x28,0x16,0x15,0x7e,0x2b};
	/*int len_data = strlen((char*)str);
	aes_encrypt(str,len_data, (uint8_t*)&key);
	write(1, str, len_data);
	aes_decrypt(str,len_data, (uint8_t*)&key);
	write(1, str, len_data);
	
	printf("FILE ENCRYPT\n");
	void *ptr;
	size_t size;
	open_file(&ptr, &size, "file_test.s", O_RDWR);
	aes_encrypt(ptr, size, (uint8_t*)&key);

	aes_decrypt(ptr, size, (uint8_t*)&key);
	write(1, ptr, size);
	munmap(ptr, size);*/
	
	/*
	 *	FONCTIONNE
	 */

	ft_encrypt(str, key);
	write(1, str, 16);
	write(1, "\n", 1);
	
	ft_decrypt(str, key);
	write(1, str, 16);
	write(1, "\n", 1);
}

/*void aes_encrypt(void* data, size_t len, uint8_t *key)
{
	int i= -1;
	printf("\n\e[91mAES ENCRYPT _start_\e[0m\n");
	size_t				cur;

	cur = 0;
	while (cur < len)
	{
		//printf("boucle:%d => cur:%zd, len:%zd, data+cur:%s\n", ++i, cur, len, data+cur);
		encrypt_128(data + cur, key);
		write(1, "\e[91m", strlen("\e[91m"));
		write(1,data+cur, 16);
		write(1, "\e[0m", strlen("\e[0m"));
		cur += 16;
	}
	printf("\n\e[91mAES ENCRYPT _end_\e[0m\n");
}

void aes_decrypt(void* data, size_t len, uint8_t *key)
{
	int i = -1;
	printf("\n\e[92mAES DECRYPT _start_\e[0m\n");
	size_t				cur;

	cur = 0;
	while (cur < len)
	{
		//printf("boucle:%d => cur:%zd, len:%zd, data+cur:%s\n", ++i, cur, len, data+cur);
		decrypt_128(data + cur, key);
		write(1, "\e[92m", strlen("\e[92m"));
		write(1,data+cur, 16);
		write(1, "\e[0m", strlen("\e[0m"));
		cur += 16;
	}
	printf("\n\e[92mAES DECRYPT _end_\e[0m\n");
}


int 	open_file(void **ptr, size_t *ptr_size, char *filepath, int flag_open)
{
	int				fd;
	struct stat		buff;

	//P_DEBUG_VARGS("filepath:%s\n", filepath);
	if ((fd = open(filepath, flag_open)) < 0)
	{
		//perror(ERROR_STR);
		return (1);	
	}
	if (fstat(fd, &buff) == -1)
	{
		//perror(ERROR_STR);
		return (2);
	}
	//check si dossier
	*ptr_size = buff.st_size;
	if ((*ptr = mmap(0, *ptr_size, PROT_WRITE | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
	{
		//perror(ERROR_STR);
		return (3);
	}
	//P_DEBUG("load file OK\n");
	return (0);
}*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#define BUF_LEN 4096

int main(int argc, char const *argv[])
{
	FILE *file;
	char buf[BUF_LEN];
	unsigned int idx;
	uint8_t 			c;

	if (argc != 2)
		return (printf("./print_opcode file.o"));
	file = fopen(argv[1], "r");
	if (file == NULL)
		return (printf("%s\n", strerror(errno)));
	if (fseek(file, 0, SEEK_SET))
		return (printf("%s\n", strerror(errno)));
	idx = 0;
	while (idx < BUF_LEN && fread(&c, sizeof(char), 1, file) == 1)
	{
		sprintf(buf + idx, "\\x%02x", c);
		idx += 4;
		if (idx <= 4096)
		{
			printf("%s",buf );
			idx ^= idx;
		}
	}
	printf("%s\n", buf);
	return 0;
}
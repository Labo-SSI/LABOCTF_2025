#include<stdio.h>
#include<stdlib.h>
#include<string.h>

const char password[] = "OjogEjwHChtdCgIIC1haNhkIOjoeWRstFA==\00";
const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void xor(char *user_input, int key) {
    for (int i = 0; i < strlen(user_input); i++) {
        user_input[i] = user_input[i] ^ key;
    }
}

size_t b64_encoded_size(size_t inlen)
{
	size_t ret;

	ret = inlen;
	if (inlen % 3 != 0)
		ret += 3 - (inlen % 3);
	ret /= 3;
	ret *= 4;

	return ret;
}

char *b64_encode(const unsigned char *in, size_t len)
{
	char   *out;
	size_t  elen;
	size_t  i;
	size_t  j;
	size_t  v;

	if (in == NULL || len == 0)
		return NULL;

	elen = b64_encoded_size(len);
	out  = malloc(elen+1);
	out[elen] = '\0';

	for (i=0, j=0; i<len; i+=3, j+=4) {
		v = in[i];
		v = i+1 < len ? v << 8 | in[i+1] : v << 8;
		v = i+2 < len ? v << 8 | in[i+2] : v << 8;

		out[j]   = b64chars[(v >> 18) & 0x3F];
		out[j+1] = b64chars[(v >> 12) & 0x3F];
		if (i+1 < len) {
			out[j+2] = b64chars[(v >> 6) & 0x3F];
		} else {
			out[j+2] = '=';
		}
		if (i+2 < len) {
			out[j+3] = b64chars[v & 0x3F];
		} else {
			out[j+3] = '=';
		}
	}

	return out;
}

int main() {
	printf("Allez, entre le mot de passe—oh, attends, laisse tomber. De toute façon, tu ne le devineras jamais.\n");
    char user_input[26];
	fgets(user_input, sizeof(user_input), stdin);

	int line_break_index = strcspn(user_input, "\n");
	user_input[line_break_index] = 0;

    xor(user_input, 0x69);
    char *encoded_user_input = b64_encode(user_input, strlen(user_input));

	if (strcmp(encoded_user_input, password) == 0) {
		printf("\nImpossible… Comment as-tu réussi à le craquer ?! Ce n'est pas possible !\nHmph… très bien, prends ton précieux flag et fiche le camp !\n");
	} else {
		printf("\nAhaha ! Tu pensais vraiment que ce serait aussi facile ? Pathétique !\n");
	}

	return 0;
}
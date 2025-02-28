#include<stdio.h>

int main() {
    char user_input[50];
    char file_content[50];

    FILE *fd;
    fd = fopen("flag.txt", "r");
    fgets(file_content, 49, fd);

    printf("Oh, tu te crois malin ? Vas-y envoie-moi un payload, ça ne marchera pas ! Mes défenses sont impénétrables.\n");
    fgets(user_input, 49, stdin);

    printf("Tu vois à quel point tes tentatives sont inutiles ?\n");
    printf(user_input);

    return 0;
}
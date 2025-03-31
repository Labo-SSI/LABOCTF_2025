#include<stdio.h>
#include<stdlib.h>
#include<string.h>

void win() {
    printf("LOGGED IN\n\nUser : Admin\n\nOptions :\n1 - shell\n2 - exit\n");
    char choice[3];
    fgets(choice, 2, stdin);

    if (strcmp(choice, "1") == 0) {
        printf("Quoi ?! Comment es-tu arrivé ici ?! Je savais que j’aurais dû supprimer tout ça… Peu importe, je ne te laisserai pas aller plus loin !\n");
        
        if (strlen(choice) == 0) {
            system("/bin/sh");
        }
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    
    char password[10];

    printf("Vas-y, tape ton précieux mot de passe... si tu l'oses ! Voyons voir si tu arrives à te connecter ahaha\n");
    fgets(password, 50, stdin);
    printf("Haha, tu as vraiment cru que quelque chose allait se passer ? Je t’ai dit que tu ne pouvais pas te connecter ! Continue d’essayer, c’est adorable...\n");

    return 0;
}
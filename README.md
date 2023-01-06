# Projet_Prog
PROG5 - Projet, année 2022-2023 Réalisation d’un éditeur de liens — Phase de Fusion

####### Utilisation #######

# Compilation # 

CFLAGS='' ./configure
make

# Utilisation du programme 

Cas de lecture d'un seul fichier : 
./main <-l> <option> <nom_fichier>
    Options :
        "-a" : Affiche toutes les parties ci-dessous
        "-h" : Affiche l’en-tete d’un fichier ELF (header)
        "-S" : Affiche la table des sectionsd’un fichier ELF (section header)
        "-s" : Affiche la table des symboles d’un fichier ELF (symbol table)
        "-r" : Afficher les tables de reimplantation d’un fichier ELF pour machine ARM (relocation section)
        "-x" : Affiche le contenu de l’une des sections d’un fichier ELF (section dump)
        NOTE : pour cette option il est necessaire d'ajouter un 4eme argument, le numero de la section que l'on souhaite afficher 
        profil : ./main <-l> <-x> <numero de la section a afficher> <nom_fichier>
        NOTE 2 : L'option "-a" affiche toutes les sections du fichier.

Cas de fusion de fichiers ELF : 
./main <-f> <nom_fichier_1> <nom_fichier_2> <nom_fichier_resultat>

# Programme de test
---Flèches ???? ---
--- Option debug ---
Description : 

Nous utilisons un test automatisé pour la lecture de fichier : 
    Nous vérifions les 5 étapes de la phase 1 en même temps, pour cela nous comparons les sorties de notre programme aux sorties 
    des commandes associées (voir section ATTENTION). 
    Pour chaque étape si les deux sorties sont les mêmes le test est réussi et l'étape est passée. 
    Affichage type : <Test_header : test5.o REUSSI.>, en vert. 

    Dans le cas où des différences dans les sorties sont trouvées : 
    une ligne en ROUGE est affichée, c'est la sortie de notre programme.
    En dessous de chaque ligne rouge,  La ligne attendu sera affiché en VERT. 
    Puis il est affiché le nombre d'erreurs trouvées dans cette partie.
    Affichage type : <Test_symb_tab : 2 erreurs trouvées dans test1.o, ECHEC>, en rouge.






./test.sh <dossier>
    On va tester tous les fichiers.o du dossier
./test.sh <fichier>
    On va tester le fichier.o

Utilisation du programmme de test  :

ATTENTION : Pour vérifier que notre programme fonctionne bien nous comparons nos sorties aux sorties de la commande 
readelf. Les sorties de notre programme sont en anglais ainsi, si l'on souhaite les comparer avec les sorties des commandes elles 
doivent êtres également en anglais et donc linux doit être configuré en anglais. 





#


# Autres  
Compilation d'un fichier en 32 bits big endian :
arm-none-eabi-gcc -mbig-endian -c <fichier>
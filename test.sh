#!/bin/bash
blanc="\e[0m"
rouge="\e[0;31m"
vert="\e[0;32m"
rougeB="\e[48;5;1m"
vertB="\e[48;5;2m"

#Compilation
gcc -g lecture.c -o lecture
clear

function header_test(){
  fichier=$1
  echo "Test du header de $(basename $fichier) :"
  errHeader=0

  sortieA=$(./lecture $fichier 0)

  #Test si le fichier est un fichier ELF
  if [[ $sortieA =~ "ERR_ELF_FILE" ]]
  then
    echo -e $rouge"ERR_ELF_FILE : Le fichier n'est pas un fichier ELF 32bits big endian."$blanc
    return
  fi

  sortieB=$(readelf -h $fichier)

  END=$(echo "$sortieA" | wc -l) 
  for ((i=1;i<=END;i++)); do
    
    ligneA=$(echo "$sortieA" | sed -n "$i p")
    ligneB=$(echo "$sortieB" | sed -n "$i p")

    if [[ $ligneA != $ligneB ]]
    then
      echo -e $rouge$ligneA$blanc "->" $vert$ligneB$blanc
      errHeader=$(expr $errHeader + 1)
    fi
  done

  if [[ $errHeader -eq 0 ]]
  then
    echo -e $vertB"Test_header : $(basename $fichier) REUSSI."$blanc $'\n'
  else
    echo -e $rougeB"Test_header : $errHeader erreurs trouvées dans $(basename $fichier), ECHEQUE"$blanc $'\n'
  fi
}


#Execution :
#./test.sh fichierELF_1 fichierELF_2 fichierELF_N

for fichier in $@
do

  #Test de recuperation du header
  header_test $fichier
  
done

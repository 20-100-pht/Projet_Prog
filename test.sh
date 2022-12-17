#!/bin/bash
blanc="\e[0m"
rouge="\e[0;31m"
vert="\e[0;32m"
rougeB="\e[48;5;1m"
vertB="\e[48;5;2m"

#Compilation
gcc -g lecture.c -o lecture
clear

function line_test(){
  fichier=$1
  read_type=$2
  test_num=$3
  err=0

  sortieA=$(./lecture $fichier $test_num)

  #Test si le fichier est un fichier ELF
  if [[ $sortieA =~ "ERR_ELF_FILE" ]] || ! [[ -f $fichier ]]
  then
    echo -e $rouge"ERR_ELF_FILE : Le fichier $fichier n'est pas un fichier ELF 32bits big endian."$blanc$'\n'
    rt=-1
    return
  fi

  sortieB=$(readelf $read_type $fichier)

  END=$(echo "$sortieA" | wc -l) 
  for ((i=1;i<=END;i++)); do
    
    ligneA=$(echo "$sortieA" | sed -n "$i p")
    ligneB=$(echo "$sortieB" | sed -n "$i p")

    if [[ "$ligneA" != "$ligneB" ]]
    then
      echo -e $rouge$ligneA$blanc "->" $vert$ligneB$blanc
      err=$(expr $err + 1)
    fi
  done

  rt=$err
}

function header_test(){
  fichier=$1
  echo "(Etape 1) : Test du header de $(basename $fichier) :"
  line_test $fichier $2 $3

  if [[ $rt -eq 0 ]]
  then
    echo -e $vertB"Test_header : $(basename $fichier) REUSSI."$blanc
  elif [[ $rt -ne -1 ]]
  then
    echo -e $rougeB"Test_header : $errHeader erreurs trouvées dans $(basename $fichier), ECHEQUE"$blanc
  fi

}

function section_header_test(){
  fichier=$1
  echo "(Etape 2) : Test du section header de $(basename $fichier) :"
  line_test $fichier $2 $3

  if [[ $rt -eq 0 ]]
  then
    echo -e $vertB"Test_section_header : $(basename $fichier) REUSSI."$blanc $'\n'
  elif [[ $rt -ne -1 ]]
  then
    echo -e $rougeB"Test_section_header : $errHeader erreurs trouvées dans $(basename $fichier), ECHEQUE"$blanc $'\n'
  fi
}

#Execution :
#./test.sh fichierELF_1 fichierELF_2 fichierELF_N nomDossierTest
#Exemple :
#./test.sh tests    file1.o
#          dossier  fichier
for fichier in $@
do

  if [[ -d $fichier ]]
  then
    for fich in $fichier/*
    do
      #Test de recuperation du header
      header_test $fich "-h" 0
      #Test de recuperation de la table des sections
      section_header_test $fich "-S" 1
    done
  else
    #Test de recuperation du header
    header_test $fichier "-h" 0
    #Test de recuperation de la table des sections
    section_header_test $fichier "-S" 1
  fi

done

#!/bin/bash

START=
END=

while getopts ":s:e:" OPTIONS
do
            case $OPTIONS in
            s)     START=$OPTARG;;
            e)     END=$OPTARG;;
            ?)     printf "Invalid option: -$OPTARG\n" $0
                          exit 2;;
           esac
done

START=${START:=NULL}
END=${END:=NULL}

green='\e[0;32m'
endgreen='\e[0m'

##################
#  ~~~ Menu ~~~  #
##################

if [ $START = NULL ] || [ $END = NULL ]; then

echo "--------------------------------------------------------------------"
echo "|                          XOR v1.0 ~ b33f                         |"
echo "|                    -Generate XOR encoder loop-                   |"
echo "--------------------------------------------------------------------"
echo "| USAGE: ./xor.sh -s [Address] -e [Address]                        |"
echo "|                                                                  |"
echo "| REQUIRED                                                         |"
echo "|         -s  Address where the encoder should start.              |"
echo "|         -e  Address where the encoder should end.                |"
echo "--------------------------------------------------------------------"

else

########################################
#  ~~~ Write addresses to xor.txt ~~~  #
########################################

echo "$START" > /tmp/tmp.txt
echo "$END" >> /tmp/tmp.txt

cat /tmp/tmp.txt |fold -w 2 >> /tmp/xor.txt
rm /tmp/tmp.txt

#############################################
#  ~~~ Assign every byte as a variable ~~~  #
#############################################

s=$(</tmp/xor.txt)
set -- $s

######################
#  ~~~ XOR-Keys ~~~  #
######################

RANDO='00,01,02,03,04,05,06,07,08,09,0A,0B,0C,0D,0E,0F,
10,11,12,13,14,15,16,17,18,19,1A,1B,1C,1D,1E,1F,
20,21,22,23,24,25,26,27,28,29,2A,2B,2C,2D,2E,2F,
30,31,32,33,34,35,36,37,38,39,3A,3B,3C,3D,3E,3F,
40,41,42,43,44,45,46,47,48,49,4A,4B,4C,4D,4E,4F,
50,51,52,53,54,55,56,57,58,59,5A,5B,5C,5D,5E,5F,
60,61,62,63,64,65,66,67,68,69,6A,6B,6C,6D,6E,6F,
70,71,72,73,74,75,76,77,78,79,7A,7B,7C,7D,7E,7F,
80,81,82,83,84,85,86,87,88,89,8A,8B,8C,8D,8E,8F,
90,91,92,93,94,95,96,97,98,99,9A,9B,9C,9D,9E,9F'

N=$(shuf -i 1-160 -n 1)

KEY=$(echo $RANDO |tr -d " " |cut -d"," -f $N)

##############################
#  ~~~ Generate Encoder ~~~  #
##############################

echo    "[>] ASM Instructions:"
echo    ""
echo -e "MOV EAX,${green}$START${endgreen}"
echo -e "XOR BYTE PTR DS:[EAX],${green}$KEY${endgreen}"
echo    "INC EAX"
echo -e "CMP EAX,${green}$END${endgreen}"
echo    "db 07eh,0f5h"
echo    ""
echo    "[>] Binary Dump:"
echo    ""
echo -e "B8"${green}$4$3$2$1${endgreen}"8030"${green}$KEY${endgreen}"403D"${green}$8$7$6$5${endgreen}"7EF5"

rm /tmp/xor.txt

fi
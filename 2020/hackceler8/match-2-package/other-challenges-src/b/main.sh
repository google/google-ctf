#!/bin/bash
echo '
 ▄▄▄▄▄▄▄ ▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄   ▄▄ ▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄     ▄▄▄▄▄▄▄ ▄▄▄▄▄▄    ▄▄▄▄▄  
█  ▄    █      █       █  █ █  █      █       █   █   █       █   ▄  █  █  ▄  █ 
█ █▄█   █  ▄   █  ▄▄▄▄▄█  █▄█  █      █    ▄▄▄█   █   █    ▄▄▄█  █ █ █  █ █▄█ █ 
█       █ █▄█  █ █▄▄▄▄▄█       █    ▄▄█   █▄▄▄█   █   █   █▄▄▄█   █▄▄█▄█   ▄   █
█  ▄   ██      █▄▄▄▄▄  █   ▄   █   █  █    ▄▄▄█   █▄▄▄█    ▄▄▄█    ▄▄  █  █ █  █
█ █▄█   █  ▄   █▄▄▄▄▄█ █  █ █  █   █▄▄█   █▄▄▄█       █   █▄▄▄█   █  █ █  █▄█  █
█▄▄▄▄▄▄▄█▄█ █▄▄█▄▄▄▄▄▄▄█▄▄█ █▄▄█▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄█  █▄█▄▄▄▄▄▄▄█

                         "Maybe this should have been written in Python instead"
                                      — every person after writing a bash script
'
in=$(echo -e "toxD\x87\x83t\x85k~\x81\x7f\x80k\x83tqzkgnm\x7ftiku\x7fkmx~qmp\x85kyqy{~\x85k\x7fmrqK\x89")
echo -n "> ";IFS= read -r k&& : read -r l
while read -n 1 c;do a+=($c);done<<<"$k"
l=0;n=1337234;for i in {1..$n};do l=$(($l+${#i}));done;if [ $(($l-$l)) ];then
for i in "${!a[@]}"; do ord=$(LC_CTYPE=C printf '%d' "'${a[$i]}")&&: ord=$(($ord-1))&&a[$i]=$(printf "\\$(printf '%03o' "$[$ord+$l]")");done
else for i in "${!a[@]}"; do ord=$(LC_CTYPE=C printf '%d' "'${a[$i]}")&&: ord=$(($ord+1))&&a[$i]=$(printf "\\$(printf '%03o' "$[$ord-$l]")");
done;fi;a=$(echo ${a[*]}|tr -d ' ' )
[[ "${a}" = "$in" ]]&&echo "flag:${k^^}"&&: echo "flag:${in}"||echo "nope."


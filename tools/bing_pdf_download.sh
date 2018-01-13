j=0;for ((i=1;i<281000000/10;i++));do let j=j+10;echo '===Page '`expr $(($j/10))`'==='; curl -s https://www.bing.com/search\?q\=filetype%3apdf\&first\=$j\&FORM\=PERE |awk -F '"' '{for(i=1;i<NF;i++){if(match($i,/\.pdf$/)){print $i}}}'|xargs -I {} wget {} -P ./bing_download ;done
for f in ./bing_download/*;do file $f|grep -v PDF|awk -F ':' '{print $1}'|xargs rm;done

for ((i=0;i<10000;i++));do curl -s "http://www.baidu.com/s?wd=filetype%3Apdf&pn="$i"0" |grep -o "{\"title\":.*\"url\":\"http://www.baidu.com/link?url.*\"}'"|awk -F '"' '{print $8}'|xargs -I {} wget {} -P ./baidu_download;done
for f in ./baidu_download/*;do file $f|grep -v PDF|awk -F ':' '{print $1}'|xargs rm;done

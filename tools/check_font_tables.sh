for file in ~/Downloads/ttf/*;do echo "【文件】"$file;ftxdumperfuser -t $1 $file 2>/dev/null;done
for file in /Users/jane/riusksk/fuzzdata/samples/ttf/*;do echo "【文件】"$file;ftxdumperfuser -t $1 $file 2>/dev/null;done
for file in /Library/Fonts/*;do echo "【文件】"$file;ftxdumperfuser -t $1 $file 2>/dev/null;done
for file in /System/Library/Fonts/*;do echo "【文件】"$file;ftxdumperfuser -t $1 $file 2>/dev/null;done
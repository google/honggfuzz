for file in ~/Downloads/ttf/*;do echo "【文件】"$file;ftxdumperfuser -t $1 $file 2>/dev/null;done
for file in /Users/jane/riusksk/fuzzdata/samples/ttf/*;do echo "【文件】"$file;ftxdumperfuser -t $1 $file 2>/dev/null;done
for file in /Library/Fonts/*;do echo "【文件】"$file;ftxdumperfuser -t $1 $file 2>/dev/null;done
for file in /System/Library/Fonts/*;do echo "【文件】"$file;ftxdumperfuser -t $1 $file 2>/dev/null;done
for file in /Users/jane/Documents/font/字体素材-《广告海报必备中英日文字体集》/字体/*;do echo "【文件】"$file;ftxdumperfuser -t $1 $file 2>/dev/null;done

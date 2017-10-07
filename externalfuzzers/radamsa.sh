#!/bin/sh
#必须加以上标记，否则execv函数调用会出错

echo "running $@"
touch ./tmp
radamsa $1 > ./tmp
mv ./tmp $1

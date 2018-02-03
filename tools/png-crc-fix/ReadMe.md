###说明
由于png存在CRC校验，变异后的文件一般都无法通过校验，因此需要在变异后作CRC修复方可得到正常解析，可以使用以下命令来完成。
###Usage：
riufuzz -V --pprocess_cmd=./png-crc-fix -r 0.0001 -t3 -n3 -f png_sample -e png -- png_read @@




#!/usr/bin/bash
xxd ../serverside >serverside.txt
xxd ../clientside >clientside.txt
md5sum ../*side
wc -l ../*side.txt
diff ../clientside.txt ../serverside.txt >diff.txt
wc -l diff.txt
case $1 in
clean)
    rm ../clientside ../clientside.txt ../serverside ../serverside.txt diff.txt
    ;;
*) ;;
esac

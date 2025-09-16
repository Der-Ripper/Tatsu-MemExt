# Tatsu-MemExt

 powershell -ExecutionPolicy Bypass -File .\mem_receiver.ps1 -Port 31337 -OutputFile C:\memory.dmp
ncat -l -p 31337 > memory.dmp
insmod mem_dumper.ko dump_path=tcp:192.168.56.1:31337
dmesg -w


sudo insmod lime-$(uname -r).ko "path=tcp:192.168.56.1:31337 format=lime"
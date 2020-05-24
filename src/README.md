After running the VM, run to the **time_p4/src** directory. 

```
cd time_p4/src
make
```

from mininet prompt

```
mininet> xterm h1 h2
```

in h1 and h2 terminal, you can put new LVT values

```
./gvt_control.py <dst_ip> <LVT>
```
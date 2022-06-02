# (WIP)

ICMP を弾くやつを Interface に適応

```shell
make build

cd bpf
clang -c -target bpf ./xdp_prog_kern.c
cd ..

go generate
go build .

sudo ip netns exec node0 ./go-xdp -I veth1
```
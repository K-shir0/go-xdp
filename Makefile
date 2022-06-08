.PHONY: build
build:
	ip netns add node0
	ip link add veth0 type veth peer veth1
	ip link set veth1 netns node0
	ip addr add 192.168.1.3/24 dev veth0
	ip netns exec node0 ip addr add 192.168.1.2/24 dev veth1
	ip link set up dev veth0
	ip netns exec node0 ip link set up dev veth1
	ip netns exec node0 ip link set up dev lo
clean:
	ip netns del node0

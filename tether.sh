ifconfig enp0s26u1u2c4i2 up
route del default
route add default gw 172.20.10.1
#route add -net 10.0.0.0 netmask 255.0.0.0 gw 10.141.100.254

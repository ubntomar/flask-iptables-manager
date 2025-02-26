sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null



sudo iptables -L -n -v

sudo iptables -L -n -v -t nat

sudo iptables -F
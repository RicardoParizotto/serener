## Compiling and Running Serene on SDE 9.9.1

Follow the instructions compile the code and load the program onto the switch. This will open a command line for you.

>> ./run_switchd.sh -p serene

Before running the switch, make sure to load the drivers and configure the environment.

### Port Configuration

Configure the ports. As a precaution, configure all ports instead of configuring just one. For example, instead of port-add 1/0 40G None, run the command for all ports (-/-):

port-add -/- 40G NONE
port-enb -/-

### Serene Rules Configuration

Configure the rules for Serene (attached "config_serene"). There's a multicast there that I used to notify the workers when they can proceed. Currently, there is no waiting list on the switch. I used the command line to access the bfrt_python, which is like the switch's CLI.

### Network Interface Configuration

Set the workers nterfaces to promiscuous mode. (This is a workaround that needs to be done on both servers).

>> sudo ifconfig enp132s0f0np0 promisc

After that, you can access the workers and run Serene. Ps: you need to explicitly specify the interface to be used.

sudo python3 client/worker.py 0 --model simple --world_size 2 --out-dir example1 --veth=enp132s0f0np0 straggler --pattern slow_worker --probability 0.15 --min-slowdown 0.5 --max-slowdown 2.0

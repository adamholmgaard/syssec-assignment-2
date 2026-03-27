# SYSSEC assignment 2

Solutions for tasks 2 and 3 from Assignment 2, in the Systems Security course.

## Setup

Make sure Rust v1.94 and all dependencies are installed.
To make sure of this, run

```shell
cargo build
```

Depending on your OS, you may need additional installations.

## Linux

We have used VirtualBox in combination with a host machine (either windows or mac) as the malicious node, we provide the run commands for linux

### Task 2

For task 2 there are two different attacks hence two run commands. The program needs special permissions so we run the code with:

```shell
sudo ./target/debug/syssec-assignment-2
```

The code takes as input a source and destination ip aswell as the attack type.

- RST attack

```shell
sudo ./target/debug/syssec-assignment-2 'source_ip' 'dest_ip' rst
```

- DupAck attack

```shell
sudo ./target/debug/syssec-assignment-2 'source_ip' 'dest_ip' dupack
```

### Task 3

For task 3 there is only a single hijacking attack. We use the simple website as target in this task, otherwise the setup is the same

- Hijack attack

```shell
sudo ./target/debug/syssec-assignment-2 'source_ip' 'dest_ip' hijack
```


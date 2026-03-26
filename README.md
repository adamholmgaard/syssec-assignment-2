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

### Task 2

Since there are two attacks for task 2 there are two different run commands. Furthermore since the program needs special permissions we run the code with:

sudo ./target/debug/syssec-assignment-2

Then since the code takes the attack and source and destination ips as input these should be included.

- RST attack:

sudo ./target/debug/syssec-assignment-2 'source_ip' 'dest_ip' rst

- DupAck attack:

sudo ./target/debug/syssec-assignment-2 'source_ip' 'dest_ip' dupack

### Task 3

- Hijack attack:

sudo ./target/debug/syssec-assignment-2 'source_ip' 'dest_ip' hijack



# Rust SGX SDK Samples

## Build and Run codes
Run a docker container based on the `baiduxlab/sgx-rust` image.

```bash
% docker compose up -d
[+] Running 2/2
 ⠿ Network sgx-sdk_default  Created    3.9s
 ⠿ Container sgx-sdk_sgx_1  Started
% docker compose exec sgx bash
root@4bdb41328613:~# cd sgx/examples/greeter
root@4bdb41328613:~/sgx/examples/greeter# export SGX_MODE=SW # set flag of the simulation mode
root@4bdb41328613:~/sgx/examples/greeter# make
```

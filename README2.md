
# Recipe:
### Tested configuration

Host hardware
`
Intel Core i9-10900K CPU
    8 cores (3.7 GHz)
    SGX v1
Intel XL710 40GbE controller
`
Host software (check default.nix for the dependencies)

`NixOS (kernel v5.11.21)`

Interconnect

`40GbE`


### How to build and run?

We used an internal development version of SCONE, we have not tested it with the publicly available version.

Build DPDK and eRPC. In eRPC/build directory;
- `make -f Makefile_dpdk_scone` -- that builds the (patched for SCONE) DPDK library inside the dpdk_scone/x86..
- `make -f Makefile_dpdk` (native runs)

- `cmake .. -DPERF=OFF -DTRANSPORT=dpdk -DSCONE=true/false` -- to make the Makefile for eRPC-lib

- and then just `make` which builds the library (.a).

For each of the protocols you can `make -D..` the binary and set the appropriate flags. For example: `-DSCONE_ALLOC` to enable the custom host-memory allocator in SCONE, `-DGMAC/ENCRYPTION` for enabling the Authenticated messages (and encrypted version respectively). Other flags includes enabling the KV store (KV), CityHash, SHA256, etc.

To run the code in SCONE:
`sudo -E Hugepagesize=2097152 LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu/:/usr/lib/gcc/x86_64-linux-gnu/7/ SCONE_VERSION=1 SCONE_LOG=7 SCONE_NO_FS_SHIELD=1 SCONE_NO_MMAP_ACCESS=1 SCONE_HEAP=3584M SCONE_LD_DEBUG=1 /opt/scone/lib/ld-scone-x86_64.so.1 <program_name>`

Important note: reserve and configure "enough" hugepages-memory as eRPC and allocator both use it.


### Code structure
- One folder for each of the implemented protocols (AllConcur, Raft, CR). We reused the core implementation of ABD from this project (https://github.com/mbailleu/avocado).
- The direct I/O networking is on eRPC with dpdk and dpdk_scone as backends.
- The allocator is in  host_allocator directory and the KV store is in concurrent_skiplist folder
- The encryption_library and enc_lib_test contain the Openssl-based implementations for the authentication layer and the ratelim.h contains the requests' rate limiter.
- SCONE_instructions.md contains SCONE dependencies.
- Lastly, for each protocol there is a config.h (for each change a re-compilation is required) for the configurations like: IPs, workloadtype, msg/value size, threads, etc.

# recipe-protocols



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


### System setup 

We pin port-1 to DPDK-driver (`igb_uio`) in all servers we want to use. Note, it should only be port-1 in this cluster as we have the NFS mounted on port-0!

The script can be found in the DPDK codebase which you can get online as explain next.

```sh
sudo python dpdk-devbind.py --bind=igb_uio 0000:01:00.1/enp1s0f1
```

You can find the correct interfaces to bind with

```sh
sudo python dpdk-devbind.py --status 
```

### How to build and run?

We used an internal development version of SCONE, we have not tested it with the publicly available version.

Build DPDK and eRPC. In eRPC/build directory;
- `make -f Makefile_dpdk_scone` -- that builds the (patched for SCONE) DPDK library inside the dpdk_scone/x86..
- `make -f Makefile_dpdk` (native runs)

- `cmake .. -DPERF=OFF -DTRANSPORT=dpdk -DSCONE=true/false` -- to make the Makefile for eRPC-lib

- and then just `make` which builds the library (.a).

For each of the protocols you can build the binary with `make -D<flags>` and set the appropriate flags. For example: `-DSCONE_ALLOC` to enable the custom host-memory allocator in SCONE, `-DGMAC/ENCRYPTION` for enabling the Authenticated messages (and encrypted version respectively). Other flags includes enabling the KV store (KV), CityHash, SHA256, etc.

The binaries would be build in the current folder.

Note: In our systems, we could only properly link the applications with the following linking flags that need to be added to any Makefile

```sh
-Wl,--whole-archive -ldpdk -Wl,--no-whole-archive -lrte_ethdev -Wl,-lrte_port
```

To run the code in SCONE:
`sudo -E Hugepagesize=2097152 LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu/:/usr/lib/gcc/x86_64-linux-gnu/7/ SCONE_VERSION=1 SCONE_LOG=7 SCONE_NO_FS_SHIELD=1 SCONE_NO_MMAP_ACCESS=1 SCONE_HEAP=3584M SCONE_LD_DEBUG=1 /opt/scone/lib/ld-scone-x86_64.so.1 <program_name> <program_args>`

For each protocol you need to configure the correct IPs on the including `common_conf.h` file.

Important note: reserve and configure "enough" hugepages-memory as eRPC and allocator both use it.


### Code structure

Please note that our codebase is a PoW of our system. It is not designed to be used in production and heavy refactoring might be of great use before using it.
- One folder for each of the implemented protocols (AllConcur, Raft, CR). We reused the core implementation of ABD from this project (https://github.com/mbailleu/avocado).
- The direct I/O networking is on `eRPC` with `dpdk` and `dpdk_scone` as backends.
- The allocator is in  `host_allocator` directory and the KV store is in `concurrent_skiplist` folder
- The e`ncryption_library` and `enc_lib_test` contain the `OpenSSL`-based implementations for the authentication layer and the `ratelim.h` contains the requests' rate limiter.
- `setup_instructions.md` contains SCONE dependencies.
- Lastly, for each protocol there is a configuration file (`common_conf.h`/`config.h`) (for each change a re-compilation is required) for the configurations like: IPs, workloadtype, msg/value size, threads, etc.

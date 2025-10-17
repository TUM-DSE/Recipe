# Dependencies (build from source in SCONE)

- Build from source the following packages
```sh
cityhash fmt openssl double-conversion folly
```

Note: some folly versions might require the patch in `SCONE_deps`. 
In case the installation fails please execute the next step and then 
re-try.

- Install system wide requirements:
```sh
sudo apt-get install libevent-dev libnuma-dev libgflags-dev libgoogle-glog-dev libboost-dev
```

- Copy the libraries in the correct path accesisble by SCONE runtime.
```sh
sudo cp /usr/local/lib/lib* /usr/lib/x86_64-linux-gnu/
```

We provide the script `setup.sh` for rebuilding and setting up the environment upon restart of a system. Source code of the required packages should have been installed manually.

## Profiling in NixOS

```sh
/run/current-system/sw/bin/profile
```

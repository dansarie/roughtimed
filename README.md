# roughtimed
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Dependencies

* [CMake](https://github.com/Kitware/CMake) (for build)
* [OpenSSL](https://github.com/openssl/openssl)

## Build

```
sudo apt-get install cmake libssl-dev
mkdir build
cd build
cmake ..
make
```

## Configure

* Run `./roughtime-keytool key` to generate a new long-term keypair.
* Run `./roughtime-keytool dele` to generate a certificate signed by the long-term private key.
* Update the template roughtimed.conf to with the cert packet and private key returned by `./roughtime-keytool dele`.
* Set the stats, leap, threads, and max_path_len variables in roughtimed.conf as suitable.
* Ensure roughtimed.conf is not world-readable or world-writable: `chmod 600 roughtimed.conf`.

## Run

```
./roughtimed -f roughtimed.conf
```

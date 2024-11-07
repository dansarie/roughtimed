# Roughtimed

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Roughtimed is a Roughtime server written in C. Roughtime is a protocol for rough time
synchronization and timestamping. Roughtime responses are signed and the signatures can be validated
against long-term keys. A Merkle tree structure in responses makes it possible to verify a large
number of responses with a single signature, reducing computational load on the server.
Additionally, chaining of responses from different servers enables clients to create cryptographic
proofs of malfeasance by servers.

Currently, Roughtimed implements the version of the Roughtime protocol described by
[draft-ietf-ntp-roughtime-11](https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-11).

## Dependencies

* [CMake](https://github.com/Kitware/CMake) (for build)
* [OpenSSL](https://github.com/openssl/openssl) (for SHA-512 and Ed25519)

## Build

```
sudo apt-get install cmake libssl-dev
mkdir build
cd build
cmake ..
make
```

## Configure

### Step-by-step guide

* Run `./roughtime-keytool key` to generate a new long-term keypair.
* Run `./roughtime-keytool dele` to generate a certificate signed by the long-term private key.
* Update the template roughtimed.conf with the public key returned by `./roughtime-keytool key`.
* Update the template roughtimed.conf with the cert packet and private key returned by `./roughtime-keytool dele`.
* Set the stats, threads, and max_path_len variables in roughtimed.conf as suitable.
* Ensure roughtimed.conf is not world-readable or world-writable: `chmod 600 roughtimed.conf`.

### roughtimed.conf

The file `roughtimed.conf` contains the configuration of the Roughtimed server. Its default location
is `/etc/roughtimed.conf`, but an alternative path can be specified using the command line flag
`-f`.

Since the configuration file contains sensitive values, it must not be readable or writable to
unauthorized users. To protect against this, Roughtimed will quit and display an error if the
configuration file is world-readable or -writable.

The following table summarizes the configuration options in the configuration file.

| Statement    | Description |
| ------------ | ----------- |
| cert         | A delegate certificate packet in base64 format. It can be generated with the `dele` command to `roughtime-keytool`. |
| publ         | The server's long-term public key in base64 format. |
| priv         | The private key for the certificate packet in cert. It is returned by the `dele` command to `roughtime-keytool`. |
| stats        | Optional parameter specifying the output path for a statistics log file. |
| thread       | Optional parameter specifying the number of worker threads. |
| max_path_len | Optional parameter specifying the maximum path length in the Merkle tree. The maximum number of responses signed at once will be 2^x, where x is the maximum path length. |

## Run

```
./roughtimed -f roughtimed.conf
```
### Command line options

| Option | Argument  | Description |
| ------ | --------- | ----------- |
| -f     | file name | Configuration file path. |
| -s     | (none)    | Don't wait for NTP synchronization when starting. |
| -v     | (none)    | Increased verbosity. |

## Statistics

If the stats statement is present in the configuration file, a line containing basic statistics will
be appended to the indicated file every minute. The six columns contain the following information,
in order: date and time, number of received valid queries, number of received invalid queries,
number of queries ignored due to query buffer overflow, maximum time error in microseconds, and
estimated time error in microseconds.

## License and Copyright

Copyright (C) 2019-2024 Marcus Dansarie

This program is free software: you can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
[the GNU General Public License](LICENSE) for more details.

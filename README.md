This code uses [libsodium](https://github.com/jedisct1/libsodium) for encryption and hashing. To install libsodium, check out their [documentation](https://download.libsodium.org/doc/).

Alternatively, the current makefile is configured to install libsodium in a unix-like environment (more specifically, a c9 instance). Try

`make libsodium_install`

or copy and paste the steps from the makefile.

To run the program, type

`make all`

after installing libsodium.
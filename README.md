# Gee-Mail
This program is a single-machine "messaging" platform that uses encryption to safely store user passwords and messages in a database file. It's mostly just an exercise in safe database interaction.

This code uses [libsodium](https://github.com/jedisct1/libsodium) for encryption and hashing. To install libsodium, check out their [documentation](https://download.libsodium.org/doc/).

Alternatively, the current makefile is configured to install libsodium in a unix-like environment (more specifically, a c9 instance). Try

`make libsodium_install`

or copy and paste the steps from the makefile.

To run the program, try

`make all`

after installing libsodium. Once the program is running, type H for a list of commands.
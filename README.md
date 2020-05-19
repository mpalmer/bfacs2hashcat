# bfacs2hashcat

This is a simple tool designed to extract the necessary information from a
Blowfish Advanced CS ("BFACS") encrypted archive to allow the passphrase to be
cracked using the [hashcat](https://hashcat.net) BFACS module (`-m 24300`).


# Building

Compile it using your favourite C compiler.  For example, using GCC:

    gcc -Wall bfacs2hashcat.c -o bfacs2hashcat


# Usage

Point `bfacs2hashcat` at any `.bfa` file, and it'll print the corresponding
hash line if it can parse the file.  Otherwise it'll print an error.


# Licence

Unless otherwise stated, everything in this repo is covered by the following
copyright notice:

    Copyright (C) 2020  Matt Palmer <matt@hezmatt.org>

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License version 3, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

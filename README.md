# BlueSSLService

## Overview
SSL Add-on framework for [BlueSocket](https://github.com/IBM-Swift/BlueSocket.git) in Swift using the Swift Package Manager. Works on OS X and Linux.

## Contents

* SSLService: Adds SSL support to **BlueSocket**. Pure Swift. 

## Prerequisites

### Swift
* Swift Open Source `swift-DEVELOPMENT-SNAPSHOT-2016-05-03-a` toolchain (**Minimum REQUIRED for latest release**)
* Swift Open Source `swift-DEVELOPMENT-SNAPSHOT-2016-05-09-a` toolchain (**Recommended**)

### OS X

* OS X 10.11.0 (*El Capitan*) or higher
* Xcode Version 7.3.1 (7D1012) or higher using the one of the above toolchains (*Recommended*)
* OpenSSL: openssl-1.0.2g.  Available via `brew install openssl`.

### Linux

* Ubuntu 15.10 (or 14.04 but only tested on 15.10)
* One of the Swift Open Source toolchains listed above

## Build

To build SSLService from the command line on OS X:

```
% cd <path-to-clone>
% swift build -Xcc -I/usr/local/opt/openssl/include
```
To build SSLService from the command line on Linux:

```
% cd <path-to-clone>
% swift build
```

## Using BlueSSLService

### Before starting

The first you need to do is import the Socket framework.  This is done by the following:
```
import Socket
import SSLService
```

### Creating the Configuration

TBD

### Creating and using the SSLService

TBD

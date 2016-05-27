# BlueSSLService

## Overview
SSL Add-on framework for [BlueSocket](https://github.com/IBM-Swift/BlueSocket.git) in Swift using the Swift Package Manager. Works on OS X and Linux.

## Contents

* SSLService: Adds SSL support to **BlueSocket**. Pure Swift. 

## Prerequisites

### Swift
* Swift Open Source `swift-DEVELOPMENT-SNAPSHOT-2016-05-09-a` toolchain

### OS X

* OS X 10.11.0 (*El Capitan*) or higher
* Xcode Version 7.3.1 (7D1012) or higher the above toolchain (*Recommended*)
* OpenSSL: openssl-1.0.2g.  Available via `brew install openssl`.

### Linux

* Ubuntu 15.10 (or 14.04 but only tested on 15.10)
* The Swift Open Source toolchain listed above

## Build

To build SSLService from the command line on OS X (assuming OpenSSL installed using `brew`):

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

**BlueSSLService** provides two ways to create a `Configuration`.  These are:
- `init(caCertificateFile: String, certificateFilePath: String, keyFilePath: String? = nil, chainFilePath: String? = nil)` - This API allows you to create a configuration using a self contained Certificate Authority file. This file **must** reside in the same directory as the application. The second parameter is the path to the certificate to be used by application to establish the connection.  The third parameter is the path to the `Private Key` file used by application.  If nil, the certificate file path will be used. The fourth parameter is the path to the certificate chain if applicable.
- `init(certificateDirPath: String, certificateFilePath: String, keyFilePath: String? = nil, chainFilePath: String? = nil)` - This API allow you to create a configuration using a directory of Certificate Authority files. You **must** also hash the CA certificates in this directory using the Certificate Tool.  The remaining parameters are identical to the previous API.

#### Example

The following illustrates creating a configuration using the second form of the API above using certificate file as the key file and not supplying a certificate chain file:
```swift
import SSLService

...

let caDirPath = "/opt/myApp/config/myCertificates"
let myCertPath = "/opt/myApp/config/myCertificate.pem"

let myConfig = SSLService.Configuration(certificateDirPath: caDirPath, certificateFilePath: myCertPath)

```

### Creating and using the SSLService

The following API is used to create the `SSLService`:
- `init?(usingConfiguration config: Configuration) throws` - This will create an instance of the `SSLService` using a previously created `Configuration`.

Once the `SSLService` is created is can applied to a previously created `Socket` instance that's just been created. The following code snippet illustrates how to do this.  *Note: Exception handling omitted for brevity.*

```swift

import Socket
import SSLService

...

// Create the configuration...
let caDirPath = "/opt/myApp/config/myCertificates"
let myCertPath = "/opt/myApp/config/myCertificate.pem"

let myConfig = SSLService.Configuration(certificateDirPath: caDirPath, certificateFilePath: myCertPath)

// Create the socket...
var socket = try Socket.create()
guard let socket = socket else {
  fatalError("Could not create socket.")
}

// Create and attach the SSLService to the socket...
//  - Note: if you're going to be using the same configuration
//          over and over, it'd be better to create it in the
//          beginning as `let` constant.
socket.delegate = try SSLService(usingConfiguration: myConfig)

// Start listening...
try socket.listen(on: 1337)

```

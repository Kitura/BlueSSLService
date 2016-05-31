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
* OpenSSL: openssl-1.0.2g or higher.  Available via `brew install openssl`.

### Linux

* Ubuntu 15.10 (or 14.04 but only tested on 15.10)
* The Swift Open Source toolchain listed above
* OpenSSL is provided by the distribution

### Package Dependencies

* BlueSocket v0.15.6 or higher
* OpenSSL-OSX v0.2.4 or higher for OS X
* OpenSSL v0.2.0 or higher for Linux

*Note:* See `Package.swift` for details.

## Build

To build `SSLService` from the command line on OS X (assuming OpenSSL installed using `brew`):

```
% cd <path-to-clone>
% swift build -Xcc -I/usr/local/opt/openssl/include
```
To build `SSLService` from the command line on Linux:

```
% cd <path-to-clone>
% swift build
```

## Using BlueSSLService

### Before starting

The first you need to do is import both the `Socket` and `SSLService` frameworks.  This is done by the following:
```swift
import Socket
import SSLService
```

### Creating the Configuration

Both clients and server require at a minimum the following configuration items:
* CA Certficate (either `caCertificateFile` or `caCertificateDirPath`)
* Application certificate (`certificateFilePath`)
* Private Key file (`keyFilePath`)

**or**

* Certificate Chain File (`chainFilePath`)

**or,** if using `self-signed` certificates:

* Application certificate (`certificateFilePath`)
* Private Key file (`keyFilePath`)

**BlueSSLService** provides three ways to create a `Configuration`.  These are:
- `init(withCACertificate caCertificateFile: String?, usingCertificateFile certificateFilePath: String?, withKeyFile keyFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true)` - This API allows you to create a configuration using a self contained `Certificate Authority (CA)` file. This file **must** reside in the same directory as the application. The second parameter is the path to the `Certificate` file to be used by application to establish the connection.  The next parameter is the path to the `Private Key` file used by application corresponding to the `Public Key` in the `Certificate`. If you're using `self-signed certificates`, set the last parameter to true.
- `init(withCACertificateDirectory caCertificateDirPath: String?, usingCertificateFile certificateFilePath: String?, withKeyFile keyFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true)` - This API allows you to create a configuration using a directory of `Certificate Authority (CA)` files. These `CA` certificates **must** be hashed using the `Certificate Tool` provided by `OpenSSL`. The following parameters are identical to the previous API.
- `init(withChainFilePath chainFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true)` - This API allow you to create a configuration using single `Certificate Chain File` (see note 2 below). Set the last parameter to true if the certificates are `self-signed`, otherwise set it to false.

*Note 1:* All `Certificate` and `Private Key` files must be `PEM` format.

*Note 2:* If using a certificate chain file, the certificates must be in `PEM` format and must be sorted starting with the subject's certificate (actual client or server certificate), followed by intermediate `CA` certificates if applicable, and ending at the highest level (root) `CA`.

*Note 3:* For the first two versions of the API, if your `Private key` is included in your certificate file, you can omit this parameter and the API will use the same file name as specified for the certificate file.

#### Example

The following illustrates creating a configuration using the second form of the API above using a self-signef certificate file as the key file and not supplying a certificate chain file:
```swift
import SSLService

...

let myCertPath = "/opt/myApp/config/myCertificate.pem"
let myKeyPath = "/opt/myApp/config/myKeyFile.pem"

let myConfig = SSLService.Configuration(withCACertificateDirectory: nil, usingCertificateFile: myCertPath, withKeyFile: myKeyFile)

...

```
*Note:* This example takes advantage of the `default` parameters available on the `SSLService.Configuration.init` function.

### Creating and using the SSLService

The following API is used to create the `SSLService`:
- `init?(usingConfiguration config: Configuration) throws` - This will create an instance of the `SSLService` using a previously created `Configuration`.

Once the `SSLService` is created, it can applied to a previously created `Socket` instance that's just been created. This needs to be done **before** using the `Socket`. The following code snippet illustrates how to do this.  *Note: Exception handling omitted for brevity.*

```swift

import Socket
import SSLService

...

// Create the configuration...
let myCertPath = "/opt/myApp/config/myCertificate.pem"
let myKeyPath = "/opt/myApp/config/myKeyFile.pem"

let myConfig = SSLService.Configuration(withCACertificateDirectory: nil, usingCertificateFile: myCertPath, withKeyFile: myKeyFile)

// Create the socket...
var socket = try Socket.create()
guard let socket = socket else {
  fatalError("Could not create socket.")
}

// Create and attach the SSLService to the socket...
//  - Note: if you're going to be using the same 
//          configuration over and over, it'd be 
//          better to create it in the beginning 
//          as `let` constant.
socket.delegate = try SSLService(usingConfiguration: myConfig)

// Start listening...
try socket.listen(on: 1337)

```
The example above creates a `SSL server` socket. Replacing the `socket.listen` function with a `socket.connect` would result in an `SSL client` being created as illustrated below:
```
// Connect to the server...
try socket.connect(to: "someplace.org", port: 1337)
```
`SSLService` handles all the negotiation and setup for the secure transfer of data. The determining factor for whether or not a `Socket` is setup as a server or client `Socket` is API which is used to initiate a connection. `listen()` will cause the `Socket` to be setup as a server socket.  Calling `connect()` results a client setup.

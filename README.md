![macOS](https://img.shields.io/badge/os-macOS-green.svg?style=flat)
![iOS](https://img.shields.io/badge/os-iOS-green.svg?style=flat)
![Linux](https://img.shields.io/badge/os-linux-green.svg?style=flat)
![Apache 2](https://img.shields.io/badge/license-Apache2-blue.svg?style=flat)
![](https://img.shields.io/badge/Swift-3.0-orange.svg?style=flat)
![](https://img.shields.io/badge/Swift-4.0-orange.svg?style=flat)
[![Build Status - Master](https://travis-ci.org/IBM-Swift/BlueSSLService.svg?branch=master)](https://travis-ci.org/IBM-Swift/BlueSSLService) 

# BlueSSLService

## Overview
SSL/TLS Add-in framework for [BlueSocket](https://github.com/IBM-Swift/BlueSocket.git) in Swift using the Swift Package Manager. Works on supported Apple platforms (using Secure Transport) and on Linux (using OpenSSL).

## Contents

* SSLService: Adds SSL/TLS support to [BlueSocket](https://github.com/IBM-Swift/BlueSocket). Pure Swift. 

## Prerequisites

### Swift

* Swift Open Source `swift-3.0.1-RELEASE` toolchain (**Minimum REQUIRED for latest release**)
* Swift Open Source `swift-4.0.0-RELEASE` toolchain (**Recommended**)
* Swift toolchain included in *Xcode Version 9.0 (9A325) or higher*.

### macOS

* macOS 10.11.6 (*El Capitan*) or higher
* Xcode Version 8.3.2 (8E2002) or higher using one of the above toolchains (*Recommended*)
* Xcode Version 9.0  (9A325) or higher using the included toolchain.
* Secure Transport is provided by macOS

### iOS

* iOS 10.0 or higher
* Xcode Version 8.3.2 (8E2002) or higher using one of the above toolchains (*Recommended*)
* Xcode Version 9.0  (9A325) or higher using the included toolchain.
* Secure Transport is provided by iOS

### Linux

* Ubuntu 16.04 (or 16.10 but only tested on 16.04)
* One of the Swift Open Source toolchain listed above
* OpenSSL is provided by the distribution

### Other Platforms

* **BlueSSLService** is **NOT** supported on *watchOS* since POSIX/BSD/Darwin sockets are not supported on the actual device although they are supported in the simulator.
* **BlueSSLService** should work on *tvOS* but has **NOT** been tested.

### Package Dependencies

* BlueSocket v0.12.70 or higher
* OpenSSL v0.3.5 or higher for Linux

*Note:* See `Package.swift` for details.

## Build

To build `SSLService` from the command line:

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

**or**, if using `self-signed` certificates:

* Application certificate (`certificateFilePath`)
* Private Key file (`keyFilePath`)

**or**, if running on Linux (for now),

* A string containing a *PEM formatted* certificate

**or**, if running on macOS:

* Certificate Chain File (`chainFilePath`) in **PKCS12** format

**or**,

* No certificate at all.

**BlueSSLService** provides five ways to create a `Configuration` supporting the scenarios above.  These are:
- `init()` - This API allows for the creation of *default* configuration.  This is equivalent to calling the next initializer without changing any parameters.
- `init(withCipherSuite cipherSuite: String? = nil, clientAllowsSelfSignedCertificates: Bool = true)` - This API allows for the creation of configuration that does not contain a backing certificate or certificate chain.  You can optionally provide a *cipherSuite* and decide whether to allow, when in client mode, use of *self-signed certificates* by the server.
- `init(withCACertificatePath caCertificateFilePath: String?, usingCertificateFile certificateFilePath: String?, withKeyFile keyFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true, cipherSuite: String? = nil)` - This API allows you to create a configuration using a self contained `Certificate Authority (CA)` file. The second parameter is the path to the `Certificate` file to be used by application to establish the connection.  The next parameter is the path to the `Private Key` file used by application corresponding to the `Public Key` in the `Certificate`. If you're using `self-signed certificates`, set the last parameter to true.
- `init(withCACertificateDirectory caCertificateDirPath: String?, usingCertificateFile certificateFilePath: String?, withKeyFile keyFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true, cipherSuite: String? = nil)` - This API allows you to create a configuration using a directory of `Certificate Authority (CA)` files. These `CA` certificates **must** be hashed using the `Certificate Tool` provided by `OpenSSL`. The following parameters are identical to the previous API.
- `init(withChainFilePath chainFilePath: String? = nil, withPassword password: String? = nil, usingSelfSignedCerts selfSigned: Bool = true, clientAllowsSelfSignedCertificates: Bool = false, cipherSuite: String? = nil)` - This API allows you to create a configuration using a single `Certificate Chain File` (see note 2 below). Add an optional password (if required) using the third parameter. Set the third parameter to true if the certificates you are using are `self-signed`, otherwise set it to false. If configuring a client and you want that client to be able to connect to servers using `self-signed` certificates, set the fourth parameter to true. 
- `init(withPEMCertificateString certificateString: String, usingSelfSignedCerts selfSigned: Bool = true, cipherSuite: String? = nil)` - This API used when supplying a PEM formatted certificate presented as a *String*. **NOTE: At present, this API is only available on Linux.**

*Note 1:* All `Certificate` and `Private Key` files must be `PEM` format. If supplying a certificate via a `String`, it must be PEM formatted. 

*Note 2:* If using a certificate chain file, the certificates must be in `PEM` format and must be sorted starting with the subject's certificate (actual client or server certificate), followed by intermediate `CA` certificates if applicable, and ending at the highest level (root) `CA`.

*Note 3:* For the first two versions of the API, if your `Private key` is included in your certificate file, you can omit this parameter and the API will use the same file name as specified for the certificate file.

*Note 4:* If you desire to customize the cipher suite used, you can do so by specifying the `cipherSuite` parameter when using one of the above initializers.  If not specified, the default value is set to `DEFAULT` on Linux. On macOS, setting of this parameter is currently not supported and attempting to set it will result in unpredictable results.  See the example below.

*Note 5:* If you're running on macOS, you must use the third form of `init` for the `Configuration` and provide a certificate chain file in `PKCS12` format, supplying a `password` if needed.

#### Example

The following illustrates creating a configuration (on *Linux*) using the second form of the API above using a self-signed certificate file as the key file and not supplying a certificate chain file.  It also illustrates setting the cipher suite to `ALL` from the default:
```swift
import SSLService

...

let myCertPath = "/opt/myApp/config/myCertificate.pem"
let myKeyPath = "/opt/myApp/config/myKeyFile.pem"

let myConfig = SSLService.Configuration(withCACertificateDirectory: nil, usingCertificateFile: myCertPath, withKeyFile: myKeyFile)

myConfig.cipherSuite = "ALL"

...

```
*Note:* This example takes advantage of the `default` parameters available on the `SSLService.Configuration.init` function. Also, changing of the `cipher suite` on *macOS* is currently not supported.

### Creating and using the SSLService

The following API is used to create the `SSLService`:
- `init?(usingConfiguration config: Configuration) throws` - This will create an instance of the `SSLService` using a previously created `Configuration`.

Once the `SSLService` is created, it can applied to a previously created `Socket` instance that's just been created. This needs to be done **before** using the `Socket`. The following code snippet illustrates how to do this (again using *Linux*).  *Note: Exception handling omitted for brevity.*

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

### Extending Connection Verification

`SSLService` provides a callback mechanism should you need to specify **additional** verification logic. After creating the instance of `SSLService`, you can set the instance variable `verifyCallback`.  This instance variable has the following signature:
```
public var verifyCallback: ((_ service: SSLService) -> (Bool, String?))? = nil
```
Setting this callback is not required. It defaults to `nil` unless set.  The first parameter passed to your callback is the instance of `SSLService` that has this callback.  This will allow you to access the public members of the `SSLService` instance in order to do additional verification.  Upon completion, your callback should return a tuple.  The first value is a `Bool` indicating the sucess or failure of the routine.  The second value is an `optional String` value used to provide a description in the case where verification failed. In the event of callback failure, an `exception` will be thrown by the internal verification function.  **Important Note:** To effectively use this callback requires knowledge of the platforms underlying secure transport service, `Apple Secure Transport` on `supported Apple platforms` and `OpenSSL` on `Linux`.

### Skipping Connection Verification

If desired, `SSLService` can *skip* the connection verification.  To accomplish this, set the property `skipVerification` to `true` after creating the `SSLService` instance.  However, if the `verifyCallback` property (described above) is set, that callback will be called regardless of this setting. The default for property is false.  It is **NOT** recommended that you skip the connection verification in a `production` environment unless you are providing verification via the `verificationCallback`.

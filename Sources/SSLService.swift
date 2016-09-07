//
//  SSLService.swift
//  SSLService
//
//  Created by Bill Abt on 5/26/16.
//
//  Copyright © 2016 IBM. All rights reserved.
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
//

import Foundation
import Socket
import OpenSSL

// MARK: SSLService

///
/// SSL Service Plugin for Socket using OpenSSL
///
public class SSLService : SSLServiceDelegate {
	
	// MARK: Statics
	
	static var openSSLInitialized: Bool 		= false
	
	// MARK: Constants
	
	let DEFAULT_VERIFY_DEPTH: Int32				= 2
	
	#if !os(Linux)
	
		let SecureTransportErrors: [OSStatus: String] = [
			errSecSuccess       : "errSecSuccess",
			errSSLNegotiation   : "errSSLNegotiation",
			errSecParam         : "errSecParam",
			errSSLClosedAbort   : "errSSLClosedAbort",
			errSecIO            : "errSecIO",
			errSSLWouldBlock    : "errSSLWouldBlock",
			errSSLPeerUnknownCA : "errSSLPeerUnknownCA",
			errSSLBadRecordMac  : "errSSLBadRecordMac",
			errSecAuthFailed    : "errSecAuthFailed",
			errSSLClosedGraceful: "errSSLClosedGraceful"
		]
	
	#endif
	
	// MARK: Typealiases
	
	#if os(Linux)
		typealias OSStatus = Int32
	#endif
	
	
	// MARK: Configuration
	
	///
	/// SSL Configuration
	///
	public struct Configuration {
		
		// MARK: Properties
		
		/// File name of CA certificate to be used.
		public private(set) var caCertificateFilePath: String? = nil
		
		/// Path to directory containing hashed CA's to be used.
		///	*Note:* `caCertificateDirPath` - All certificates in the specified directory **must** be hashed.
		public private(set) var caCertificateDirPath: String? = nil
		
		/// Path to the certificate file to be used.
		public private(set) var certificateFilePath: String? = nil
		
		/// Path to the key file to be used.
		public private(set) var keyFilePath: String? = nil
		
		/// Path to the certificate chain file (optional).
		public private(set) var certificateChainFilePath: String? = nil
		
		/// True if using `self-signed` certificates.
		public private(set) var certsAreSelfSigned = false
		
		#if os(Linux)
			/// Cipher suite to use. Defaults to `ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL`
			public var cipherSuite: String = "ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP:+eNULL"
		#else
			/// Cipher suite to use. Defaults to `14,13,2B,2F,2C,30,9E,9F,23,27,09,28,13,24,0A,14,67,33,6B,39,08,12,16,9C,9D,3C,3D,2F,35,0A`
			public var cipherSuite: String = "14,13,2B,2F,2C,30,9E,9F,23,27,09,28,13,24,0A,14,67,33,6B,39,08,12,16,9C,9D,3C,3D,2F,35,0A"
		#endif
		
		/// Password (if needed) typically used for PKCS12 files.
		public var password: String? = nil
		
		// MARK: Lifecycle
		
		///
		/// Initialize a configuration using a `CA Certificate` file.
		///
		/// - Parameters:
		///		- caCertificateFilePath:	Path to the PEM formatted CA certificate file.
		///		- certificateFilePath:		Path to the PEM formatted certificate file.
		///		- keyFilePath:				Path to the PEM formatted key file. If nil, `certificateFilePath` will be used.
		///		- selfSigned:				True if certs are `self-signed`, false otherwise. Defaults to true.
		///
		///	- Returns:	New Configuration instance.
		///
		public init(withCACertificateFilePath caCertificateFilePath: String?, usingCertificateFile certificateFilePath: String?, withKeyFile keyFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true) {
			
			self.certificateFilePath = certificateFilePath
			self.keyFilePath = keyFilePath ?? certificateFilePath
			self.certsAreSelfSigned = selfSigned
			self.caCertificateFilePath = caCertificateFilePath
		}
		
		///
		/// Initialize a configuration using a `CA Certificate` directory.
		///
		///	*Note:* `caCertificateDirPath` - All certificates in the specified directory **must** be hashed using the `OpenSSL Certificate Tool`.
		///
		/// - Parameters:
		///		- caCertificateDirPath:		Path to a directory containing CA certificates. *(see note above)*
		///		- certificateFilePath:		Path to the PEM formatted certificate file. If nil, `certificateFilePath` will be used.
		///		- keyFilePath:				Path to the PEM formatted key file (optional). If nil, `certificateFilePath` is used.
		///		- selfSigned:				True if certs are `self-signed`, false otherwise. Defaults to true.
		///
		///	- Returns:	New Configuration instance.
		///
		public init(withCACertificateDirectory caCertificateDirPath: String?, usingCertificateFile certificateFilePath: String?, withKeyFile keyFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true) {
			
			self.certificateFilePath = certificateFilePath
			self.keyFilePath = keyFilePath ?? certificateFilePath
			self.certsAreSelfSigned = selfSigned
			self.caCertificateDirPath = caCertificateDirPath
		}
		
		///
		/// Initialize a configuration using a `Certificate Chain File`.
		///
		/// *Note:* If using a certificate chain file, the certificates must be in PEM format and must be sorted starting with the subject's certificate (actual client or server certificate), followed by intermediate CA certificates if applicable, and ending at the highest level (root) CA.
		///
		/// - Parameters:
		///		- chainFilePath:			Path to the certificate chain file (optional). *(see note above)*
		///		- selfSigned:				True if certs are `self-signed`, false otherwise. Defaults to true.
		///
		///	- Returns:	New Configuration instance.
		///
		public init(withChainFilePath chainFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true) {
			
			self.certificateChainFilePath = chainFilePath
			self.certsAreSelfSigned = selfSigned
		}
	}
	
	// MARK: Properties
	
	// MARK: -- Public
	
	/// SSL Configuration (Read only)
	public private(set) var configuration: Configuration
	
	// MARK: -- Private
	
	/// True if setup as server, false if setup as client.
	private var isServer: Bool = true
	
	#if os(Linux)
	
		/// SSL Connection
		private var cSSL: UnsafeMutablePointer<SSL>? = nil
	
		/// SSL Method
		/// **Note:** We use `SSLv23` which causes negotiation of the highest available SSL/TLS version.
		private var method: UnsafePointer<SSL_METHOD>? = nil
	
		/// SSL Context
		private var context: UnsafeMutablePointer<SSL_CTX>? = nil
	
	#else
	
		/// Socket pointer
		public private(set) var socketPtr = UnsafeMutablePointer<Socket>.allocate(capacity: 1)
	
		/// SSL Context
		public private(set) var context: SSLContext?
	
	#endif
	
	
	// MARK: Lifecycle
	
	///
	/// Initialize an SSLService instance.
	///
	/// - Parameter config:		Configuration to use.
	///
	/// - Returns: SSLService instance.
	///
	public init?(usingConfiguration config: Configuration) throws {
		
		// Store it...
		self.configuration = config
		
		// Validate the config...
		try self.validate(configuration: config)
	}
	
	///
	/// Clone an existing instance of SSLService.
	///
	/// - Parameter source:		The instance of SSLService to clone.
	///
	/// - Returns: New SSLService instance cloned from the provided instance.
	///
	private init?(with source: SSLService) throws {
		
		self.configuration = source.configuration

		// Validate the config...
		try self.validate(configuration: source.configuration)
		
		// Initialize as server...
		try self.initialize(asServer: true)
	}
	
	
	// MARK: SSLServiceDelegate Protocol
	
	///
	/// Initialize SSL Service
	///
	/// - Parameter asServer:	True for initializing a server, otherwise a client.
	///
	public func initialize(asServer: Bool) throws {
		
		#if os(Linux)
			
			// Common initialization...
			if !SSLService.openSSLInitialized {
				SSL_library_init()
				SSL_load_error_strings()
				OPENSSL_config(nil)
				OPENSSL_add_all_algorithms_conf()
				SSLService.openSSLInitialized = true
			}
		
			// Server or client specific method determination...
			self.isServer = asServer
			if isServer {
			
				self.method = SSLv23_server_method()
			
			} else {
			
				self.method = SSLv23_client_method()
			}
			
		#endif
		
		// Prepare the context...
		try self.prepareContext()
	}
	
	///
	/// Deinitialize SSL Service
	///
	public func deinitialize() {
		
		#if os(Linux)
			// Shutdown and then free SSL pointer...
			if self.cSSL != nil {
				SSL_shutdown(self.cSSL!)
				SSL_free(self.cSSL!)
			}
		
			// Now the context...
			if self.context != nil {
				SSL_CTX_free(self.context!)
			}
		
			// Finally, finish cleanup...
			ERR_free_strings()
			EVP_cleanup()
		
		#else
		
			// Shutdown and then free SSL pointer...
			if self.context != nil {
				SSLClose(self.context!)
			}
			
		#endif
	}
	
	///
	/// Processing on acceptance from a listening socket
	///
	/// - Parameter socket:	The connected Socket instance.
	///
	public func onAccept(socket: Socket) throws {
		
		// If the new socket doesn't have a delegate, create one using self...
		if socket.delegate == nil {
			
			let delegate = try SSLService(with: self)
			socket.delegate = delegate
			try socket.delegate?.onAccept(socket: socket)
			
		} else {
		
			#if os(Linux)
				
				// Prepare the connection...
				let sslConnect = try prepareConnection(socket: socket)
				
				// Start the handshake...
				let rc = SSL_accept(sslConnect)
				if rc <= 0 {
				
					try self.throwLastError(source: "SSL_accept")
				}
				
			#else
				
				// Prepare the connection...
				try prepareConnection(socket: socket)
				
			#endif
			
			try self.verifyConnection()
		}
	}
	
	///
	/// Processing on connection to a listening socket
	///
	/// - Parameter socket:	The connected Socket instance.
	///
	public func onConnect(socket: Socket) throws {
		
		#if os(Linux)
			
			// Prepare the connection...
			let sslConnect = try prepareConnection(socket: socket)
		
			// Start the handshake...
			let rc = SSL_connect(sslConnect)
			if rc <= 0 {
			
				try self.throwLastError(source: "SSL_connect")
			}
			
		#else
			
			// Prepare the connection...
			try prepareConnection(socket: socket)
			
		#endif
		
		// Verify the connection...
		try self.verifyConnection()
	}
	
	///
	/// Low level writer
	///
	/// - Parameters:
	///		- buffer:		Buffer pointer.
	///		- bufSize:		Size of the buffer.
	///
	///	- Returns the number of bytes written. Zero indicates SSL shutdown, less than zero indicates error.
	///
	public func send(buffer: UnsafeRawPointer!, bufSize: Int) throws -> Int {
		
		#if os(Linux)
			
			guard let sslConnect = self.cSSL else {
				
				let reason = "ERROR: SSL_write, code: \(ECONNABORTED), reason: Unable to reference connection)"
				throw SSLError.fail(Int(ECONNABORTED), reason)
			}
			
			let rc = SSL_write(sslConnect, buffer, Int32(bufSize))
			if rc < 0 {
			
				try self.throwLastError(source: "SSL_write")
			}
			return Int(rc)
		
		#else
		
			guard let sslContext = self.context else {
				
				let reason = "ERROR: SSL_write, code: \(ECONNABORTED), reason: Unable to reference connection)"
				throw SSLError.fail(Int(ECONNABORTED), reason)
			}
			
			var processed = 0
			var status: OSStatus
			repeat {
				
				status = SSLWrite(sslContext, buffer, bufSize, &processed)
				
			} while status == errSSLWouldBlock
			
			if status != errSecSuccess {
				
				try self.throwLastError(source: "SSL_write", err: status)
			}
			return processed
			
		#endif
	}
	
	///
	/// Low level reader
	///
	/// - Parameters:
	///		- buffer:		Buffer pointer.
	///		- bufSize:		Size of the buffer.
	///
	///	- Returns the number of bytes read. Zero indicates SSL shutdown, less than zero indicates error.
	///
	public func recv(buffer: UnsafeMutableRawPointer, bufSize: Int) throws -> Int {
		
		#if os(Linux)
			
			guard let sslConnect = self.cSSL else {
				
				let reason = "ERROR: SSL_read, code: \(ECONNABORTED), reason: Unable to reference connection)"
				throw SSLError.fail(Int(ECONNABORTED), reason)
			}
			
			let rc = SSL_read(sslConnect, buffer, Int32(bufSize))
			if rc < 0 {
			
				try self.throwLastError(source: "SSL_read")
			}
			return Int(rc)
		
		#else
		
			guard let sslContext = self.context else {
				
				let reason = "ERROR: SSL_read, code: \(ECONNABORTED), reason: Unable to reference connection)"
				throw SSLError.fail(Int(ECONNABORTED), reason)
			}
			
			var processed = 0
			var status: OSStatus
			repeat {
				
				status = SSLRead(sslContext, buffer, bufSize, &processed)
				
			} while status == errSSLWouldBlock
			
			if status != errSecSuccess {
				
				try self.throwLastError(source: "SSL_read", err: status)
			}
			
			return processed
			
		#endif
	}
	
	// MARK: Private Methods
	
	///
	/// Validate configuration
	///
	/// - Parameter configuration:	Configuration to validate.
	///
	private func validate(configuration: Configuration) throws {
		
		// If we're using self-signed certs, we only require a certificate and key...
		if configuration.certsAreSelfSigned {
			
			if configuration.certificateFilePath == nil || configuration.keyFilePath == nil {
				
				throw SSLError.fail(Int(ENOENT), "Certificate and/or key file not specified.")
			}
			
		} else {
			
			// If we don't have a certificate chain file, we require the following...
			if configuration.certificateChainFilePath == nil {
				
				// Need a CA certificate (file or directory)...
				if configuration.caCertificateFilePath == nil && configuration.caCertificateDirPath == nil {
					
					throw SSLError.fail(Int(ENOENT), "CA Certificate not specified.")
				}
				
				// Also need a certificate file and key file...
				if configuration.certificateFilePath == nil || configuration.keyFilePath == nil {
					
					throw SSLError.fail(Int(ENOENT), "Certificate and/or key file not specified.")
				}
			}
		}
		
		
		// Now check if what's specified actually exists...
		// See if we've got everything...
		//	- First the CA...
		if let caFile = configuration.caCertificateFilePath {
			
			if !FileManager.default.fileExists(atPath: caFile) {
				
				throw SSLError.fail(Int(ENOENT), "CA Certificate doesn't exist in current directory.")
			}
		}
		
		if let caPath = configuration.caCertificateDirPath {
			
			var isDir: ObjCBool = false
			if !FileManager.default.fileExists(atPath: caPath, isDirectory: &isDir) {
				
				throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't exist.")
			}
			#if os(Linux)
				if !isDir {
				
					throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't specify a directory.")
				}
			#else
				if !isDir.boolValue {
					
					throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't specify a directory.")
				}
			#endif
		}
		
		//	- Then the certificate file...
		if let certFilePath = configuration.certificateFilePath {
			
			if !FileManager.default.fileExists(atPath: certFilePath) {
				
				throw SSLError.fail(Int(ENOENT), "Certificate doesn't exist at specified path.")
			}
		}
		
		//	- Now the key file...
		if let keyFilePath = configuration.keyFilePath {
			
			if !FileManager.default.fileExists(atPath: keyFilePath) {
				
				throw SSLError.fail(Int(ENOENT), "Key file doesn't exist at specified path.")
			}
		}
		
		//	- Finally, if present, the certificate chain path...
		if let chainPath = configuration.certificateChainFilePath {
			
			if !FileManager.default.fileExists(atPath: chainPath) {
				
				throw SSLError.fail(Int(ENOENT), "Certificate chain doesn't exist at specified path.")
			}
		}
	}
	
	///
	/// Prepare the context.
	///
	private func prepareContext() throws {
		
		#if os(Linux)
		
			// Make sure we've got the method to use...
			guard let method = self.method else {
			
				let reason = "ERROR: Unable to reference SSL method."
				throw SSLError.fail(Int(ENOMEM), reason)
			}
		
			// Now we can create the context...
			self.context = SSL_CTX_new(method)
		
			guard let context = self.context else {
			
				let reason = "ERROR: Unable to create SSL context."
				throw SSLError.fail(Int(ENOMEM), reason)
			}
		
			// Handle the stuff common to both client and server...
			SSL_CTX_set_cipher_list(context, self.configuration.cipherSuite)
			if self.configuration.certsAreSelfSigned {
				SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nil)
			} else {
				SSL_CTX_set_verify(context, SSL_VERIFY_PEER, nil)
			}
			SSL_CTX_set_verify_depth(context, DEFAULT_VERIFY_DEPTH)
		
			// Then handle the client/server specific stuff...
			if !self.isServer {
			
				SSL_CTX_ctrl(context, SSL_CTRL_OPTIONS, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION, nil)
			}
		
			// Now configure the rest...
			//	Note: We've already verified the configuration, so we've at least got the minimum requirements.
			// 	- First process the CA certificate(s) if any...
			var rc: Int32 = 0
			if configuration.caCertificateFilePath != nil || configuration.caCertificateDirPath != nil {
			
				let caFile = self.configuration.caCertificateFilePath
				let caPath = self.configuration.caCertificateDirPath
			
				rc = SSL_CTX_load_verify_locations(context, caFile, caPath)
				if rc <= 0 {
				
					try self.throwLastError(source: "CA Certificate file/dir")
				}
			}
		
			//	- Then the app certificate...
			if let certFilePath = self.configuration.certificateFilePath {
			
				rc = SSL_CTX_use_certificate_file(context, certFilePath, SSL_FILETYPE_PEM)
				if rc <= 0 {
				
					try self.throwLastError(source: "Certificate")
				}
			}
		
			//	- An' the corresponding Private key file...
			if let keyFilePath = self.configuration.keyFilePath {
			
				rc = SSL_CTX_use_PrivateKey_file(context, keyFilePath, SSL_FILETYPE_PEM)
				if rc <= 0 {
				
					try self.throwLastError(source: "Key file")
				}
			
				// Check it for consistency...
				rc = SSL_CTX_check_private_key(context)
				if rc <= 0 {
				
					try self.throwLastError(source: "Check private key")
				}
			}
		
			//	- Finally, if present, the certificate chain path...
			if let chainPath = configuration.certificateChainFilePath {
			
				rc = SSL_CTX_use_certificate_chain_file(context, chainPath)
				if rc <= 0 {
				
					try self.throwLastError(source: "Certificate chain file")
				}
			}
		
		#else
		
			if !self.isServer {
				
				let reason = "ERROR: Only server currently supported"
				throw SSLError.fail(Int(ENOENT),reason)
			}
			
			//	Note: We've already verified the configuration, so we've at least got the minimum requirements.

			//	- Must have certificate chain path...
			if let chainPath = configuration.certificateChainFilePath {
				
				guard NSData(contentsOfFile: chainPath) != nil else {
					
					let reason = "ERROR: Error reading PKCS12 file"
					throw SSLError.fail(Int(ENOENT),reason)
				}
				
			} else {
				
				let reason = "ERROR: Error reading PKCS12 file"
				throw SSLError.fail(Int(ENOENT),reason)
			}
			
			// Create the context...
			self.context = SSLCreateContext(kCFAllocatorDefault,SSLProtocolSide.serverSide,SSLConnectionType.streamType)
			guard let sslContext = self.context else {
				
				let reason = "ERROR: Unable to create SSL context."
				throw SSLError.fail(Int(ENOMEM), reason)
			}
			
			// Now prepare it...
			SSLSetIOFuncs(sslContext, sslReadCallback, sslWriteCallback)
			
			// Ensure we've got the certificates...
			guard let certFile = configuration.certificateChainFilePath else {
				
				let reason = "ERROR: No PKCS12 file"
				throw SSLError.fail(Int(ENOENT),reason)
			}
			
			// Now load them...
			var status: OSStatus
			guard let p12Data = NSData(contentsOfFile: certFile) else {
				
				let reason = "ERROR: Error reading PKCS12 file"
				throw SSLError.fail(Int(ENOENT),reason)
			}
			
			// Create key dictionary for reading p12 file...
			guard let passwd: String = self.configuration.password else {
				
				let reason = "ERROR: No password for PKCS12 file"
				throw SSLError.fail(Int(ENOENT),reason)
			}
			let key: NSString = kSecImportExportPassphrase as NSString
			let options: NSDictionary = [key: passwd as AnyObject]
			
			var items: CFArray? = nil
			
			// Import the PKCS12 file...
			status = SecPKCS12Import(p12Data, options, &items)
			if status != errSecSuccess {
				
				try self.throwLastError(source: "SecPKCS12Import", err: status)
			}
			
			// Now extract what we need...
			let newArray = items! as [AnyObject] as NSArray
			let dictionary = newArray.object(at: 0)
			
			//	- Identity reference...
			var secIdentityRef = (dictionary as AnyObject).value(forKey: kSecImportItemKeyID as String)
			secIdentityRef = (dictionary as AnyObject).value(forKey: "identity")
			guard let secIdentity = secIdentityRef else {
				
				let reason = "ERROR: Can't extract identity."
				throw SSLError.fail(Int(ENOENT),reason)
			}
			
			var certs = [secIdentity]
			var ccerts: Array<SecCertificate> = (dictionary as AnyObject).value(forKey: kSecImportItemCertChain as String) as! Array<SecCertificate>
			for i in 1 ..< ccerts.count {
				
				certs += [ccerts[i] as AnyObject]
			}
			
			status = SSLSetCertificate(sslContext, certs as CFArray)
			if status != errSecSuccess {
				
				try self.throwLastError(source: "SSLSetCertificate", err: status)
			}
			
			
			let cipherlist = configuration.cipherSuite.components(separatedBy: ",")
			let eSize = cipherlist.count * MemoryLayout<SSLCipherSuite>.size
			let eCipherSuites : UnsafeMutablePointer<SSLCipherSuite> = UnsafeMutablePointer.allocate(capacity: eSize)
			for i in 0..<cipherlist.count {
				
				eCipherSuites.advanced(by: i).pointee = UInt32(cipherlist[i] , radix: 16)!
			}
			status = SSLSetEnabledCiphers(sslContext, eCipherSuites, cipherlist.count)
			if status != errSecSuccess {
				
				try self.throwLastError(source: "SSLSetConnection", err: status)
			}
			
		#endif
	}
	
#if os(Linux)
	
	///
	/// Prepare the connection for either server or client use.
	///
	/// - Parameter socket:	The connected Socket instance.
	///
	/// - Returns: `UnsafeMutablePointer` to the SSL connection.
	///
	private func prepareConnection(socket: Socket) throws -> UnsafeMutablePointer<SSL> {
		
		// Make sure our context is valid...
		guard let context = self.context else {
			
			let reason = "ERROR: Unable to access SSL context."
			throw SSLError.fail(Int(EFAULT), reason)
		}
		
		// Now create the connection...
		self.cSSL = SSL_new(context)
		
		guard let sslConnect = self.cSSL else {
			
			let reason = "ERROR: Unable to create SSL connection."
			throw SSLError.fail(Int(EFAULT), reason)
		}
		
		// Set the socket file descriptor...
		SSL_set_fd(sslConnect, socket.socketfd)
		
		return sslConnect
	}
	
#else
	
	///
	/// Prepare the connection for either server or client use.
	///
	/// - Parameter socket:	The connected Socket instance.
	///
	private func prepareConnection(socket: Socket) throws {
		
		// Make sure we've got a context...
		guard let sslContext = self.context else {
			
			let reason = "ERROR: Unable to access SSL context."
			throw SSLError.fail(Int(EFAULT), reason)
		}
		
		// Set the socket file descriptor...
		self.socketPtr.pointee = socket
		var status: OSStatus = SSLSetConnection(sslContext, self.socketPtr)
		if status != errSecSuccess {
			
			try self.throwLastError(source: "SSLSetConnection", err: status)
		}
		
		repeat {
			
			status = SSLHandshake(sslContext)
			
		} while status == errSSLWouldBlock
		
		if status != errSecSuccess {
			
			try self.throwLastError(source: "SSLHandshake", err: status)
		}
	}
	
#endif
	
	///
	/// Do connection verification
	///
	private func verifyConnection() throws {
		
		// Skip the verification if we're using self-signed certs and we're a server...
		if self.configuration.certsAreSelfSigned && self.isServer {
			return
		}
		
		// @FIXME: No verification on macOS yet...
		
		#if os(Linux)

			// Standard Linux verification...
			guard let sslConnect = self.cSSL else {
			
				let reason = "ERROR: verifyConnection, code: \(ECONNABORTED), reason: Unable to reference connection)"
				throw SSLError.fail(Int(ECONNABORTED), reason)
			}
		
			if SSL_get_peer_certificate(sslConnect) != nil {
			
				let rc = SSL_get_verify_result(sslConnect)
				switch rc {
				
				case Int(X509_V_OK):
					return
				case Int(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT), Int(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY):
					if self.configuration.certsAreSelfSigned {
						return
					}
				default:
					break
				}
			
				// If we're here, we've got an error...
				let reason = "ERROR: verifyConnection, code: \(rc), reason: Peer certificate was not presented."
				throw SSLError.fail(Int(ECONNABORTED), reason)
			
			} else {
			
				let reason = "ERROR: verifyConnection, code: \(ECONNABORTED), reason: Peer certificate was not presented."
				throw SSLError.fail(Int(ECONNABORTED), reason)
			}
		
		#endif
	}
	
	///
	/// Throws the last error encountered.
	///
	/// - Parameters:
 	///		- source: 	The string describing the error.
	///		- err:		On `macOS`, the error code, *unused* on `Linux`.
	///
	///
	private func throwLastError(source: String, err: OSStatus = 0) throws {
		
		var errorString: String
		
		#if os(Linux)
			
			let err = ERR_get_error()
			if let errorStr = ERR_reason_error_string(err) {
				errorString = String(validatingUTF8: errorStr)!
			} else {
				errorString = "Could not determine error reason."
			}
			
		#else
			
			if let val = SecureTransportErrors[err] {
				errorString = val
			} else {
				errorString = "Could not determine error reason."
			}
			
		#endif
		
		let reason = "ERROR: \(source), code: \(err), reason: \(errorString)"
		throw SSLError.fail(Int(err), reason)
	}
}

#if !os(Linux)

	///
	/// SSL Read Callback
	///
	/// - Parameters:
	///		- connection:	The connection to read from (contains pointer to active Socket object).
	///		- data:			The area for the returned data.
	///		- dataLength:	The amount of data to read.
	///
	/// - Returns:			The `OSStatus` reflecting the result of the call.
	///
	private func sslReadCallback(connection: SSLConnectionRef, data: UnsafeMutableRawPointer, dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
		
		// Extract the socket descriptor from the context...
		var temp = connection
		let addr = withUnsafePointer(to: &temp) {
			return UnsafeRawPointer($0)
		}
		let socket = addr.assumingMemoryBound(to: Socket.self).pointee
		
		// Now the bytes to read...
		let bytesRequested = dataLength.pointee
		
		// Read the data from the socket...
		let bytesRead = read(socket.socketfd, data, UnsafePointer<Int>(dataLength).pointee)
		if bytesRead > 0 {
			
			dataLength.initialize(to: bytesRead)
			if bytesRequested > bytesRead {
				
				return OSStatus(errSSLWouldBlock)
				
			} else {
				
				return noErr
			}
			
		} else if bytesRead == 0 {
			
			dataLength.initialize(to: 0)
			return OSStatus(errSSLClosedGraceful)
			
		} else {
			
			dataLength.initialize(to: 0)
			
			switch errno {
				
			case ENOENT:
				return OSStatus(errSSLClosedGraceful)
			case EAGAIN:
				return OSStatus(errSSLWouldBlock)
			case ECONNRESET:
				return OSStatus(errSSLClosedAbort)
			default:
				return OSStatus(errSecIO)
			}
			
		}
		
	}
	
	///
	/// SSL Write Callback
	///
	/// - Parameters:
	///		- connection:	The connection to write to (contains pointer to active Socket object).
	///		- data:			The data to be written.
	///		- dataLength:	The amount of data to be written.
	///
	/// - Returns:			The `OSStatus` reflecting the result of the call.
	///
	private func sslWriteCallback(connection: SSLConnectionRef, data: UnsafeRawPointer, dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
		
		// Extract the socket descriptor from the context...
		var temp = connection
		let addr = withUnsafePointer(to: &temp) {
			return UnsafeRawPointer($0)
		}
		let socket = addr.assumingMemoryBound(to: Socket.self).pointee
		
		// Now the bytes to read...
		let bytesToWrite = dataLength.pointee
		
		// Write to the socket...
		let bytesWritten = write(socket.socketfd, data, UnsafePointer<Int>(dataLength).pointee)
		if bytesWritten > 0 {
			
			dataLength.initialize(to: bytesWritten)
			if bytesToWrite > bytesWritten {
			
				return Int32(errSSLWouldBlock)
				
			} else {
				
				return noErr
			}
			
		} else if bytesWritten == 0 {
			
			dataLength.initialize(to: 0)
			return OSStatus(errSSLClosedGraceful)
			
		} else {
			
			dataLength.initialize(to: 0)
			
			if errno == EAGAIN {
			
				return OSStatus(errSSLWouldBlock)
				
			} else {
				
				return OSStatus(errSecIO)
			}
		}
	}
	
#endif

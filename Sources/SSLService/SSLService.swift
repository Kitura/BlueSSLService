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

#if os(Linux)
	import OpenSSL
#endif

import Dispatch

// MARK: SSLService

///
/// **SSLService:** SSL Service Plugin for Socket using **Apple Secure Transport** on `macOS` and **OpenSSL** on `Linux`.
///
public class SSLService: SSLServiceDelegate {
	
	// MARK: Statics
	
	#if os(Linux)
		/// Flag set to indicate that OpenSSL has been initialized.  This initialization need only be done once per instance.
		static var initialized: Bool 					= false
	#endif
	
	// MARK: Constants
	
	// MARK: PEM Certificate Markers
	
	/// PEM Begin Marker
	static let PEM_BEGIN_MARKER: String					= "-----BEGIN CERTIFICATE-----"
	
	/// PEM End Marker
	static let PEM_END_MARKER: String					= "-----END CERTIFICATE-----"
	
	/// Default verfication depth
	static let DEFAULT_VERIFY_DEPTH: Int32				= 2
	
	#if !os(Linux)
	
		/// String representation of Secure Transport Errors
		let SecureTransportErrors: [OSStatus: String] 	= [
			errSecSuccess       	 : "errSecSuccess",
			errSSLNegotiation   	 : "errSSLNegotiation",
			errSecParam         	 : "errSecParam",
			errSSLClosedAbort   	 : "errSSLClosedAbort",
			errSecIO            	 : "errSecIO",
			errSSLWouldBlock    	 : "errSSLWouldBlock",
			errSSLPeerUnknownCA 	 : "errSSLPeerUnknownCA",
			errSSLBadRecordMac  	 : "errSSLBadRecordMac",
			errSecAuthFailed    	 : "errSecAuthFailed",
			errSSLClosedGraceful	 : "errSSLClosedGraceful",
			errSSLXCertChainInvalid	 : "errSSLXCertChainInvalid",
			errSSLPeerAuthCompleted: "errSSLPeerAuthCompleted"
		]
	
	#endif
	
	// MARK: Typealiases
	
	#if os(Linux)
		typealias OSStatus 								= Int32
	#endif
	
	// MARK: Helpers
	
	///
	/// Used to dispatch reads and writes to protect the SSLContext
	///
	public struct SSLReadWriteDispatcher {
		
		/// Internal semaphore
		let s = DispatchSemaphore(value: 1)
	
		///
		/// Sync access to the embedded closure.
		///
		/// - Parameters:
		///		- execute:		The block of `protected` code to be executed.
		///
		///	- Returns:			<R>
		///
		func sync<R>(execute: () throws -> R) rethrows -> R {
		
			_ = s.wait(timeout: DispatchTime.distantFuture)
		
			defer {
				s.signal()
			}
				
			return try execute()
		}
	}
	
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
		
		/// Path to PEM formatted certificate string.
		public private(set) var certificateString: String? = nil
		
		/// True if server is using `self-signed` certificates.
		public private(set) var certsAreSelfSigned = false
        
        /// True if isServer == false and the client accepts self-signed certificates. Defaults to false, be careful to not leave as true in production
        public private(set) var clientAllowsSelfSignedCertificates = false
		
		#if os(Linux)
			/// Cipher suites to use. Defaults to `DEFAULT:!DH`
			public var cipherSuite: String = "DEFAULT:!DH"
		#else
			/// Cipher suites to use. Defaults to `14,13,2B,2F,2C,30,9E,9F,23,27,09,28,13,24,0A,14,67,33,6B,39,08,12,16,9C,9D,3C,3D,2F,35,0A`
			// @FIXME: This isn't quite right, needs to be revisited.
			public var cipherSuite: String = "14,13,2B,2F,2C,30,9E,9F,23,27,09,28,13,24,0A,14,67,33,6B,39,08,12,16,9C,9D,3C,3D,2F,35,0A"
		
			/// `True` to use default cipher list, false otherwise.
			public var useDefaultCiphers: Bool = true

			/// Cached array of previously imported PKCS12.
			fileprivate var pkcs12Certs: CFArray? = nil
		#endif
		
		/// Password (if needed) typically used for PKCS12 files.
		public var password: String? = nil
		
		/// True if no backing certificates provided (Readonly).
		public private(set) var noBackingCertificates = false
		
		// MARK: Lifecycle
		
		///
		/// Initialize a configuration with no backing certificates.
		///
		/// - Parameters:
		///		- cipherSuite:					Optional String containing the cipher suite to use.
		///		- clientAllowsSelfSignedCertificates:
		///										`true` to accept self-signed certificates from a server. `false` otherwise.
		///										**Note:** This parameter is only used when `SSLService` is used with a client socket.
		///
		///	- Returns:	New Configuration instance.
		///
		public init(withCipherSuite cipherSuite: String? = nil, clientAllowsSelfSignedCertificates: Bool = true) {
			
			self.noBackingCertificates = true
			self.clientAllowsSelfSignedCertificates = clientAllowsSelfSignedCertificates
			if cipherSuite != nil {
				self.cipherSuite = cipherSuite!
			}
		}
		
		///
		/// Initialize a configuration using a `CA Certificate` file.
		///
		/// - Parameters:
		///		- caCertificateFilePath:	Path to the PEM formatted CA certificate file.
		///		- certificateFilePath:		Path to the PEM formatted certificate file.
		///		- keyFilePath:				Path to the PEM formatted key file. If nil, `certificateFilePath` will be used.
		///		- selfSigned:				True if certs are `self-signed`, false otherwise. Defaults to true.
		///		- cipherSuite:				Optional String containing the cipher suite to use.
		///
		///	- Returns:	New Configuration instance.
		///
		public init(withCACertificateFilePath caCertificateFilePath: String?, usingCertificateFile certificateFilePath: String?, withKeyFile keyFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true, cipherSuite: String? = nil) {
			
			self.certificateFilePath = certificateFilePath
			self.keyFilePath = keyFilePath ?? certificateFilePath
			self.certsAreSelfSigned = selfSigned
			self.caCertificateFilePath = caCertificateFilePath
			if cipherSuite != nil {
				self.cipherSuite = cipherSuite!
			}
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
		///		- cipherSuite:				Optional String containing the cipher suite to use.
		///
		///	- Returns:	New Configuration instance.
		///
		public init(withCACertificateDirectory caCertificateDirPath: String?, usingCertificateFile certificateFilePath: String?, withKeyFile keyFilePath: String? = nil, usingSelfSignedCerts selfSigned: Bool = true, cipherSuite: String? = nil) {
			
			self.certificateFilePath = certificateFilePath
			self.keyFilePath = keyFilePath ?? certificateFilePath
			self.certsAreSelfSigned = selfSigned
			self.caCertificateDirPath = caCertificateDirPath
			if cipherSuite != nil {
				self.cipherSuite = cipherSuite!
			}
		}
		
		///
		/// Initialize a configuration using a `Certificate Chain File`.
		///
		/// *Note:* If using a certificate chain file, the certificates must be in PEM format and must be sorted starting with the subject's certificate (actual client or server certificate), followed by intermediate CA certificates if applicable, and ending at the highest level (root) CA.
		///
		/// - Parameters:
		///		- chainFilePath:                        Path to the certificate chain file (optional). *(see note above)*
		///		- password:                             Password for the chain file (optional).
		///		- selfSigned:                           True if certs are `self-signed`, false otherwise. Defaults to true.
        ///     - clientAllowsSelfSignedCertificates:   True if, as a client, connections to self-signed servers are allowed
		///		- cipherSuite:                          Optional String containing the cipher suite to use.
		///
		///	- Returns:	New Configuration instance.
		///
        public init(withChainFilePath chainFilePath: String?, withPassword password: String? = nil, usingSelfSignedCerts selfSigned: Bool = true, clientAllowsSelfSignedCertificates: Bool = false, cipherSuite: String? = nil) {
			
			self.certificateChainFilePath = chainFilePath
			self.password = password
			self.certsAreSelfSigned = selfSigned
            self.clientAllowsSelfSignedCertificates = clientAllowsSelfSignedCertificates
			if cipherSuite != nil {
				self.cipherSuite = cipherSuite!
			}
		}

		#if os(Linux)
		///
		/// Initialize a configuration using a `PEM formatted certificate in String form`.
		///
		/// - Parameters:
		///		- certificateString:		PEM formatted certificate in String form.
		///		- selfSigned:				True if certs are `self-signed`, false otherwise. Defaults to true.
		///		- cipherSuite:				Optional String containing the cipher suite to use.
		///
		///	- Returns:	New Configuration instance.
		///
		public init(withPEMCertificateString certificateString: String, usingSelfSignedCerts selfSigned: Bool = true, cipherSuite: String? = nil) {
			
			self.certificateString = certificateString
			self.certsAreSelfSigned = selfSigned
			if cipherSuite != nil {
				self.cipherSuite = cipherSuite!
			}
		}
		#endif
	}
		
	// MARK: Properties
	
	// MARK: -- Public
	
	// MARK: --- Settable
	
	///
	/// Verification Callback. Called by the internal `verifyConnection()` function to do any *additional* connection verification.  This property is set after initializing the `SSLService`.
	///
	/// - Parameters service:	This service module
	///
	/// - Returns:	Tuple containing a `Bool` to indicate success or failure of the verification and a `String?` containing text describing the error if desired.
	///
	public var verifyCallback: ((_ service: SSLService) -> (Bool, String?))? = nil
	
	/// If true, skips the internal verification.  However, if the `verifyCallback` property is set, the callback will be called regardless of this setting. Default is false. This property is set after initializing the `SSLService`.
	public var skipVerification: Bool = false
	
	// MARK: --- Read Only
	
	/// SSL Configuration (Read only)
	public private(set) var configuration: Configuration
	
	/// True if setup as server, false if setup as client.
	public private(set) var isServer: Bool = true

	/// Read/write dispatcher to serialize these operations...
	public private(set) var rwDispatch = SSLReadWriteDispatcher()
	
	#if os(Linux)
	
		/// SSL Connection
		public private(set) var cSSL: UnsafeMutablePointer<SSL>? = nil
	
		/// SSL Method
		/// **Note:** We use `SSLv23` which causes negotiation of the highest available SSL/TLS version.
		public private(set) var method: UnsafePointer<SSL_METHOD>? = nil
	
		/// SSL Context
		public private(set) var context: UnsafeMutablePointer<SSL_CTX>? = nil
	
	
		// MARK: ALPN
		
		/// List of supported ALPN protocols
		public func addSupportedAlpnProtocol(proto: String) {
			if SSLService.availableAlpnProtocols.contains(proto) {
				return
			}
			SSLService.availableAlpnProtocols.append(proto)
		}
		private static var availableAlpnProtocols = [String]()
		
		/// The negotiated ALPN protocol, if any
		public private(set) var negotiatedAlpnProtocol: String?
	
	#else
	
		/// Socket Pointer containing the socket fd (passed to the `SSLRead` and `SSLWrite` callback routines).
		public private(set) var socketPtr = UnsafeMutablePointer<Int32>.allocate(capacity: 1)
	
		/// SSL Context
		public private(set) var context: SSLContext?
	
	#endif
	
	// MARK: Lifecycle
	
	///
	/// Initialize an `SSLService` instance.
	///
	/// - Parameter config:		Configuration to use.
	///
	/// - Returns: `SSLService` instance.
	///
	public init?(usingConfiguration config: Configuration) throws {
		
		// Store it...
		self.configuration = config
		
		// Validate the config...
		try self.validate(configuration: config)
	}
	
	///
	/// Clone an existing instance of `SSLService`.
	///
	/// - Parameter source:		The instance of `SSLService` to clone.
	///
	/// - Returns: New `SSLService` instance cloned from the provided instance.
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
	/// Initialize `SSLService`
	///
	/// - Parameter asServer:	True for initializing a server, otherwise a client.
	///
	public func initialize(asServer: Bool) throws {
		
		self.isServer = asServer

		#if os(Linux)
			
			// Common initialization...
			// 	- We only do this once...
			if !SSLService.initialized {
				SSL_library_init()
				SSL_load_error_strings()
				OPENSSL_config(nil)
				OPENSSL_add_all_algorithms_conf()
				SSLService.initialized = true
			}
			
			// Server or client specific method determination...
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
	/// Deinitialize `SSLService`
	///
	public func deinitialize() {
		
		#if os(Linux)
			
			// Shutdown and then free SSL pointer...
			if self.cSSL != nil {
				
				// This should avoid receiving the SIGPIPE when shutting down a session...
				let rc = SSL_get_shutdown(self.cSSL!)
				if rc >= 0 {
					SSL_shutdown(self.cSSL!)
				}
				
				// Finish cleaning up...
				SSL_free(self.cSSL!)
			}
			
			// Now the context...
			if self.context != nil {
				SSL_CTX_free(self.context!)
			}
			
			// Finally, finish cleanup...
			// NOTE: Can't call these due to issues with latest OpenSSL...
			//ERR_free_strings()
			//EVP_cleanup()
			
		#else
			
			// Cloae the context...
			if self.context != nil {
				SSLClose(self.context!)
			}
			
			// Free the socket pointer...
            #if swift(>=4.1)
                self.socketPtr.deallocate()
            #else
                self.socketPtr.deallocate(capacity: 1)
            #endif
			
		#endif
	}
	
	///
	/// Processing on acceptance from a listening socket
	///
	/// - Parameter socket:	The connected `Socket` instance.
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
				ERR_clear_error()
				let rc = SSL_accept(sslConnect)
				if rc <= 0 {
					
					try self.throwLastError(source: "SSL_accept", err: SSL_get_error(sslConnect, rc))
				}
				
			#else
				
				// Prepare the connection and start the handshake process...
				try prepareConnection(socket: socket)
				
			#endif
			
			try self.verifyConnection()
			
			#if os(Linux)
			
				// Seek for ALPN protocol and select the first supported one
				negotiateAlpnProtocols()
			
			#endif
		}
	}
	
	///
	/// Processing on connection to a listening socket
	///
	/// - Parameter socket:	The connected `Socket` instance.
	///
	public func onConnect(socket: Socket) throws {
		
		#if os(Linux)
			
			// Prepare the connection...
			let sslConnect = try prepareConnection(socket: socket)
			
			// Start the handshake...
			ERR_clear_error()
			let rc = SSL_connect(sslConnect)
			if rc <= 0 {
				
				try self.throwLastError(source: "SSL_connect", err: SSL_get_error(sslConnect, rc))
			}
			
		#else
			
			// Prepare the connection and start the handshake process...
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
	public func send(buffer: UnsafeRawPointer, bufSize: Int) throws -> Int {
		
		#if os(Linux)
			
			let processed = try self.rwDispatch.sync(execute: { [unowned self] () -> Int in
				
				guard let sslConnect = self.cSSL else {
				
					let reason = "ERROR: SSL_write, code: \(ECONNABORTED), reason: Unable to reference connection)"
					throw SSLError.fail(Int(ECONNABORTED), reason)
				}
			
				ERR_clear_error()
				let rc = SSL_write(sslConnect, buffer, Int32(bufSize))
				if rc < 0 {
				
					let lastError = SSL_get_error(sslConnect, rc)
					if lastError == SSL_ERROR_WANT_READ || lastError == SSL_ERROR_WANT_WRITE {
						
						throw SSLError.retryNeeded
					}
				
					try self.throwLastError(source: "SSL_write", err: lastError)
					return 0
				}
				return Int(rc)
			})
			
			return processed
			
		#else
			
			let processed = try self.rwDispatch.sync(execute: { [unowned self] () -> Int in
				
				guard let sslContext = self.context else {
					
					let reason = "ERROR: SSL_write, code: \(ECONNABORTED), reason: Unable to reference connection)"
					throw SSLError.fail(Int(ECONNABORTED), reason)
				}
				
				var processed = 0
				let status: OSStatus = SSLWrite(sslContext, buffer, bufSize, &processed)
				if status == errSSLWouldBlock {
					
					throw SSLError.retryNeeded
					
				} else if status != errSecSuccess {
					
					try self.throwLastError(source: "SSLWrite", err: status)
				}
				return processed
			})
			
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
	///	- Returns: the number of bytes read. Zero indicates SSL shutdown or in the case of a non-blocking socket, no data available for reading, less than zero indicates error.
	///
	public func recv(buffer: UnsafeMutableRawPointer, bufSize: Int) throws -> Int {
		
		#if os(Linux)
			
			let processed = try self.rwDispatch.sync(execute: { [unowned self] () -> Int in
				
				guard let sslConnect = self.cSSL else {
				
					let reason = "ERROR: SSL_read, code: \(ECONNABORTED), reason: Unable to reference connection)"
					throw SSLError.fail(Int(ECONNABORTED), reason)
				}
			
				ERR_clear_error()
				let rc = SSL_read(sslConnect, buffer, Int32(bufSize))
				if rc < 0 {
				
					let lastError = SSL_get_error(sslConnect, rc)
					if lastError == SSL_ERROR_WANT_READ || lastError == SSL_ERROR_WANT_WRITE {

						errno = EAGAIN
						return -1
					}
				
					try self.throwLastError(source: "SSL_read", err: lastError)
					return 0
				}
				return Int(rc)
			})
		
			return processed
	
		#else
			
			let processed = try self.rwDispatch.sync(execute: { [unowned self] () -> Int in
				
				guard let sslContext = self.context else {
				
					let reason = "ERROR: SSLRead, code: \(ECONNABORTED), reason: Unable to reference connection)"
					throw SSLError.fail(Int(ECONNABORTED), reason)
				}
			
				var processed = 0
				let status: OSStatus = SSLRead(sslContext, buffer, bufSize, &processed)
				if status != errSecSuccess && status != errSSLWouldBlock && status != errSSLClosedGraceful {
				
					try self.throwLastError(source: "SSLRead", err: status)
				}
			
				if status == errSSLWouldBlock {
				
					errno = EWOULDBLOCK
					return -1
				}
			
				return status == errSSLClosedGraceful ? 0 : processed
			
			})
			
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
		
		// Skip validation if no backing certificates provided...
		if configuration.noBackingCertificates {
			return
		}
		
		// If we have a certificate in string format, check that first...
		if let certString = configuration.certificateString {
			
			// Make sure that string in a valid format...
			guard certString.hasPrefix(SSLService.PEM_BEGIN_MARKER) &&
				certString.hasSuffix(SSLService.PEM_END_MARKER) &&
				certString.utf8.count > 0 else {
					
					throw SSLError.fail(Int(ENOENT), "PEM Certificate String is not valid.")
			}
			return
		}
        
		#if os(Linux)
			
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
			
		#else
			
			// On macOS and friends, we currently only support PKCS12 formatted certificate chain file...
			//	- Note: This is regardless of whether it's self-signed or not.
			if configuration.certificateChainFilePath == nil {
				
				throw SSLError.fail(Int(ENOENT), "PKCS12 file not specified.")
			}
			
		#endif
		
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
			#if !os(Linux) || swift(>=4.1)
				if !isDir.boolValue {
					
					throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't specify a directory.")
				}
			#else
				if !isDir {
					
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
				try self.throwLastError(source: reason)
				return
			}
			
			// Handle the stuff common to both client and server...
			//	- Auto retry...
			SSL_CTX_ctrl(context, SSL_CTRL_MODE, SSL_MODE_AUTO_RETRY, nil)

			//	- User selected cipher list...
			SSL_CTX_set_cipher_list(context, self.configuration.cipherSuite)

			//	- Verification behavior...
			if self.configuration.certsAreSelfSigned {
				SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nil)
			}
			SSL_CTX_set_verify_depth(context, SSLService.DEFAULT_VERIFY_DEPTH)
			
			//	- Auto ECDH handling...  Note: requires OpenSSL 1.0.2 or greater.
			SSL_CTX_setAutoECDH(context)
			
			// Then handle the client/server specific stuff...
			if !self.isServer {
				
				SSL_CTX_ctrl(context, SSL_CTRL_OPTIONS, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION, nil)
			}
			
			// Now configure the rest...
			//	Note: We've already verified the configuration, so we've at least got the minimum requirements.
			// 	- First process the CA certificate(s) if any...
			var rc: Int32 = 0
			if self.configuration.caCertificateFilePath != nil || self.configuration.caCertificateDirPath != nil {
				
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
			
			//	- Now, if present, the certificate chain path...
			if let chainPath = configuration.certificateChainFilePath {
				
				rc = SSL_CTX_use_certificate_chain_file(context, chainPath)
				if rc <= 0 {
					
					try self.throwLastError(source: "Certificate chain file")
				}
			}
			
			//	- And, if we have certificate string, process that...
			if let certString = configuration.certificateString {
				
				let bio = BIO_new(BIO_s_mem())
				defer {
					BIO_free(bio)
				}
				BIO_puts(bio, certString)
				let certificate = PEM_read_bio_X509(bio, nil, nil, nil)
				if certificate == nil {
					
					try self.throwLastError(source: "PEM Certificate String to X509")
				}
				rc = SSL_CTX_use_certificate(context, certificate)
				if rc <= 0 {
					
					try self.throwLastError(source: "PEM Certificate String")
				}
			}
			
			// - Finally, setup ALPN/NPN callback functions
			// -- NPN advertised protocols to be sent in ServerHello if requested
			SSL_CTX_set_next_protos_advertised_cb(context, { ( ssl, data, len, arg ) in
				
				//E.g. data: [ 0x02, 0x68, 0x32 ] //2, 'h', '2'
				var availBytes = [UInt8]()
				let available = SSLService.availableAlpnProtocols
				
				for proto in available {
					
					availBytes.append(UInt8(proto.lengthOfBytes(using: .ascii)))
					let protoBytes: [UInt8] = Array(proto.utf8)
					availBytes.append(contentsOf: protoBytes)
				}
				data?.initialize(to: availBytes)
				len?.pointee = UInt32(availBytes.count)
				
				return SSL_TLSEXT_ERR_OK
				
			}, nil)
			
			// -- Callback for selecting an ALPN protocol based on supported protocols
			SSL_CTX_set_alpn_select_cb_wrapper(context, { (ssl, out, outlen, _in, _inlen, arg) in
				
				//_in is a buffer of bytes sent by the client within the ClientHello. The structure
				//is a byte of length followed by ascii bytes for the name of the protocol.
				//E.g. "\u{02}h2\u{08}http/1.1"
				
				// For each protocol listed in the _in buffer, check to see if it is also listed
				// in the supported protocol. Select the first supported protocol.
				if let _in = _in {
					
					let data = Data(bytes: _in, count: Int(_inlen))
					let available = SSLService.availableAlpnProtocols
					var lengthByteIndex = 0
					
					while lengthByteIndex < data.count {
						
						let lowerIndex = lengthByteIndex + 1
						let upperIndex = lengthByteIndex + Int(data[lengthByteIndex]) + 1
						let range:Range<Int> = lowerIndex ..< upperIndex
						let protData = data.subdata(in: range)
						if let inStr = String(data: protData, encoding: .ascii) {
							
							if available.contains(inStr) {
								
								//The protocol is supported, set it back in the out buffer and return
								//an OK code
								out?.pointee = _in + lowerIndex
								outlen?.pointee = (_in + lengthByteIndex).pointee
								return SSL_TLSEXT_ERR_OK
							}
						}
						
						//Advance to the next protocol length byte in the buffer
						lengthByteIndex = upperIndex
					}
				}
				
				// None of the provided protocol is supported. Return NOACK.
				return SSL_TLSEXT_ERR_NOACK
				
			}, nil)
			
		#else
			
			// Note: We've already verified the configuration, so we've at least got the minimum requirements.
			//	Therefore, we don't need to check again...
			
			// So, first create the context...
			let protocolSide: SSLProtocolSide = self.isServer ? .serverSide : .clientSide
			self.context = SSLCreateContext(kCFAllocatorDefault, protocolSide, SSLConnectionType.streamType)
			guard let sslContext = self.context else {
				
				let reason = "ERROR: Unable to create SSL context."
				throw SSLError.fail(Int(ENOMEM), reason)
			}
			
			// Now prepare it...
			//	- Setup our read and write callbacks...
			SSLSetIOFuncs(sslContext, sslReadCallback, sslWriteCallback)
			
			//  - Process the PKCS12 file (if any)...
			var status: OSStatus
			if configuration.noBackingCertificates == false {
				
				// If we haven't processed the PKCS12 yet, process it now...
				if self.configuration.pkcs12Certs == nil {
					
					//	- Ensure we've got the certificates...
					guard let certFile = configuration.certificateChainFilePath else {
						
						let reason = "ERROR: No PKCS12 file"
						throw SSLError.fail(Int(ENOENT), reason)
					}
					
					// 	- Now load them...
					guard let p12Data = NSData(contentsOfFile: certFile) else {
						
						let reason = "ERROR: Error reading PKCS12 file"
						throw SSLError.fail(Int(ENOENT), reason)
					}
					
					// 	- Create key dictionary for reading p12 file...
					guard let passwd: String = self.configuration.password else {
						
						let reason = "ERROR: No password for PKCS12 file"
						throw SSLError.fail(Int(ENOENT), reason)
					}
					let key: NSString = kSecImportExportPassphrase as NSString
					let options: NSDictionary = [key: passwd as AnyObject]
					
					var items: CFArray? = nil
					
					// 	- Import the PKCS12 file...
					status = SecPKCS12Import(p12Data, options, &items)
					if status != errSecSuccess {
						
						try self.throwLastError(source: "SecPKCS12Import", err: status)
					}
					
					// 	- Now extract what we need...
					let newArray = items! as [AnyObject] as NSArray
					if newArray.count == 0 {
						let reason = "ERROR: Could not load content of PKCS12 file"
						throw SSLError.fail(Int(ENOENT), reason)
					}
					let dictionary = newArray.object(at: 0)
					
					//	-- Identity reference...
					var secIdentityRef = (dictionary as AnyObject).value(forKey: kSecImportItemKeyID as String)
					secIdentityRef = (dictionary as AnyObject).value(forKey: "identity")
					guard let secIdentity = secIdentityRef else {
						
						let reason = "ERROR: Can't extract identity."
						throw SSLError.fail(Int(ENOENT), reason)
					}
					
					//	-- Cert chain...
					var certs = [secIdentity]
					var ccerts: Array<SecCertificate> = (dictionary as AnyObject).value(forKey: kSecImportItemCertChain as String) as! Array<SecCertificate>
					for i in 1 ..< ccerts.count {
						
						certs += [ccerts[i] as AnyObject]
					}
					
					// reuse pkcs12 certs in clones as SecPKCS12Import is very expensive
					self.configuration.pkcs12Certs = certs as CFArray
				}
				
				status = SSLSetCertificate(sslContext, self.configuration.pkcs12Certs)
				if status != errSecSuccess {
					
					try self.throwLastError(source: "SSLSetCertificate", err: status)
				}
				
			}
			
			// If we're using default ciphers, skip the process below...
			if configuration.useDefaultCiphers {
				return
			}
			
			//	- Setup the cipher list...
			let cipherlist = configuration.cipherSuite.components(separatedBy: ",")
			let eSize = cipherlist.count * MemoryLayout<SSLCipherSuite>.size
			let eCipherSuites: UnsafeMutablePointer<SSLCipherSuite> = UnsafeMutablePointer.allocate(capacity: eSize)
			for i in 0..<cipherlist.count {
				
				eCipherSuites.advanced(by: i).pointee = SSLCipherSuite(cipherlist[i], radix: 16)!
			}
			
			//	- Enable the desired ciphers...
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
	/// - Parameter socket:	The connected `Socket` instance.
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
	
	///
	/// The function will use the OpenSSL API to negotiate an ALPN protocol with the client.
	/// This is usually being done in response the a ClientHello message that contains the ALPN extension information.
	/// If an ALPN protocol has been chose, it will be set in the 'negotiatedAlpnProtocol' field.
	///
	private func negotiateAlpnProtocols() {
	
		var alpn: UnsafePointer<UInt8>? = nil
		var alpnlen: UInt32 = 0
	
		SSL_get0_next_proto_negotiated(self.cSSL, &alpn, &alpnlen)
		if (alpn == nil) {
			SSL_get0_alpn_selected_wrapper(self.cSSL, &alpn, &alpnlen)
		}
	
		if alpn != nil && alpnlen > 0 {
			let data = Data(bytes: alpn!, count: Int(alpnlen))
			let alpnStr = String(data: data, encoding: .ascii)
				negotiatedAlpnProtocol = alpnStr
		} else {
			negotiatedAlpnProtocol = nil
		}
	}
	
#else
	
	///
	/// Prepare the connection for either server or client use.
	///
	/// - Parameter socket:	The connected `Socket` instance.
	///
	private func prepareConnection(socket: Socket) throws {
		
		// Make sure we've got a context...
		guard let sslContext = self.context else {
			
			let reason = "ERROR: Unable to access SSL context."
			throw SSLError.fail(Int(EFAULT), reason)
		}
		
		// Set the socket file descriptor as our connection data...
		self.socketPtr.pointee = socket.socketfd
		
		var status: OSStatus = SSLSetConnection(sslContext, self.socketPtr)
		if status != errSecSuccess {
			
			try self.throwLastError(source: "SSLSetConnection", err: status)
		}
        
        // Allow self signed certificates from server
        if isServer == false && configuration.clientAllowsSelfSignedCertificates == true {
            SSLSetSessionOption(sslContext, .breakOnServerAuth, true)
        }

		
		// Start and repeat the handshake process until it either completes or fails...
		repeat {
			
			status = SSLHandshake(sslContext)
			
		} while status == errSSLWouldBlock
		
		if status != errSecSuccess && status != errSSLPeerAuthCompleted {
			
			try self.throwLastError(source: "SSLHandshake", err: status)
		}
	}
	
#endif
	
	///
	/// Do connection verification
	///
	private func verifyConnection() throws {

		// Only do verification if the skip verification flag is off and...
		// 	we have backing certificates...
		if self.skipVerification == false && self.configuration.noBackingCertificates == false {
			
			// Skip the verification if we're using self-signed certs and we're a server...
			if self.configuration.certsAreSelfSigned && self.isServer {
				return
			}
		
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
					case Int(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT),
					     Int(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY),
					     Int(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT):
						if self.configuration.certsAreSelfSigned {
							return
						}
					default:
						break
					}
				
					// If we're here, we've got an error...
					let reason = "ERROR: verifyConnection, code: \(rc), reason: Unable to verify presented peer certificate."
					throw SSLError.fail(Int(ECONNABORTED), reason)
				
				}
			
				// If we're a client, we need to see the certificate and verify it...
				//	Otherwise, if we're a server we may or may not be presented one. If we get one however, we must verify it...
				if !self.isServer {
				
					let reason = "ERROR: verifyConnection, code: \(ECONNABORTED), reason: Peer certificate was not presented."
					throw SSLError.fail(Int(ECONNABORTED), reason)
				}
			
			#else
			
				// @FIXME: No standard verification on macOS yet...
			
			#endif
			
		}
		
		// Always do any additional caller defined verification...
		
		// If a callback to do additional verification is present, execute the callback now...
		if let callback = self.verifyCallback {
			
			let (passed, failReason) = callback(self)
			if passed {
				return
			}
			
			let reason = failReason ?? "Unknown verification failure"
			throw SSLError.fail(Int(EFAULT), "ERROR: " + reason)
		}
	}
	
	///
	/// Throws the last error encountered.
	///
	/// - Parameters:
	///		- source: 	The string describing the error.
	///		- err:		On `macOS`, the error code, *unused* on `Linux`.
	///
	///	- Returns:		Throws an exception.  On `Linux`, however, if `ERR_get_error()` returns a zero (0), this function simply returns indicating no error.
	///
	private func throwLastError(source: String, err: OSStatus = 0) throws {
		
		var errorCode = err
		var errorString: String
		
		#if os(Linux)
			
			if errorCode == 0 || errorCode == SSL_ERROR_SSL {
				errorCode = Int32(ERR_get_error())
			}
			
			// Don't throw an error if the err code comes back as a zero...
			//	- This indicates no error found, so just return...
			if errorCode == 0 {
				return
			}
			
			if let errorStr = ERR_reason_error_string(UInt(errorCode)) {
				errorString = String(validatingUTF8: errorStr)!

				if let errorFunc = ERR_func_error_string(UInt(errorCode)) {
					errorString = String(validatingUTF8: errorFunc)! + ":" + errorString
				}
			} else {
				errorString = "Could not determine error reason."
			}
			
		#else
			
			// If no error, just return...
			if errorCode == errSecSuccess {
				return
			}
			
			if let val = SecureTransportErrors[errorCode] {
				errorString = val
			} else {
				errorString = "Could not determine error reason."
			}
			
		#endif
		
		let reason = "ERROR: \(source), code: \(errorCode), reason: \(errorString)"
		throw SSLError.fail(Int(errorCode), reason)
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
		
		// Extract the socket file descriptor from the context...
		let socketfd = connection.assumingMemoryBound(to: Int32.self).pointee
		
		// Now the bytes to read...
		let bytesRequested = dataLength.pointee
		
		// Read the data from the socket...
		let bytesRead = read(socketfd, data, bytesRequested)
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
		
		// Extract the socket file descriptor from the context...
		let socketfd = connection.assumingMemoryBound(to: Int32.self).pointee
		
		// Now the bytes to read...
		let bytesToWrite = dataLength.pointee
		
		// Write to the socket...
		let bytesWritten = write(socketfd, data, bytesToWrite)
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

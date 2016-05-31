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
	
	// MARK: Constants
	
	let DEFAULT_VERIFY_DEPTH: Int32				= 4
	
	// MARK: Configuration
	
	///
	/// SSL Configuration
	///
	public struct Configuration {
		
		// MARK: Properties
		
		/// File name of CA certificate to be used.
		///	*Note:* `caCertificateFile` **must** reside in the same directory as the application.
		public private(set) var caCertificateFile: String? = nil
		
		/// Path to directory containing hashed CA's to be used.
		///	*Note:* `caCertificateDirPath` - All certificates in the specified directory **must** be hashed.
		public private(set) var caCertificateDirPath: String? = nil
		
		/// Path to the certificate file to be used.
		public private(set) var certificateFilePath: String? = nil
		
		/// Path to the key file to be used.
		public private(set) var keyFilePath: String? = nil
		
		/// Path to the certificate chain file (optional).
		public private(set) var certificateChainFilePath: String? = nil
		
		// MARK: Lifecycle
		
		///
		/// Initialize a configuration using a `CA Certificate` file.
		///
		///	*Note:* `caCertificateFile` **must** reside in the **same** directory as the application.
		///
		/// - Parameters:
		///		- caCertificateFile:		Name of the PEM formatted CA certificate file. *(see note above)*
		///		- certificateFilePath:		Path to the PEM formatted certificate file.
		///		- keyFilePath:				Path to the PEM formatted key file.
		///
		///	- Returns:	New Configuration instance.
		///
		public init(withCACertificate caCertificateFile: String?, usingCertificateFile certificateFilePath: String?, withKeyFile keyFilePath: String?) {
			
			self.caCertificateFile = caCertificateFile
			self.certificateFilePath = certificateFilePath
			self.keyFilePath = keyFilePath
		}
		
		///
		/// Initialize a configuration using a `CA Certificate` directory.
		///
		///	*Note:* `caCertificateDirPath` - All certificates in the specified directory **must** be hashed using the `OpenSSL Certificate Tool`.
		///
		/// - Parameters:
		///		- caCertificateDirPath:		Path to a directory containing CA certificates. *(see note above)*
		///		- certificateFilePath:		Path to the PEM formatted certificate file.
		///		- keyFilePath:				Path to the PEM formatted key file (optional). If nil, `certificateFilePath` is used.
		///
		///	- Returns:	New Configuration instance.
		///
		public init(withCACertificateDirectory caCertificateDirPath: String?, usingCertificateFile certificateFilePath: String?, withKeyFile keyFilePath: String?) {
			
			self.caCertificateDirPath = caCertificateDirPath
			self.certificateFilePath = certificateFilePath
			self.keyFilePath = keyFilePath
		}
		
		///
		/// Initialize a configuration using a `Certificate Chain File`.
		///
		/// *Note:* If using a certificate chain file, the certificates must be in PEM format and must be sorted starting with the subject's certificate (actual client or server certificate), followed by intermediate CA certificates if applicable, and ending at the highest level (root) CA.
		///
		/// - Parameter chainFilePath:		Path to the certificate chain file (optional). *(see note above)*
		///
		///	- Returns:	New Configuration instance.
		///
		public init(withChainFilePath chainFilePath: String? = nil) {
			
			self.certificateChainFilePath = chainFilePath
		}
	}
	
	// MARK: Properties
	
	// MARK: -- Public
	
	/// SSL Configuration (Read only)
	public private(set) var configuration: Configuration
	
	// MARK: -- Private
	
	/// True if setup as server, false if setup as client.
	private var isServer: Bool = true
	
	/// SSL Connection
	private var cSSL: UnsafeMutablePointer<SSL>? = nil
	
	/// SSL Method
	/// **Note:** We use `SSLv23` which causes negotiation of the highest available SSL/TLS version.
	private var method: UnsafePointer<SSL_METHOD>? = nil
	
	/// SSL Context
	private var context: UnsafeMutablePointer<SSL_CTX>? = nil
	
	
	// MARK: Lifecycle
	
	///
	/// Initialize an SSLService instance.
	///
	/// - Parameter config:		Configuration to use.
	///
	/// - Returns: SSLServer instance.
	///
	public init?(usingConfiguration config: Configuration) throws {
		
		// Store it...
		self.configuration = config
		
		// Validate the config...
		try self.validate(configuration: config)
	}
	
	
	// MARK: SSLServiceDelegate Protocol
	
	///
	/// Initialize SSL Service
	///
	/// - Parameter isServer:	True for initializing a server, otherwise a client.
	///
	public func initialize(isServer: Bool) throws {
		
		// Common initialization...
		SSL_library_init()
		SSL_load_error_strings()
		OPENSSL_config(nil)
		OPENSSL_add_all_algorithms_conf()
		
		// Server or client specific method determination...
		self.isServer = isServer
		if isServer {
			
			self.method = SSLv23_server_method()
			
		} else {
			
			self.method = SSLv23_client_method()
		}
		
		// Prepare the context...
		try self.prepareContext()
	}
	
	///
	/// Deinitialize SSL Service
	///
	public func deinitialize() {
		
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
	}
	
	///
	/// Processing on acceptance from a listening socket
	///
	/// - Parameter socket:	The connected Socket instance.
	///
	public func onAccept(socket: Socket) throws {
		
		// Prepare the connection...
		let sslConnect = try prepareConnection(socket: socket)
		
		// Start the handshake...
		let rc = SSL_accept(sslConnect)
		if rc <= 0 {
			
			try self.throwLastError(source: "SSL_accept")
		}
	}
	
	///
	/// Processing on connection to a listening socket
	///
	/// - Parameter socket:	The connected Socket instance.
	///
	public func onConnect(socket: Socket) throws {
		
		// Prepare the connection...
		let sslConnect = try prepareConnection(socket: socket)
		
		// Start the handshake...
		let rc = SSL_connect(sslConnect)
		if rc <= 0 {
			
			try self.throwLastError(source: "SSL_connect")
		}
	}
	
	///
	/// Do connection verification
	///
	public func verifyConnection() throws {
		
		guard let sslConnect = self.cSSL else {
			
			let reason = "ERROR: verifyConnection, code: \(ECONNABORTED), reason: Unable to reference connection)"
			throw SSLError.fail(Int(ECONNABORTED), reason)
		}
		
		if SSL_get_peer_cert_chain(sslConnect) != nil {
			
			if SSL_get_verify_result(sslConnect) != Int(X509_V_OK) {
				
				let reason = "ERROR: verifyConnection, code: \(EFAULT), reason: Peer certificate failed verification."
				throw SSLError.fail(Int(EFAULT), reason)
			}
			
			// Note: if here, connection has been verified.
			
		} else {
			
			let reason = "ERROR: verifyConnection, code: \(ECONNABORTED), reason: Peer certificate was not presented."
			throw SSLError.fail(Int(ECONNABORTED), reason)
		}
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
	public func send(buffer: UnsafePointer<Void>!, bufSize: Int) throws -> Int {
		
		guard let sslConnect = self.cSSL else {
			
			let reason = "ERROR: SSL_write, code: \(ECONNABORTED), reason: Unable to reference connection)"
			throw SSLError.fail(Int(ECONNABORTED), reason)
		}
		
		let rc = SSL_write(sslConnect, buffer, Int32(bufSize))
		if rc < 0 {
			
			try self.throwLastError(source: "SSL_write")
		}
		return Int(rc)
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
	public func recv(buffer: UnsafeMutablePointer<Void>!, bufSize: Int) throws -> Int {
		
		guard let sslConnect = self.cSSL else {
			
			let reason = "ERROR: SSL_read, code: \(ECONNABORTED), reason: Unable to reference connection)"
			throw SSLError.fail(Int(ECONNABORTED), reason)
		}
		
		let rc = SSL_read(sslConnect, buffer, Int32(bufSize))
		if rc < 0 {
			
			try self.throwLastError(source: "SSL_read")
		}
		return Int(rc)
	}
	
	// MARK: Private Methods
	
	///
	/// Validate configuration
	///
	/// - Parameter configuration:	Configuration to validate.
	///
	private func validate(configuration: Configuration) throws {
		
		// If we don't have a certificate chain file, we require the following...
		if configuration.certificateChainFilePath == nil {
			
			// Need a CA certificate (file or directory)...
			if configuration.caCertificateFile == nil && configuration.caCertificateDirPath == nil {
			
			throw SSLError.fail(Int(ENOENT), "CA Certificate not specified.")
			}
			
			// Also need a certificate file and key file...
			if configuration.certificateFilePath == nil || configuration.keyFilePath == nil {
				
				throw SSLError.fail(Int(ENOENT), "Certificate and/or key file not specified.")
			}
		}
		
		// Now check if what's specified actually exists...
		#if os(Linux)
			// See if we've got everything...
			//	- First the CA...
			if let caFile = configuration.caCertificateFile {
				
				let path = "./\(caFile)"
				if !NSFileManager.defaultManager().fileExists(atPath: path) {
					
					throw SSLError.fail(Int(ENOENT), "CA Certificate doesn't exist in current directory.")
				}
			}
			
			if let caPath = configuration.caCertificateDirPath {
				
				var isDir: ObjCBool = false
				if !NSFileManager.defaultManager().fileExists(atPath: caPath, isDirectory: &isDir) {
					
					throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't exist.")
				}
				if !isDir {
					
					throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't specify a directory.")
				}
			}
			
			//	- Then the certificate file...
			if let certFilePath = configuration.certificateFilePath {
				
				if !NSFileManager.defaultManager().fileExists(atPath: certFilePath) {
					
					throw SSLError.fail(Int(ENOENT), "Certificate doesn't exist at specified path.")
				}
			}
			
			//	- Now the key file...
			if let keyFilePath = configuration.keyFilePath {
				
				if !NSFileManager.defaultManager().fileExists(atPath: keyFilePath) {
					
					throw SSLError.fail(Int(ENOENT), "Key file doesn't exist at specified path.")
				}
			}
			
			//	- Finally, if present, the certificate chain path...
			if let chainPath = configuration.certificateChainFilePath {
				
				if !NSFileManager.defaultManager().fileExists(atPath: chainPath) {
					
					throw SSLError.fail(Int(ENOENT), "Certificate chain doesn't exist at specified path.")
				}
			}
		#else
			// See if we've got everything...
			//	- First the CA...
			if let caFile = configuration.caCertificateFile {
				
				let path = "./\(caFile)"
				if !NSFileManager.default().fileExists(atPath: path) {
					
					throw SSLError.fail(Int(ENOENT), "CA Certificate doesn't exist in current directory.")
				}
			}
			
			if let caPath = configuration.caCertificateDirPath {
				
				var isDir: ObjCBool = false
				if !NSFileManager.default().fileExists(atPath: caPath, isDirectory: &isDir) {
					
					throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't exist.")
				}
				if !isDir {
					
					throw SSLError.fail(Int(ENOENT), "CA Certificate directory path doesn't specify a directory.")
				}
			}
			
			//	- Then the certificate file...
			if let certFilePath = configuration.certificateFilePath {
				
				if !NSFileManager.default().fileExists(atPath: certFilePath) {
					
					throw SSLError.fail(Int(ENOENT), "Certificate doesn't exist at specified path.")
				}
			}
			
			//	- Now the key file...
			if let keyFilePath = configuration.keyFilePath {
				
				if !NSFileManager.default().fileExists(atPath: keyFilePath) {
					
					throw SSLError.fail(Int(ENOENT), "Key file doesn't exist at specified path.")
				}
			}
			
			//	- Finally, if present, the certificate chain path...
			if let chainPath = configuration.certificateChainFilePath {
				
				if !NSFileManager.default().fileExists(atPath: chainPath) {
					
					throw SSLError.fail(Int(ENOENT), "Certificate chain doesn't exist at specified path.")
				}
			}
		#endif
	}
	
	///
	/// Prepare the context.
	///
	private func prepareContext() throws {
		
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
		SSL_CTX_set_cipher_list(context, "ALL")
		SSL_CTX_set_verify(context, SSL_VERIFY_PEER, nil)
		SSL_CTX_set_verify_depth(context, DEFAULT_VERIFY_DEPTH)
		SSL_CTX_set_tlsext_use_srtp(context, "SRTP_AES128_CM_SHA1_80")
		
		// Then handle the client/server specific stuff...
		if !self.isServer {
			
			//SSL_CTX_ctrl(context, SSL_CTRL_OPTIONS, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION, nil)
		}
		
		// Now configure the rest...
		//	Note: We've already verified the configuration, so we've at least got the minimum requirements.
		// 	- First process the CA certificate(s) if any...
		var rc: Int32 = 0
		if configuration.caCertificateFile != nil || configuration.caCertificateDirPath != nil {
			
			let caFile = self.configuration.caCertificateFile
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
	}
	
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
	
	private func throwLastError(source: String) throws {
		
		let err = ERR_get_error()
		var errorString: String
		if let errorStr = ERR_reason_error_string(err) {
			errorString = String(validatingUTF8: errorStr)!
		} else {
			errorString = "Could not determine error reason."
		}
		let reason = "ERROR: \(source), code: \(err), reason: \(errorString)"
		throw SSLError.fail(Int(err), reason)
	}
}

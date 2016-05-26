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
/// SSL Service Plugin for BlueSocket using OpenSSL
///
public class SSLService : SSLServiceDelegate {
	
	// MARK: Configuration
	
	public struct Configuration {
		
		// MARK: Properties
		
		/// Path to the certificate file to be used.
		public private(set) var certificateFilePath: String
		
		/// Path to the key file to be used.
		public private(set) var keyFilePath: String
		
		// MARK: Lifecycle
		
		///
		/// Initialize a configuration
		///
		public init?(certificatePath: String, keyPath: String) throws {
			
			self.certificateFilePath = certificatePath
			self.keyFilePath = keyPath
		}
	}
	
	// MARK: Properties
	
	// MARK: -- Public
	
	public private(set) var configuration: Configuration
	
	// MARK: -- Private
	
	private var cSSL: SSL? = nil
	private var method: SSL_METHOD? = nil
	private var context: SSL_CTX? = nil
	
	
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
		
		// Common...
		SSL_load_error_strings()
		SSL_library_init()
		OPENSSL_add_all_algorithms_noconf()
		
		// Server or client specific...
		if isServer {
			
			try self.initServerSide()
			
		} else {
			
			try self.initClientSide()
		}
	}
	
	///
	/// Deinitialize SSL Service
	///
	public func deinitialize() {
		
		// Shutdown and then free SSL pointer...
		if self.cSSL != nil {
			withUnsafeMutablePointer(&self.cSSL!) {
				SSL_shutdown($0)
				SSL_free($0)
			}
		}

		// Now the context...
		if self.context != nil {
			withUnsafeMutablePointer(&self.context!) {
				SSL_CTX_free($0)
			}
		}
		
		// Finally, finish cleanup...
		ERR_free_strings()
		EVP_cleanup()
	}
	
	///
	/// Processing on acceptance from a listening socket
	///
	public func onAccept(socket: Socket) throws {
		
		
	}
	
	///
	/// Processing on connection to a listening socket
	///
	public func onConnect(socket: Socket) throws {
		
		
	}
	
	///
	/// Do connection verification
	///
	public func verifyConnection(socket: Socket) throws {
		
		
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
	public func send(buffer: UnsafePointer<Void>!, bufSize: Int) -> Int {
		
		return 0
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
	public func recv(buffer: UnsafeMutablePointer<Void>!, bufSize: Int) -> Int {
		
		return 0
	}
	
	// MARK: Private Methods
	
	///
	/// Validate configuration
	///
	private func validate(configuration: Configuration) throws {
		
		
	}
	
	///
	/// Initial client side SSL
	///
	private func initClientSide() throws {
		
		
	}

	///
	/// Initial server side SSL
	///
	private func initServerSide() throws {
		
		
	}
}

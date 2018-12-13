//
//  SocketTests.swift
//  BlueSocket
//
//  Created by Bill Abt on 3/15/16.
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

import XCTest
import Foundation
import Dispatch

#if os(Linux)
	import Glibc
#endif

import Socket
@testable import SSLService

class SSLServiceTests: XCTestCase {
	
	let QUIT: String = "QUIT"
	let port: Int32 = 1337
	let host: String = "127.0.0.1"
	let path: String = "/tmp/server.test.socket"
	let password = "kitura"
	var configuration: SSLService.Configuration? = nil
	var certPath: URL? = nil
	var keyPath: URL? = nil
	var p12Path: URL? = nil
	
	/// Test for bundle usage.
	static var useBundles: Bool {
		if let bundle = SSLServiceTests.bundle {
			let path = bundle.path(forResource: "cert", ofType: "p12")
			return path != nil
		} else {
			return false
		}
	}
	
	#if os(Linux)
		static let bundle: Bundle? = nil
	#else
		static let bundle: Bundle? = Bundle(for: SSLServiceTests.self)
	#endif
	
	#if os(Linux)
		let enableSSL = true
	#else
		let enableSSL = false
	#endif
	
	///
	/// Platform independent utility function to locate test files.
	///
	/// - Parameters:
	///		- resource:			The name of the resource to find.
	///		- ofType:			The type (i.e. extension) of the resource.
	///
	///	- Returns:	URL for the resource or nil if a path to the resource cannot be found.
	///
	static public func getFilePath(for resource: String, ofType: String) -> URL? {
		
		var path: URL
		
		if SSLServiceTests.useBundles, let bundle = SSLServiceTests.bundle {
			guard let bPath = bundle.path(forResource: resource, ofType: ofType) else {
				
				return nil
			}
			path = URL(fileURLWithPath: bPath)
			
		} else {
			
			path = URL(fileURLWithPath: #file).appendingPathComponent("../certs/" + resource + "." + ofType).standardized
		}
		
		return path
	}
	
	override func setUp() {

		super.setUp()
    }
    
    override func tearDown() {

		super.tearDown()
    }
	
	func createConfiguration() {
		
		self.certPath = SSLServiceTests.getFilePath(for: "cert", ofType: "pem")
		XCTAssertNotNil(self.certPath)
		self.keyPath = SSLServiceTests.getFilePath(for: "key", ofType: "pem")
		XCTAssertNotNil(self.keyPath)
		self.p12Path = SSLServiceTests.getFilePath(for: "cert", ofType: "p12")
		XCTAssertNotNil(self.p12Path)
		
		#if os(Linux)
			self.configuration = SSLService.Configuration(withCACertificateDirectory: nil, usingCertificateFile: self.certPath?.path, withKeyFile: self.keyPath?.path, usingSelfSignedCerts: true)
		#else
			self.configuration = SSLService.Configuration(withChainFilePath: self.p12Path?.path, withPassword: self.password, usingSelfSignedCerts: true)
		#endif
		
	}
	
	func createSecureHelper(family: Socket.ProtocolFamily = .inet) throws -> Socket {
		
		let socket = try Socket.create(family: family)
		XCTAssertNotNil(socket)
		XCTAssertFalse(socket.isConnected)
		XCTAssertTrue(socket.isBlocking)
		
		if enableSSL {
		
			self.createConfiguration()
		
			let service = try SSLService(usingConfiguration: self.configuration!)
			XCTAssertNotNil(service)
		
			socket.delegate = service
		
		}
		
		return socket
	}
	
	func launchSecureServerHelper(family: Socket.ProtocolFamily = .inet) {
		
		let queue: DispatchQueue? = DispatchQueue.global(qos: .userInteractive)
		guard let pQueue = queue else {
			
			print("Unable to access global interactive QOS queue")
			XCTFail()
			return
		}
		
		pQueue.async { [unowned self] in
			
			do {
				
				try self.secureServerHelper(family: family)
				
			} catch let error {
				
				guard let socketError = error as? Socket.Error else {
					
					print("Unexpected error...")
					XCTFail()
					return
				}
				
				print("launchSecureServerHelper Error reported:\n \(socketError.description)")
				XCTFail()
			}
		}
	}
	
	func secureServerHelper(family: Socket.ProtocolFamily = .inet) throws {
		
		var keepRunning: Bool = true
		var listenSocket: Socket? = nil
		
		do {
			
			try listenSocket = Socket.create(family: family)
			
			guard let listener = listenSocket else {
				
				print("Unable to unwrap socket...")
				XCTFail()
				return
			}
			
			var socket: Socket
			
			if enableSSL {
			
				self.createConfiguration()
			
				let service = try SSLService(usingConfiguration: self.configuration!)
				XCTAssertNotNil(service)

				listener.delegate = service
			
			}
			
			// Setting up TCP...
			try listener.listen(on: Int(port), maxBacklogSize: 10)

			print("Listening on port: \(port)")
			
			socket = try listener.acceptClientConnection()
			
			print("Accepted connection from: \(socket.remoteHostname) on port \(socket.remotePort), Secure? \(socket.signature!.isSecure)")
			
			try socket.write(from: "Hello, type 'QUIT' to end session\n")
			
			var bytesRead = 0
			repeat {
				
				var readData = Data()
				bytesRead = try socket.read(into: &readData)
				
				if bytesRead > 0 {
					
					guard let response = NSString(data: readData, encoding: String.Encoding.utf8.rawValue) else {
						
						print("Error decoding response...")
						readData.count = 0
						XCTFail()
						break
					}
					
					if response.hasPrefix(QUIT) {
						
						keepRunning = false
					}
					
					// TCP or UNIX?
					if family == .inet || family == .inet6 {
						print("Server received from connection at \(socket.remoteHostname):\(socket.remotePort): \(response) ")
					} else {
						print("Server received from connection at \(socket.remotePath!): \(response) ")
					}
					
					let reply = "Server response: \n\(response)\n"
					try socket.write(from: reply)
					
				}
				
				if bytesRead == 0 {
					
					break
				}
				
			} while keepRunning
			
			socket.close()
			XCTAssertFalse(socket.isActive)
			
		} catch let error {
			
			guard let socketError = error as? Socket.Error else {
				
				print("Unexpected error...")
				XCTFail()
				return
			}
			
			// This error is expected when we're shutting it down...
			if socketError.errorCode == Int32(Socket.SOCKET_ERR_WRITE_FAILED) {
				return
			}
			print("serverHelper Error reported: \(socketError.description)")
			XCTFail()
		}
	}

	func readAndPrint(socket: Socket, data: inout Data) throws -> String? {
		
		data.count = 0
		let	bytesRead = try socket.read(into: &data)
		if bytesRead > 0 {
			
			print("Read \(bytesRead) from socket...")
			
			guard let response = NSString(data: data as Data, encoding: String.Encoding.utf8.rawValue) else {
				
				print("Error accessing received data...")
				XCTFail()
				return nil
			}
			
			print("Response:\n\(response)")
			return String(describing: response)
		}

		return nil
	}
	
	func testSSLConfiguration() {
		
		self.createConfiguration()
	}
	
	func testSecureReadWrite() {
		
		let hostname = "127.0.0.1"
		let port: Int32 = 1337
		
		let bufSize = 4096
		var data = Data()
		
		do {
			
			// Launch the server helper...
			launchSecureServerHelper()
			
			// Need to wait for the server to come up...
			#if os(Linux)
			_ = Glibc.sleep(2)
			#else
			_ = Darwin.sleep(2)
			#endif
			
			// Create the signature...
			let signature = try Socket.Signature(protocolFamily: .inet, socketType: .stream, proto: .tcp, hostname: hostname, port: port)!
			
			// Create the socket...
			let socket = try createSecureHelper()
			
			// Defer cleanup...
			defer {
				// Close the socket...
				socket.close()
				XCTAssertFalse(socket.isActive)
			}
			
			// Connect to the server helper...
			try socket.connect(using: signature)
			if !socket.isConnected {
				
				fatalError("Failed to connect to the server...")
			}
			
			print("\nConnected to host: \(hostname):\(port)")
			print("\tSocket signature: \(socket.signature!.description)\n")
			
			_ = try readAndPrint(socket: socket, data: &data)
			
			let hello = "Hello from client..."
			try socket.write(from: hello)
			
			print("Wrote '\(hello)' to socket...")
			
			let response = try readAndPrint(socket: socket, data: &data)
			
			XCTAssertNotNil(response)
			XCTAssertEqual(response, "Server response: \n\(hello)\n")
			
			try socket.write(from: "QUIT")
			
			print("Sent quit to server...")
			
			// Need to wait for the server to go down before continuing...
			#if os(Linux)
			_ = Glibc.sleep(1)
			#else
			_ = Darwin.sleep(1)
			#endif
			
		} catch let error {
			
			// See if it's a socket error or something else...
			guard let socketError = error as? Socket.Error else {
				
				print("Unexpected error...")
				XCTFail()
				return
			}
			
			print("testReadWrite Error reported: \(socketError.description)")
			XCTFail()
		}
		
	}

	static var allTests = [
		("testSSLConfiguration", testSSLConfiguration),
		("testSecureReadWrite", testSecureReadWrite),
	]
}

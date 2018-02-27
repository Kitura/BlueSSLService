//
//  Package.swift
//  SSLService
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

import PackageDescription

#if os(Linux) || os(macOS) || os(iOS) || os(tvOS)

	let package = Package(
		name: "SSLService",
		targets: [Target(name: "SSLService")],
		dependencies: [
			.Package(url: "https://github.com/IBM-Swift/BlueSocket.git", majorVersion: 1, minor: 0),
			],
		exclude: ["SSLService.xcodeproj", "README.md", "Sources/Info.plist"])
		
	#if os(Linux)
		
		package.dependencies.append(
			.Package(url: "https://github.com/IBM-Swift/OpenSSL.git", majorVersion: 1, minor: 0))
		
	#endif
	
#else
	
	fatalError("Unsupported OS")
	
#endif

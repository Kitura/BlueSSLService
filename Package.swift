// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

//
//  Package.swift
//  SSLService
//
//  Copyright © 2016-2020 IBM and the authors of the Kitura project. All rights reserved.
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.
//

import PackageDescription

#if os(Linux) || os(macOS) || os(iOS) || os(tvOS)

var packageDependencies: [Package.Dependency] = [.package(url: "https://github.com/Kitura/BlueSocket.git", from: "1.0.0")]
var targetDependencies: [Target.Dependency] = [.byName(name: "Socket")]

#if os(Linux)

	packageDependencies.append(.package(url: "https://github.com/Kitura/OpenSSL.git", from: "2.0.0"))

	targetDependencies.append(.byName(name: "OpenSSL"))

#endif

let package = Package(
    name: "SSLService",

    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "SSLService",
            targets: ["SSLService"]),
        ],

    dependencies:
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        packageDependencies,

    targets: [
        // Targets are the basic building blocks of a package. A target defines a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "SSLService",
            dependencies: targetDependencies,
            exclude: ["SSLService.xcodeproj", "README.md", "Sources/Info.plist"]
		),
		.testTarget(
			name: "SSLServiceTests",
			dependencies: ["SSLService"]
		)
	]
)

#else

fatalError("Unsupported OS")

#endif


Pod::Spec.new do |s|
  s.name        = "BlueSSLService"
  s.version     = "2.0.0"
  s.summary     = "SSL/TLS Add-in framework for BlueSocket in Swift"
  s.homepage    = "https://github.com/Kitura/BlueSSLService"
  s.license     = { :type => "Apache License, Version 2.0" }
  s.author     = "IBM and the Kitura project authors"
  s.module_name  = 'SSLService'
  s.swift_version = '5.1'
  s.requires_arc = true
  s.osx.deployment_target = "10.12"
  s.ios.deployment_target = "10.0"
  s.tvos.deployment_target = "10.0"
  s.source   = { :git => "https://github.com/Kitura/BlueSSLService.git", :tag => s.version }
  s.source_files = "Sources/SSLService/*.swift"
  s.dependency 'BlueSocket', '~> 2.0.0'
  s.pod_target_xcconfig =  {
        'SWIFT_VERSION' => '5.1',
  }
end

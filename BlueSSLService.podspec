Pod::Spec.new do |s|
  s.name        = "BlueSSLService"
  s.version     = "0.12.57"
  s.summary     = "SSL/TLS Add-in framework for BlueSocket in Swift"
  s.homepage    = "https://github.com/IBM-Swift/BlueSSLService"
  s.license     = { :type => "Apache License, Version 2.0" }
  s.author     = "IBM"
  s.module_name  = 'SSLService'

  s.requires_arc = true
  s.osx.deployment_target = "10.11"
  s.ios.deployment_target = "10.0"
  s.tvos.deployment_target = "10.0"
  s.source   = { :git => "https://github.com/IBM-Swift/BlueSSLService.git", :tag => s.version }
  s.source_files = "Sources/SSLService/*.swift"
  s.dependency 'BlueSocket', '~> 0.12.70'
  s.pod_target_xcconfig =  {
        'SWIFT_VERSION' => '3.1.1',
  }
end

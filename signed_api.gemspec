# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'signed_api/version'

Gem::Specification.new do |spec|
  spec.name          = "signed_api"
  spec.version       = SignedApi::VERSION
  spec.authors       = ["ykmr1224"]
  spec.email         = ["ykmr1224@gmail.com"]
  spec.description   = %q{SignedApi gem offers easy way to make your web APIs secure by using secret key based signature authentication.}
  spec.summary       = %q{SignedApi gem offers easy way to make your web APIs secure by using secret key based signature authentication.}
  spec.homepage      = "https://github.com/ykmr1224"
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.3"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"
end

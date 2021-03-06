# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rails_api_authentication/version'

Gem::Specification.new do |spec|
  spec.name          = "rails_api_authentication"
  spec.version       = RailsApiAuthentication::VERSION
  spec.authors       = ["liyijie"]
  spec.email         = ["liyijie825@gmail.com"]

  spec.summary       = %q{Rails API Project Authentication.}
  spec.description   = %q{Rails API Project Authentication.}
  spec.homepage      = "https://git.tallty.com/open-source/rails_api_authentication"
  spec.license       = "MIT"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = "https://git.tallty.com/open-source/rails_api_authentication"
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Object-Hash Mapping for Redis
  # https://github.com/soveran/ohm
  spec.add_dependency "ohm"
  # This is a library generating unique id in short pattern. https://rubygems.org/gems/uuid64
  # https://github.com/heckpsi-lab/uuid64
  spec.add_dependency "uuid64"

  spec.add_development_dependency "bundler", "~> 1.14"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end

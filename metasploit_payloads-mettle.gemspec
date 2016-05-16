# -*- coding:binary -*-
require_relative 'lib/metasploit_payloads/mettle/version'

Gem::Specification.new do |spec|
  spec.name          = 'metasploit_payloads-mettle'
  spec.version       = MetasploitPayloads::Mettle::VERSION
  spec.authors       = ['Adam Cammack', 'Brent Cook']
  spec.email         = ['adam_cammack@rapid7.com', 'brent_cook@rapid7.com']
  spec.description   = %q{Compiled binaries for Metasploit's next-gen Meterpreter}
  spec.summary       = %q{This gem contains the compiled binaries required to make
                        Mettle function, and eventually their stages and stagers}
  spec.homepage      = 'http://www.metasploit.com'
  spec.license       = '3-clause (or "modified") BSD'

  spec.files         = `git ls-files lib/`.split("\n")
  spec.files        += Dir['build/*/bin/mettle']
  spec.files        += Dir['build/*/bin/mettle.bin']
  spec.executables   = []
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.12'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'gem-release'
end

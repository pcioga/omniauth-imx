# frozen_string_literal: true

require_relative 'lib/omniauth/imx/version'

Gem::Specification.new do |spec|
  spec.name = 'omniauth-imx'
  spec.version = Omniauth::Imx::VERSION
  spec.authors = ['Pedro Cioga']
  spec.email = ['pcioga@gmail.com']

  spec.summary = 'IMX OAuth2 Strategy for OmniAuth'
  spec.description = spec.summary
  spec.homepage = "https://github.com/pcioga/omniauth-imx"
  spec.required_ruby_version = '>= 2.6.0'

  spec.metadata['allowed_push_host'] = "TODO: Set to your gem server 'https://example.com'"

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = "https://github.com/pcioga/omniauth-imx"
  #spec.metadata['changelog_uri'] = "TODO: Put your gem's CHANGELOG.md URL here."

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) || f.match(%r{\A(?:bin|test|spec|features|\.git|\.circleci|appveyor|.*\.gem)\z})
    end
  end
  spec.bindir = 'exe'
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'httparty'
  spec.add_dependency 'jwt'
  spec.add_dependency 'omniauth'
  spec.add_dependency 'omniauth-oauth2'
end

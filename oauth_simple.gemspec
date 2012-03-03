# coding: utf-8

require 'rake'

# reference : http://guides.rubygems.org/specification-reference/
Gem::Specification.new do |spec|
  
  # ===============================
  #   Required gemspec attributes
  # ===============================
  spec.name    = 'oauth_simple'
  spec.version = '0.1.0-pre'
  spec.summary = 'Helper for OAuth 1.0'
  spec.files = FileList[
    'README.rdoc',
    'lib/**/*',
    'test/**/*',
    #".document",
    #".gitignore",
    #"LICENSE",
    #"Rakefile",
    #"VERSION",
    #"test/main_test.rb",
    #"test/main_test_1.8.rb",
    #"test/main_test_1.9.rb",
    #"test/test_test.rb"
  ].to_a
  spec.require_paths = [ 'lib' ]
  #platform=
  #rubygems_version
  
  # ===============================
  #   Optional gemspec attributes
  # ===============================
  #  add_development_dependency
  #  add_runtime_dependency
  #  bindir
  #  cert_chain
  #  executables
  #  extensions
  #  extra_rdoc_files
  #  license=
  #  licenses=
  #  post_install_message
  #  rdoc_options
  #  required_ruby_version=
  #  requirements
  #  signing_key
  #  test_files=
  
  # spec.date    = "2011-01-03" # default = "Time.now"
  
  # spec.author
  spec.authors  = [ 'NOBUOKA Yu' ]
  spec.email    = 'nobuoka@vividcode.info'
  #spec.description = "This gem is a one of implementations of W3C DOM." # more detailed than summary
  spec.homepage = 'https://github.com/nobuoka/ruby-OAuthSimple'
  spec.has_rdoc = true
  spec.rdoc_options += [
    '--charset=UTF-8',
    '--main', 'README.rdoc'
  ]
  spec.extra_rdoc_files = [
    'README.rdoc'
    #"LICENSE",
  ]
  spec.test_files = [
    'test/test_main.rb',
    #"test/main_test_1.8.rb",
    #"test/main_test_1.9.rb",
    #"test/test_test.rb"
  ]
  
=begin
  if spec.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    spec.specification_version = 3
    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      spec.add_development_dependency(%q<thoughtbot-shoulda>, [">= 0"])
    else
      spec.add_dependency(%q<thoughtbot-shoulda>, [">= 0"])
    end
  else
    spec.add_dependency(%q<thoughtbot-shoulda>, [">= 0"])
  end
=end
  
end

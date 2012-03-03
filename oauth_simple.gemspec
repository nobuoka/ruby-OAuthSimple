# coding: utf-8

require "rake"

Gem::Specification.new do |spec|
  
  spec.name    = 'oauth-simple'
  spec.version = '0.1.0'
  # spec.date    = "2011-01-03" # default = "Time.now"
  
  spec.authors = [ 'NOBUOKA Yu' ]
  spec.email   = %q{nobuoka@vividcode.info}
  spec.summary = 'OAuth helper'
  #spec.description = "This gem is a one of implementations of W3C DOM." # more detailed than summary
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
  #s.homepage = %q{http://github.com/nobuoka/test}
  spec.has_rdoc = true
  spec.rdoc_options += [
    '--charset=UTF-8',
    '--main', 'README.rdoc'
  ]
  spec.extra_rdoc_files = [
    'README.rdoc'
    #"LICENSE",
  ]
  spec.require_paths = [ 'lib' ]
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

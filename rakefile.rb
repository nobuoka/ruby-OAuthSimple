# coding: UTF-8

require 'rake/testtask'

task :default => [:test]

Rake::TestTask.new do |test|
  # $LOAD_PATH に追加するパス (デフォルトで 'lib' は入っている)
  test.libs << 'test'
  # テスト対象ファイルの指定
  test.test_files = Dir[ 'test/**/test_*.rb' ]
  test.verbose = true
end

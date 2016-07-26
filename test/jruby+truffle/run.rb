$LOAD_PATH.unshift File.expand_path('../../../lib', __FILE__)

require 'argon2'
require 'minitest/autorun'

$LOAD_PATH.unshift File.expand_path('..', __FILE__)

Dir.glob(File.expand_path('../../*_test.rb', __FILE__)).each do|f|
  puts f
  require f
end

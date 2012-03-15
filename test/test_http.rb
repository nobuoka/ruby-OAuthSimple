# coding: UTF-8

require File.expand_path File.join( File.dirname(__FILE__), 'helper_path_setting' )

require 'uri'
require 'minitest/unit'
require 'minitest/autorun'

require 'oauth_simple'
require 'oauth_simple/http'

class TestHttp < MiniTest::Unit::TestCase
  
  # OAuthSimple::HTTP is a subclass of Net::HTTP
  MyHTTP = OAuthSimple::HTTP.create_subclass_with_default_oauth_params()
  MyHTTP.set_default_oauth_client_credentials( 'key', 'secret' )
  #MyHTTP.set_default_oauth_user_credentials( key, secret )
  MyHTTP.set_default_signature_method( 'HMAC-SHA1' )
  
  ###
  # test by using OAuth Test Server : http://term.ie/oauth/example/
  def test_getting_request_token
    
    http = MyHTTP.new( 'term.ie' )
    # connection start
    http.start() do |http|
      assert_equal( http.class, MyHTTP )
      http.request_post( '/oauth/example/request_token.php', nil ) do |res|
        assert_equal( '200', res.code )
        assert_equal( 'oauth_token=requestkey&oauth_token_secret=requestsecret', res.body )
      end
      
      token, secret = http.request_oauth_temp_credentials( '/oauth/example/request_token.php', 'oob' )
      assert_equal( 'requestkey'   , token  )
      assert_equal( 'requestsecret', secret )
    end
  end
  
end

__END__

assert( .... )

# coding: UTF-8

require File.expand_path File.join( File.dirname(__FILE__), 'helper_path_setting' )

require 'uri'
require 'minitest/unit'
require 'minitest/autorun'
require 'webrick'

require 'oauth_simple'
require 'oauth_simple/http'

class TestLocalHttp < MiniTest::Unit::TestCase

  # OAuthSimple::HTTP is a subclass of Net::HTTP
  MyHTTP = OAuthSimple::HTTP.create_subclass_with_default_oauth_params()
  MyHTTP.set_default_oauth_client_credentials( '775f44e3e40459a8', '8f6fbb343c4a45c3f69594c7b943' )
  #MyHTTP.set_default_oauth_user_credentials( key, secret )
  MyHTTP.set_default_oauth_signature_method( 'HMAC-SHA1' )

  ###
  # test by using OAuth Test Server : http://oauth-sandbox.sevengoslings.net/
  #   Request Token URL     : http://oauth-sandbox.sevengoslings.net/request_token
  #   User Authorization URL: http://oauth-sandbox.sevengoslings.net/authorize
  #   Access Token URL      : http://oauth-sandbox.sevengoslings.net/access_token 
  def test_getting_request_token
    m = Mutex.new
    state = nil
    test_thread = Thread.current
    server_thread = nil
    server = WEBrick::HTTPServer.new( BindAddress: '127.0.0.1', Port: '10080', ServerType: Thread,
       StartCallback: ->(){
          #$stderr << "[DEBUG] start!!!!\n"
          m.synchronize {
            if state == :waiting_startup
              server_thread = Thread.current
              test_thread.wakeup
            end
          }
    #}, StopCallback: ->() {
          #$stderr << "[DEBUG] stop!!!!\n"
    } )
    server.mount_proc( '/' ) do |req,res|
      begin
        p req.body
      rescue => err
        puts err.backtrace
      end
      res.body = 'test'
      assert "server ok"
    end
    server.start

    m.synchronize {
      state = :waiting_startup
    }
    sleep 5
    m.synchronize {
      raise 'server not started' if server_thread.nil?
      state = nil
    }
    $stderr << "[DEBUG] test test\n"
    begin
      http = MyHTTP.new( '127.0.0.1', '10080' )
      # connection start
      http.start() do |http|
        assert_equal( http.class, MyHTTP )
        http.request_post( '/request_token', '' ) do |res|
          assert_equal( '200', res.code )
        end
      end
    rescue
      $stderr << "failed test...\n"
    else
      assert "client ok"
    end

    server.shutdown
    server_thread.join
=begin
    http = MyHTTP.new( 'oauth-sandbox.sevengoslings.net' )
    # connection start
    http.start() do |http|
      assert_equal( http.class, MyHTTP )
      http.request_post( '/request_token', nil ) do |res|
        assert_equal( '200', res.code )
        #assert_equal( 'oauth_token=requestkey&oauth_token_secret=requestsecret', res.body )
      end

      #token, secret = http.request_oauth_temp_credentials( '/oauth/example/request_token.php', 'oob' )
      #assert_equal( 'requestkey'   , token  )
      #assert_equal( 'requestsecret', secret )
    end
=end
  end

end

__END__

assert( .... )

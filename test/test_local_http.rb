# coding: UTF-8

require File.expand_path File.join( File.dirname(__FILE__), 'helper_path_setting' )

require 'uri'
require 'minitest/unit'
require 'minitest/autorun'
require 'webrick'

require 'oauth_simple'
require 'oauth_simple/http'

class TestLocalHttp < MiniTest::Unit::TestCase

  def do_test_with_webrick_server( server_proc, client_proc, opts = {} )
    opts = { Port: '10080' }.merge opts

    m = Mutex.new
    state = nil
    test_thread = Thread.current
    server_thread = nil
    server_errors = []
    server = WEBrick::HTTPServer.new( BindAddress: '127.0.0.1', Port: opts[:Port],
        ServerType: Thread,
        StartCallback: ->(){
          m.synchronize {
            if state == :waiting_startup
              server_thread = Thread.current
              test_thread.wakeup
            else
              server.shutdown
            end
          }
        } )
    server.mount_proc( '/' ) do |req,res|
      begin
        server_proc.call( req, res )
      rescue Object => err
        server_errors << err
        raise
      end
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

    begin
      client_proc.call
    ensure
      server.shutdown
      server_thread.join
    end
    if not server_errors.empty?
      server_errors.each do |err|
        raise err
      end
    end

  end

  # signature 'DLzSR6NYLv5a3wk4%2BGEjpYS8IQY%3D'
  module OAuthSimple::HelperFunctions
    def create_nonce_str # overwrite for test
      'gV5JSqJR8m9xzYR3'
    end
    def create_timestamp_str # overwrite for test
      '1338567554'
    end
  end

  def test_1
    # OAuthSimple::HTTP is a subclass of Net::HTTP
    http_class = OAuthSimple::HTTP.create_subclass_with_default_oauth_params()
    http_class.set_default_oauth_client_credentials( 'MyKey', 'MySecret' )
    #http_class.set_default_oauth_user_credentials( key, secret )
    http_class.set_default_oauth_signature_method( 'HMAC-SHA1' )

    port = '10080'
    server_proc = ->(req,res) {
      assert req.header.has_key?( 'authorization' ), 'has key Authrization'
      auth_header_str = req['authorization'].gsub( /\AOAuth\s+/, '' )
      vv = auth_header_str.split( /,\s*/ )
      kv_map = {}
      vv.each do |v|
        kv_pair = v.split( /=/, 2 )
        kv_map[kv_pair[0]] = kv_pair[1]
      end
      assert_equal kv_map['oauth_signature'], '"DLzSR6NYLv5a3wk4%2BGEjpYS8IQY%3D"'
    }
    client_proc = ->() {
      http = http_class.new( '127.0.0.1', port )
      # connection start
      http.start() do |http|
        http.request_post( '/request_token', '' ) do |res|
          assert_equal( '200', res.code )
        end
      end
    }
    do_test_with_webrick_server( server_proc, client_proc, Port: port )
    assert true, 'dame-'
  end

end

__END__

assert( .... )

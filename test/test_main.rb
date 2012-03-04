# coding: UTF-8

require 'uri'
require 'test/unit'

$LOAD_PATH.unshift File.dirname(__FILE__)
$LOAD_PATH.unshift File.join( File.dirname(__FILE__), "..", "lib" )
require 'oauth_simple'
require 'oauth_simple/http'

class TestMain < Test::Unit::TestCase
  
  def test_sign_simple
    base_str   = 'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal'
    secret_str = 'kd94hf93k423kf44&pfkkdhi9sl3r4s00'
    signature  = 'tR3+Ty81lMeYAr/Fid0kMTYa/WM='
    digest = OpenSSL::HMAC::digest( OpenSSL::Digest::SHA1.new(), secret_str, base_str )
    assert_equal( signature, [digest].pack('m').gsub!( /\n/u, '' ) )
    base_str   = 'POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7'
    secret_str = 'j49sk3j29djd&dh893hdasih9'
    signature  = 'r6%2FTJjbCOr97%2F%2BUU0NsvSne7s5g%3D'
    digest = OpenSSL::HMAC::digest( OpenSSL::Digest::SHA1.new(), secret_str, base_str )
    assert_equal( signature, OAuthSimple::HelperFunctions.enc_perenc( [digest].pack('m').gsub!( /\n/u, '' ) ) )
  end
  
  def test_nonce_string_creation
    # 引数を与えなければ, 16 文字の文字列
    nonce_str = OAuthSimple::HelperFunctions.create_nonce_str()
    assert_equal( nonce_str.class, String )
    assert_equal( nonce_str.length, 16 )
    # 0 以上の整数を引数として与えると, その長さの文字列
    [ 20, 0, 300, 432, 125432 ].each do |len|
      nonce_str = OAuthSimple::HelperFunctions.create_nonce_str( len )
      assert_equal( nonce_str.class,  String )
      assert_equal( nonce_str.length, len )
    end
  end
  
  def test_helper
    req_helper = OAuthSimple::RequestHelper.new(
      URI.parse( 'https://api.twitter.com/oauth/request_token' ),
      'POST',
      'CONS_SECRET_XXXX&',
      OAuthSimple::RequestParamList.new( [
        # TwitVC
        [ 'oauth_consumer_key',     'CONS_KEY_XXXX'         ],
        [ 'oauth_signature_method', 'HMAC-SHA1'             ],
        [ 'oauth_timestamp',        ( Time.now() - Time.utc( 1970, 1, 1 ) ).to_i().to_s() ],
        [ 'oauth_nonce',            'dfaeaveafefea'         ],
        [ 'oauth_version',          '1.0'                   ],
      ] ),
    )
    assert_equal( req_helper.host, 'api.twitter.com' )
    assert_equal( req_helper.port, 443               )
  end
  
  # RFC5849 Sec. 3.1 の試験
  # http://tools.ietf.org/html/rfc5849
  # 
  #   POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
  #   Host: example.com
  #   Content-Type: application/x-www-form-urlencoded
  #   
  #   c2&a3=2+q
  # 
  # The client assigns values to the following protocol parameters using
  # its client credentials, token credentials, the current timestamp, a
  # uniquely generated nonce, and indicates that it will use the
  # "HMAC-SHA1" signature method:
  #  oauth_consumer_key:     9djdj82h48djs9d2
  #  oauth_token:            kkk9d7dh3k39sjv7
  #  oauth_signature_method: HMAC-SHA1
  #  oauth_timestamp:        137131201
  #  oauth_nonce:            7d8f3e4a
  def test_sign
    client_secret = 'j49sk3j29djd'
    token_secret  = 'dh893hdasih9'
    req_helper = OAuthSimple::RequestHelper.new(
      URI.parse( 'http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b' ),
      'POST',
      "#{client_secret}&#{token_secret}",
      OAuthSimple::RequestParamList.new( [
        [ 'oauth_consumer_key',     '9djdj82h48djs9d2' ],
        [ 'oauth_token',            'kkk9d7dh3k39sjv7' ],
        [ 'oauth_signature_method', 'HMAC-SHA1'        ],
        [ 'oauth_timestamp',        '137131201'        ],
        [ 'oauth_nonce',            '7d8f3e4a'         ],
      ] ),
      nil,
      OAuthSimple::RequestParamList.new( [
        [ 'c2', nil   ],
        [ 'a3', '2 q' ],
      ] ),
    )
    #p req_helper.oauth_header_str
  end
  
  def test_factory
    rhf = OAuthSimple::RequestHelperFactory.new(
      :consumer_key     => '9djdj82h48djs9d2',
      :consumer_secret  => 'j49sk3j29djd'    ,
      :token            => 'kkk9d7dh3k39sjv7',
      :token_secret     => 'dh893hdasih9'    ,
      :signature_method => 'HMAC-SHA1'       ,
    )
    req_helper = rhf.create(
      URI.parse( 'http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b' ),
      'POST',
      :body_params => OAuthSimple::RequestParamList.new( [
        [ 'c2', nil   ],
        [ 'a3', '2 q' ],
      ] )
    )
    assert_equal( req_helper.class, OAuthSimple::RequestHelper )
    #p req_helper.oauth_header_str
  end
  
  ###
  # test by using OAuth Test Server : http://term.ie/oauth/example/
  def test_getting_request_token
    # OAuthSimple::HTTP is a subclass of Net::HTTP
    http = OAuthSimple::HTTP.new( 'term.ie' )
    
    # OAuth setting (this feature provided by OAuthSimple::HTTP)
    http.use_oauth = true
    http.set_oauth_client_credentials( 'key', 'secret' )
    http.set_oauth_signature_method( 'HMAC-SHA1' ) # at this time, only 'HMAC-SHA1' is supported
    
    # connection start
    http.start() do |http|
      assert_equal( http.class, OAuthSimple::HTTP )
      http.request_post( '/oauth/example/request_token.php', nil ) do |res|
        assert_equal( '200', res.code )
        assert_equal( 'oauth_token=requestkey&oauth_token_secret=requestsecret', res.body )
      end
      
      token, secret = http.request_oauth_temp_credentials( '/oauth/example/request_token.php', 'oob' )
    end
  end
  
end

__END__

assert( .... )

# coding: UTF-8

require 'uri'
require 'test/unit'

$LOAD_PATH.unshift File.dirname(__FILE__)
$LOAD_PATH.unshift File.join( File.dirname(__FILE__), "..", "lib" )
require 'oauth_simple'

class TestMain < Test::Unit::TestCase
  
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
  
end

__END__

assert( .... )

require 'uri'
require 'net/http'

# 送信先 URL
url = 'https://api.twitter.com/oauth/request_token'
# リクエストメソッド
method = 'POST'
# Consumer key と secret
consumer_key    = "XXXXXXXXXX"
consumer_secret = "XXXXXXXXXX"
# 今回は request token を求める例で token secret はないので空文字列
token_secret = ''
# secrets 文字列 (Consumer secret と token secret を繋いだもの)
secrets = consumer_secret + '&' + token_secret
# OAuth 関係のパラメータ
oauth_param_list = OAuthRequestHelper::ParamList.new(
  [
    [ 'oauth_consumer_key',     consumer_key ],
    [ 'oauth_nonce',            OAuthRequestHelper.get_nonce_string() ],
    [ 'oauth_signature_method', 'HMAC-SHA1' ],
    [ 'oauth_timestamp',        Long.toString( new Date().getTime() / 1000 ) ],
    [ 'oauth_version',          '1.0' ],
    [ 'oauth_callback',         'oob' ],
  ] )
# OAuthRequestHelper のインスタンス化
# 今回はクエリパラメータにもリクエストボディにも情報を載せないので, 後ろ 2 つの引数は null
req_helper = OAuthRequestHelper.new( url, method, secrets, oauth_param_list, nil, nil )
# インスタンス化と同時にシグニチャ生成もされるので, あとは helper から情報を取って
# リクエストを送信するだけ


Net::HTTP.start( req_helper.host, req_helper.port ) do |http|
  # -- GET --
  # OAuth ヘッダに追加
  http.get( req_helper.req_path, { 'OAuth' => req_helper.get_oauth_header() } )
  # query に追加
  http.get( req_helper.req_path_with_oauth_param )
  # -- POST --
  # OAuth ヘッダに追加
  http.post( req_helper.req_path, req_helper.req_body,
      { 'OAuth' => req_helper.get_oauth_header() } )
end

# coding : utf-8

require 'net/http'
require 'oauth_simple/helper_functions'
require 'oauth_simple/request_param_list'

module OAuthSimple
class HTTP < Net::HTTP
  
  include HelperFunctions
  
  # @consumer_key
  # @token
  # @signature_method
  # (timestamp, nonce, version)
  #    -> signature
  # 
  # @consumer_secret
  # @token_secret
  
  ###
  # Override
  # Net::HTTP#transport_request をオーバーライド
  def transport_request( req )
    if use_oauth?
      req_method = req.method.upcase
      uri_str_scheme = use_ssl? ? 'https' : 'http'
      uri_str_host   = addr_port.downcase # デフォルトでない場合ポート番号含む
      # TODO: path 中の '#' はどのように扱われるべき?
      qpath, uri_str_fragment = req.path.split( '#', 2 )
      uri_str_path, query_str = qpath.split( '?', 2 )
      # OAuth Header (基本的には自分で用意)
      #req.get_fields( 'Authorization' )
      # ...
      # body  parameters (必要な場合だけ)
      #  Protocol parameters can be transmitted in the HTTP request entity-
      #  body, but only if the following REQUIRED conditions are met:
      #   o  The entity-body is single-part.
      #   o  The entity-body follows the encoding requirements of the
      #      "application/x-www-form-urlencoded" content-type as defined by
      #      [W3C.REC-html40-19980424].
      #   o  The HTTP request entity-header includes the "Content-Type" header
      #      field set to "application/x-www-form-urlencoded".
      body_str = nil
      if req.request_body_permitted?
        content_type = req.content_type || 'application/x-www-form-urlencoded'
        if content_type == 'application/x-www-form-urlencoded'
          body_str = req.body
        end
      end
      
      secret_str = [ @consumer_secret, @token_secret ].
          map {|e| e.nil? ? '' : enc_perenc( @consumer_secret ) }.join( '&' )
      
      # for debug
      #puts "request method - #{req_method}"
      #puts "http or https  - #{uri_str_scheme}"
      #puts "host[:port]    - #{uri_str_host}"
      #puts "path           - #{uri_str_path}"
      #puts "query str      - #{query_str.nil? ? '<nil>' : query_str}"
      #puts "body str       - #{body_str.nil? ? '<nil>' : body_str}"
      
      p_params = RequestParamList.new()
      p_params.add( 'oauth_consumer_key'      , @consumer_key          ) if @consumer_key
      p_params.add( 'oauth_token'             , @token                 ) if @token
      p_params.add( 'oauth_signature_method'  , @signature_method      ) if @signature_method
      p_params.add( 'oauth_timestamp'         , create_timestamp_str() )
      p_params.add( 'oauth_nonce'             , create_nonce_str()     )
      p_params.add( 'oauth_version'           , '1.0' )
      
      param_list = RequestParamList.new()
      param_list.concat p_params
      param_list.concat RequestParamList.from_percent_encoded_str query_str if query_str
      param_list.concat RequestParamList.from_percent_encoded_str body_str  if body_str
      
      # signature の計算
      uri_str = "#{uri_str_scheme}://#{uri_str_host}#{uri_str_path}"
      signature = calc_signature( req_method, uri_str, param_list, secret_str )
      
      # Authorization Header (TODO: add another way)
      p_params.add( 'oauth_signature', signature )
      req.add_field( 'Authorization', 'OAuth ' + p_params.to_header_string() )
    end
    return super # 引数, block をそのまま継承先へ渡す
  end
  
  def use_oauth=( val )
    @use_oauth = val
  end
  
  def use_oauth?
    @use_oauth
  end
  
  def set_oauth_client_credentials( key, secret )
    @consumer_key    = key
    @consumer_secret = secret
  end
  
  def set_oauth_user_credentials( token, secret )
    @token        = token
    @token_secret = secret
  end
  
  def set_oauth_signature_method( sigmet )
    @signature_method = sigmet
  end
  
end
end

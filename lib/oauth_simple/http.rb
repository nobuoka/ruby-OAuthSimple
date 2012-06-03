# coding : utf-8

require 'net/http'
require 'oauth_simple/helper_functions'
require 'oauth_simple/request_param_list'

module OAuthSimple

###
# Subclass of Net::HTTP, which has feature of OAuth authentication
class HTTP < Net::HTTP

  include HelperFunctions

  module DefaultOAuthParamSettable
    def set_default_oauth_client_credentials( key, secret )
      @client_credentials = [ key, secret ]
    end

    def set_default_oauth_user_credentials( key, secret )
      @user_credentials = [ key, secret ]
    end

    def set_default_oauth_signature_method( sig_met )
      @signature_method = sig_met
    end

    def set_default_oauth_params_location( location )
      @oauth_params_location = location
    end

    def get_default_params
      params = {}
      params[:oauth_client_credentials] = @client_credentials if @client_credentials
      params[:oauth_user_credentials  ] = @user_credentials   if @user_credentials
      params[:signature_method        ] = @signature_method   if @signature_method
      params[:oauth_params_location   ] = @oauth_params_location if @oauth_params_location
      return params
    end
  end

  # :stopdoc:
  # 空のハッシュを表す定数
  EMPTY_HASH = {}.freeze
  # :startdoc:

  def initialize( *args )
    super
    self.set_oauth_params_location( LOC_AUTHORIZATION_HEADER )
  end

  def self.create_subclass_with_default_oauth_params( oauth_params = EMPTY_HASH )
    klass = Class.new( self ) do
      def initialize( *args )
        super
        default_params = self.class.get_default_params
        self.use_oauth = true
        if default_params.has_key? :oauth_client_credentials
          self.set_oauth_client_credentials( *default_params[:oauth_client_credentials] )
        end
        if default_params.has_key? :oauth_user_credentials
          self.set_oauth_user_credentials( *default_params[:oauth_user_credentials] )
        end
        if default_params.has_key? :signature_method
          # at this time, only 'HMAC-SHA1' is supported
          self.set_oauth_signature_method( default_params[:signature_method] )
        end
        if default_params.has_key? :oauth_params_location
          self.set_oauth_params_location( default_params[:oauth_params_location] )
        end
      end
    end
    klass.extend DefaultOAuthParamSettable
    # TODO oauth_params で渡されたパラメータをここでセット
    #
    return klass
  end

  # @consumer_key
  # @token
  # @signature_method
  # (timestamp, nonce, version)
  #    -> signature
  # 
  # @consumer_secret
  # @token_secret

  ###
  # Override: Net::HTTP#transport_request
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
      body_str = nil # body_str は req body に oauth パラメータを追加できる場合には nil でない
      if req.request_body_permitted?
        content_type = req.content_type || 'application/x-www-form-urlencoded'
        if content_type == 'application/x-www-form-urlencoded'
          body_str = req.body
        end
      end

      secret_str = [ @oauth_consumer_secret, @oauth_token_secret ].
                   map {|e| e.nil? ? '' : enc_perenc( e ) }.
                   join( '&' )

      # for debug
      #puts "request method - #{req_method    }"
      #puts "http or https  - #{uri_str_scheme}"
      #puts "host[:port]    - #{uri_str_host  }"
      #puts "path           - #{uri_str_path  }"
      #puts "query str      - #{query_str.nil? ? '<nil>' : query_str}"
      #puts "body str       - #{body_str.nil?  ? '<nil>' : body_str }"

      p_params = RequestParamList.new()
      {
        'oauth_consumer_key'     => @oauth_consumer_key,
        'oauth_token'            => @oauth_token,
        'oauth_signature_method' => @oauth_signature_method,
      }.each_pair{|k,v| p_params.add( k, v ) if v }
      p_params.add( 'oauth_timestamp'       , create_timestamp_str() )
      p_params.add( 'oauth_nonce'           , create_nonce_str()     )
      p_params.add( 'oauth_version'         , '1.0'                  )
      if req.respond_to? :oauth_params
        req.oauth_params.each_pair do |key,value|
          p_params.add( key, value )
        end
      end

      param_list = RequestParamList.new()
      param_list.concat p_params
      if query_str
        q_params = RequestParamList.from_percent_encoded_str query_str
        param_list.concat q_params
      end
      if body_str
        b_params = RequestParamList.from_percent_encoded_str body_str
        param_list.concat b_params
      end

      # signature の計算
      uri_str = "#{uri_str_scheme}://#{uri_str_host}#{uri_str_path}"
      signature = calc_signature( req_method, uri_str, param_list, secret_str )

      p_params.add( 'oauth_signature', signature )
      if @oauth_params_loc == LOC_AUTHORIZATION_HEADER
        # Authorization Header
        req.add_field( 'Authorization', 'OAuth ' + p_params.to_header_string() )
      elsif @oauth_params_loc == LOC_REQBODY_OR_REQQUERY and body_str
        req.body = b_params.concat( p_params ).to_query_string
      else
        new_query_str = ( q_params ? q_params.concat( p_params ) : p_params ).to_query_string
        qpath, uri_str_fragment = req.path.split( '#', 2 )
        req.path[0..-1] = [ [ uri_str_path, new_query_str ].join( '?' ), uri_str_fragment ].join( '#' )
      end
    end
    return super # 引数, block をそのまま継承先へ渡す
  end

  def use_oauth=( val )
    @use_oauth = !!val
  end

  def use_oauth?
    @use_oauth
  end

  def set_oauth_client_credentials( key, secret )
    @oauth_consumer_key    = key
    @oauth_consumer_secret = secret
  end

  def set_oauth_user_credentials( token, secret )
    @oauth_token        = token
    @oauth_token_secret = secret
  end

  def set_oauth_signature_method( sigmet )
    if sigmet != 'HMAC-SHA1'
      raise %q{at this time, only 'HMAC-SHA1' is supported}
    end
    @oauth_signature_method = sigmet
  end

  LOC_AUTHORIZATION_HEADER = :auth_header
  LOC_REQBODY_OR_REQQUERY = :reqbody_or_reqquery
  LOC_REQQUERY = :reqquery
  def set_oauth_params_location( location )
    @oauth_params_loc = location
  end

  # TODO: POST メソッド以外も使えるように
  def request_oauth_temp_credentials( path, oauth_callback_uri, &block )
    req = Post.new( path )
    req.set_oauth_param( 'oauth_callback', oauth_callback_uri )
    token  = nil
    secret = nil
    request( req ) do |res|
      if res.code == '200'
         params = RequestParamList.from_percent_encoded_str res.body
         token  = params.get_values( 'oauth_token' )[0]
         secret = params.get_values( 'oauth_token_secret' )[0]
      else
        if block
          block.call res
        else
          raise 'error' # TODO
        end
      end
    end

    # Set credentials automatically
    set_oauth_user_credentials( token, secret )
    return token, secret
  end

  # TODO: POST メソッド以外も使えるように
  def request_oauth_token_credentials( path, oauth_verifier, &block )
    req = Post.new( path )
    req.set_oauth_param( 'oauth_verifier', oauth_verifier )
    token  = nil
    secret = nil
    request( req ) do |res|
      if res.code == '200'
         params = RequestParamList.from_percent_encoded_str res.body
         token  = params.get_values( 'oauth_token' )[0]
         secret = params.get_values( 'oauth_token_secret' )[0]
      else
        if block
          block.call res
        else
          raise 'error'
        end
      end
    end
    set_oauth_user_credentials( token, secret )
    return token, secret
  end

  module OAuthParamsHandler
    def set_oauth_param( name, value )
      # TODO: name must start with 'oauth_'
      @oauth_params ||= {}
      @oauth_params[ name ] = value
    end
    def get_oauth_param( name )
      ( @oauth_params || {} )[ name ]
    end
    def oauth_params
      @oauth_params || {}
    end
  end

  class Get < Net::HTTP::Get
    include OAuthParamsHandler
  end
  class Post < Net::HTTP::Post
    include OAuthParamsHandler
  end

end
end

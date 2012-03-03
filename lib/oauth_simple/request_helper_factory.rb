# coding : utf-8

require 'oauth_simple/helper_functions'

module OAuthSimple
class RequestHelperFactory
  
  include HelperFunctions
  
  ###
  #     consumer_secret
  #     oauth_consumer_key
  #     oauth_token
  #       clients MAY omit the parameter.
  #     oauth_signature_method
  #     oauth_timestamp
  #       MAY be omitted when using the "PLAINTEXT" signature method.
  #     oauth_nonce
  #       MAY be omitted when using the "PLAINTEXT" signature method.
  #     oauth_version
  #       OPTIONAL.  If present, MUST be set to "1.0". 
  # :consumer_key, :consumer_secret, :token, :token_secret, :signature_method
  # :use_default_timestamp, :use_default_nonce, :use_default_version
  def initialize( args )
    args = {
      :use_default_timestamp => true,
      :use_default_nonce     => true,
      :use_default_version   => true,
    }.merge args
    # String object or nil
    @consumer_key          = args.delete( :consumer_key          )
    @consumer_secret       = args.delete( :consumer_secret       )
    @token                 = args.delete( :token                 )
    @token_secret          = args.delete( :token_secret          )
    @signature_method      = args.delete( :signature_method      )
    # boolean
    @use_default_timestamp = args.delete( :use_default_timestamp )
    @use_default_nonce     = args.delete( :use_default_nonce     )
    @use_default_version   = args.delete( :use_default_version   )
    # TODO: args に key が残っている場合, 警告を表示
  end
  
  ###
  # create RequestHelper object
  def create( req_uri, req_method, option_params )
    # secret_str 生成
    cons_sec = option_params[:consumer_secret] || @consumer_secret
    tokn_sec = option_params[:token_secret   ] || @token_secret
    secret_str = "#{cons_sec}&#{tokn_sec}"
    
    # protocol params
    p_params = RequestParamList.new()
    p_params.add( 'oauth_consumer_key'    , @consumer_key          ) if @consumer_key
    p_params.add( 'oauth_token'           , @token                 ) if @token
    p_params.add( 'oauth_signature_method', @signature_method      ) if @signature_method
    p_params.add( 'oauth_timestamp'       , create_timestamp_str() ) if @use_default_timestamp
    p_params.add( 'oauth_nonce'           , create_nonce_str()     ) if @use_default_nonce
    p_params.add( 'oauth_version'         , '1.0'                  ) if @use_default_version
    p_params2 = option_params.delete( :protocol_params )
    p_params.concat p_params2 if p_params2
    
    # query_params and body_params
    q_params = option_params.delete( :query_params )
    b_params = option_params.delete( :body_params  )
    
    # RequestHelper object 生成
    RequestHelper.new( req_uri, req_method, secret_str, p_params, q_params, b_params )
  end
  
end
end

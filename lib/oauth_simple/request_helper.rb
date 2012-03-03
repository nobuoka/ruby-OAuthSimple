# coding : utf-8

require 'oauth_simple/helper_functions'

module OAuthSimple
class RequestHelper
  
  include HelperFunctions
  
  ###
  # req_uri    : URI or String object
  # req_method : String
  def initialize( req_uri, req_method, oauth_secret, protocol_params, query_params = nil, body_params = nil )
    # URI
    @req_uri    = req_uri # 後ろの処理で query は nil になる
    # String or Symbol?
    @req_method = req_method
    # String or Symbol?
    @sig_method = nil
    # String
    @secret_str = oauth_secret
    # RequestParamList 
    @p_params = protocol_params
    # RequestParamList or nil
    q_params_list = []
    if @req_uri.query
      q_params_list << RequestParamList.from_percent_encoded_str( @req_uri.query )
      @req_uri.query = nil
    end
    if query_params
      q_params_list << q_params_list
    end
    @q_params = q_params_list.empty? ? nil : q_params_list.inject{|a,b| a.concat b}
    # RequestParamList or nil
    @b_params = body_params
    
    params = RequestParamList.new()
    params.concat @p_params
    params.concat @q_params if @q_params
    params.concat @b_params if @b_params
    
    # URI の処理
    #   The scheme, authority, and path of the request resource URI [RFC3986]
    #   are included by constructing an "http" or "https" URI representing
    #   the request resource (without the query or fragment) as follows:
    # 1.  The scheme and host MUST be in lowercase.
    uri_str = ''
    # scheme
    uri_str << @req_uri.scheme.downcase
    uri_str << '://'
    uri_str << @req_uri.host.downcase
    # 3.  The port MUST be included if it is not the default port for the
    #   scheme, and MUST be excluded if it is the default.  Specifically,
    #   the port MUST be excluded when making an HTTP request [RFC2616]
    #   to port 80 or when making an HTTPS request [RFC2818] to port 443.
    #   All other non-default port numbers MUST be included.
    if @req_uri.port != @req_uri.default_port
      uri_str << ":#{@req_uri.port}"
    end
    uri_str << @req_uri.path
    
    @p_params.add( 'oauth_signature', calc_signature( req_method, uri_str, params, @secret_str ) )
  end
  
  def host
    @req_uri.host
  end
  
  def port
    @req_uri.port
  end
  
  def request_method
    @req_method
  end
  
  ###
  # path + '?' + query
  def qpath
    @req_uri.path
  end
  
  def qpath_with_oauth_params
    
  end
  
  def req_body
  end
  
  def req_body_with_oauth_params
  end
  
  def oauth_header_str( realm_str = nil )
    'OAuth ' + @p_params.to_header_string()
  end
  
end
end

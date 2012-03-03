# coding : utf-8

require 'oauth_simple/helper_functions'

module OAuthSimple
class RequestParamList
  
  include HelperFunctions
  
  def initialize( arg = Array.new() )
    if ( arg.is_a? Array ) then
      arg.each do |item|
        if not item.is_a?( Array ) or item.length != 2 or not item[0].is_a?( String ) or not ( item[1].is_a?( String ) or item[1].nil? ) then
          raise "引数として与えられた Array が正しい形式ではありません. 引数として与えられた Array オブジェクトの各要素は, String オブジェクト 2 つからなる Array オブジェクトである必要があります"
        end
      end
      @list = arg
    elsif ( arg.is_a? Hash ) then
      @list = Array.new()
      arg.each do |key,val|
        @list.push( [key, val] )
      end
    elsif ( arg.is_a? String ) then
      @list = Array.new()
      if ( /%(?![a-fA-F\d]{2})/u =~ arg ) then
        # OAuth の仕様どおりではないが, URL エンコードの形式ならば受け付ける
        raise "引数として与えられた String オブジェクトが正しく encode されたものではありません"
      end
      param_list = arg.split( /&/u )
      param_list.each do |item|
        if ( item.nil? || item == "" ) then
          next
        end
        pair = item.split( /=/u )
        @list.push( [decode( pair[0] ), decode( pair[1].to_s() )] )
      end
    else
      raise "型エラー : ParameterList の初期化時に与えることができる引数の型は Array と String のみです"
    end
  end
  
  def self.from_percent_encoded_str( str )
    # HelperFunctions モジュールで定義されている... 関数呼び出しにはできない?
    new HelperFunctions.decode_from_percent_encoded_str( str )
  end
  
  public
  def +( other )
    return ParameterList.new( self.get_list() + other.get_list() )
  end
  
  def concat( other )
    @list.concat( other.get_list() )
    return self
  end
  
  def add( name, value )
    @list.push( [name, value] )
    return nil
  end
  
  def get_values( name )
    res_list = Array.new()
    @list.each do |item|
      if ( item[0] == name ) then
        res_list.push( item[1] )
      end
    end
    return res_list
  end
  
  alias :[] :get_values
  
  def each()
    @list.each do |item|
      yield( item[0], item[1] )
    end
  end
  
  def to_header_string()
    #list = get_sorted_list()
    sb_str = String.new()
    @list.each do |item|
      if ( sb_str != "" ) then
        sb_str << ", "
      end
      sb_str << enc_perenc( item[0] ) << '="' << enc_perenc( item[1] ) << '"'
    end
    return sb_str
  end
  
  def to_query_string()
    list = get_sorted_list()
    sb_str = String.new()
    list.each do |item|
      if ( sb_str != "" ) then
        sb_str << "&"
      end
      sb_str << encode( item[0] ) << "=" << encode( item[1] )
    end
    return sb_str
  end
  
=begin
  def to_signature_string( method, url, key )
    list = get_sorted_list()
    sb_str = String.new()
    list.each do |item|
      if ( sb_str != "" ) then
        sb_str << "&"
      end
      sb_str << encode( item[0] ) << "=" << encode( item[1] )
    end
    base_string = encode( method ) + "&" + encode( url ) + "&" + encode( sb_str )
    digest = OpenSSL::HMAC::digest( OpenSSL::Digest::SHA1.new(), key, base_string )
    sig = [digest].pack("m").gsub!( /\n/u, "" )
    return sig
  end
=end
  
  protected
  def get_list()
    return @list
  end
  
  public
  # http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
  def get_normalized_params_str()
    @list.
      map do |e|
        [ enc_perenc( e[0] ), e[1] ? enc_perenc( e[1] ) : '' ]
      end.
      sort do |a,b|
        case a[0] <=> b[0]
          when  1 then rel =  1
          when -1 then rel = -1
          when  0 then rel = a[1] <=> b[1]
        end
      end.
      map{ |e| "#{e[0]}=#{e[1]}" }.
      join( '&' )
  end
  
end
end

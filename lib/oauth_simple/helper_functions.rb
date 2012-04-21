# coding : utf-8

require 'openssl'

module OAuthSimple
module HelperFunctions
  
  # ====================
  #   MODULE FUNCTIONS
  # ====================
  module_function
  
  # nonce 用にランダムに文字列生成するメソッド
  NONCE_STRING_SOURCE = ('a'..'z').to_a() + ('A'..'Z').to_a() + ('0'..'9').to_a()
  def create_nonce_str( length = 16 )
    Array.new( length ).map{ NONCE_STRING_SOURCE[rand(NONCE_STRING_SOURCE.size)] }.join('')
  end
  
  def create_timestamp_str( time = Time.now )
    ( time - Time.utc( 1970, 1, 1 ) ).to_i().to_s()
  end
  
  def calc_signature( method, uri_str, param_list, secret_str )
    params_str = param_list.get_normalized_params_str()
    #sb_str = String.new()
    #list.each do |item|
    #  if ( sb_str != "" ) then
    #    sb_str << "&"
    #  end
    #  sb_str << encode( item[0] ) << "=" << encode( item[1] )
    #end
    base_str = [ method, uri_str, params_str ].map{ |e| enc_perenc(e) }.join('&')
    digest = OpenSSL::HMAC::digest( OpenSSL::Digest::SHA1.new(), secret_str, base_str )
    return [digest].pack('m').gsub!( /\n/u, '' )
  end
  
  # param  : String
  # return : [ [ String, String or nil ], ... ]
  def decode_from_percent_encoded_str( str )
    str.split( '&', -1 ).map! do |s|
      if s.empty?
        [ '', nil ]
      else
        pair = s.split( '=', -1 ).map!{ |s| dec_perenc( s ) }
        # TODO: pair の要素数は 1 以上 2 以下 ('=' がない場合など, 1 個だけの場合もある)
        [ pair[0], pair[1] ]
      end
    end
  end
  
  # param  : [ [ String, String or nil ], ... ]
  # return : String
  def encode_to_percent_encoded_str_pairs( str_pairs )
    str_pairs.map do |pair|
      pair[1].nil? ? enc_perenc( pair[0] ) 
                   : enc_perenc( pair[0] ) + '=' + enc_perenc( pair[1] )
    end.join( '&' )
  end

  # TODO これで良いか?
  # UTF-8 エンコードされたものをパーセントエンコードしているとみなしてデコードする
  # パーセントエンコードする際には文字列を UTF-8 エンコードするのは OAuth 1.0 の仕様
  # だが, デコード時はこれでよいか?
  def dec_perenc( str )
    str.gsub( /%[a-fA-F\d]{2}/u ){ |s| [s[1,2]].pack('H*') }.force_encoding( Encoding::UTF_8 )
  end

  def enc_perenc( str )
    str.gsub( /[^a-zA-Z\d\-\._\~]/u ) do |s|
      d_str = s.unpack("H*")[0].upcase()
      e_str = String.new()
      while ( d_str[0,2] != "" ) do
        e_str << "%" << d_str[0,2]
        d_str[0,2] = ""
      end
      e_str
    end
  end
  
end
end

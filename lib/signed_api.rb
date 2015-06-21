require "signed_api/version"
require 'openssl'
require 'uri'
require 'cgi'
require 'base64'

module SignedApi
  extend self

  class MissingParameterError < RuntimeError; end
  class AuthSecretNotFoundError < RuntimeError; end
  class SignatureExpiredError < RuntimeError; end
  class SignatureUnmatchError < RuntimeError; end

  # Returns url signed by the key, secret, and expiry
  #
  # Parameter examples
  # root_url : "http://example.com"
  # method : "GET"/"POST"/etc
  # path : "/some/useful/api"
  # params : {:param1 => "value1", :param2 => "value2"}
  # key : "SomeKeyStringForYourSecretKey"
  # secret : "anysecretstring"
  # expiry_limit : 60 #the signature will be expired in 60 sec
  def get_signed_url(root_url, method, path, params, key, secret, expiry_limit=60)
    params = ApiHelper::sign_params(method, path, params, key, secret, expiry_limit)
    root_url + path + '?' + ApiHelper::normalize_params(params)
  end

  def get_signed_path(method, path, params, key, secret, expiry_limit=60)
    params = ApiHelper::sign_params(method, path, params, key, secret, expiry_limit)
    path + '?' + ApiHelper::normalize_params(params)
  end

  # Returns signature added parameter hash
  #
  # method: HTTP METHOD ('GET', 'POST', etc)
  # path: invoked path ('/api/search', '/api/get', etc)
  # params: http params ({param1: value1, param2: value2}, etc)
  # key: authentication key (any string)
  # secret: authentication secret (any string)
  # expiry_limit: the request will expire in expiry_limit seconds (integer)
  def sign_params(method, path, params, key, secret, expiry_limit=60)
    raise ArgumentError, "Expected string for method parameter" unless method.kind_of?(String)
    raise ArgumentError, "Expected string for path parameter" unless path.kind_of?(String)
    raise ArgumentError, "Expected hash for params parameter" unless params.kind_of?(Hash)
    raise ArgumentError, "Expected string for key parameter" unless key.kind_of?(String)
    raise ArgumentError, "Expected string for secret parameter" unless secret.kind_of?(String)
    raise ArgumentError, "Expected integer for expiry_limit parameter" unless expiry_limit.kind_of?(Integer)
    raise ArgumentError, "Expected params not contain auth_key/auth_hash/expiry" unless params[:auth_key].nil? && params[:auth_hash].nil? && params[:expiry].nil?
    res_params = params.merge(auth_key: key, expiry: (Time.now.utc.to_i + expiry_limit).to_s)
    string_to_sign = signed_string(method, path, res_params)
    res_params[:auth_hash] = sha256_hmac_base64(secret, string_to_sign)
    return res_params
  end

  # Verify input params contains valid signature
  #
  # This method will raise an error if the verification failed.
  def verify_signature!(method, path, params, &get_secret)
    auth_hash = params[:auth_hash]

    # duplicate params without :auth_hash
    params = params.reject{|key| key==:auth_hash}
    auth_key = params[:auth_key]
    expiry = params[:expiry]
    raise MissingParameterError, "auth_key, auth_hash, or expiry is missing" if auth_key.nil? || auth_hash.nil? || expiry.nil?

    secret = get_secret.call(auth_key)
    raise AuthSecretNotFoundError, "auth_secret for the auth_key is not found" if secret.nil?

    now = Time.now.utc.to_i.to_s
    raise SignatureExpiredError if now > expiry

    raise SignatureUnmatchError, "auth_hash did not match" if auth_hash != gen_authhash(method, path, params, auth_key, secret)

    return true
  end

  # Verify input params contain valid signature
  #
  # This method merely returns the result of verification by true or false.
  def verify_signature(method, path, params, &get_secret)
    begin
      return true if verify_signature!(method, path, params, &get_secret)
    rescue MissingParameterError, AuthSecretNotFoundError, SignatureExpiredError, SignatureUnmatchError
      return false
    end
  end

  def normalize_params(params)
    params.collect{|key, value| "#{CGI.escape(key.to_s)}=#{CGI.escape(value.to_s)}"}.compact.sort! * "&"
  end

protected

  def signed_string(method, path, params)
    "#{method}\n#{path}\n#{normalize_params(params)}"
  end

  def sha256_hmac_base64(secret, string_to_sign)
    digest = OpenSSL::Digest::SHA256.new
    Base64.strict_encode64(OpenSSL::HMAC.digest(digest, secret, string_to_sign))
  end

  def gen_authhash(method, path, params, key, secret)
    string_to_sign = signed_string(method, path, params)
    sha256_hmac_base64(secret, string_to_sign)
  end
end

require 'spec_helper'
require 'signed_api'

describe SignedApi do
  it 'should have a version number' do
    expect(SignedApi::VERSION).not_to be_nil
  end

  describe "#sign_params" do
    it "signs parameter properly" do
      params = SignedApi::sign_params("GET", "/api/search", {a: "param_a", b: "param_b", c: "param_c"}, "key", "secret", 10)
      expect(params[:auth_key]).to eql("key")
      expect(params[:auth_hash]).not_to be_nil
      expect(params[:expiry]).not_to be_nil
      expect(params[:expiry].to_i).to be > Time.now.utc.to_i
      expect(params[:expiry].to_i).to be < Time.now.utc.to_i+20
      expect(params[:a]).to eql("param_a")
      expect(params[:b]).to eql("param_b")
      expect(params[:c]).to eql("param_c")
    end

    it "handle exceptional case properly" do
      expect {
        SignedApi::sign_params(nil, "/api/search", {a: "param_a"}, "key", "secret", 10)
      }.to raise_error

      expect {
        SignedApi::sign_params('GET', nil, {a: "param_a"}, "key", "secret", 10)
      }.to raise_error

      expect {
        SignedApi::sign_params('GET', "/api/search", nil, "key", "secret", 10)
      }.to raise_error

      expect {
        SignedApi::sign_params('GET', "/api/search", {a: "param_a"}, nil, "secret", 10)
      }.to raise_error

      expect {
        SignedApi::sign_params('GET', "/api/search", {a: "param_a"}, "key", nil, 10)
      }.to raise_error

      expect {
        SignedApi::sign_params('GET', "/api/search", {a: "param_a"}, "key", "secret", "10")
      }.to raise_error

      expect {
        SignedApi::sign_params('GET', "/api/search", {a: "param_a", auth_key: "hoge"}, "key", "secret", 10)
      }.to raise_error

      expect {
        SignedApi::sign_params('GET', "/api/search", {a: "param_a", auth_hash: "hoge"}, "key", "secret", 10)
      }.to raise_error

      expect {
        SignedApi::sign_params('GET', "/api/search", {a: "param_a", expiry: "hoge"}, "key", "secret", 10)
      }.to raise_error
    end
  end

  describe "#verify_signature!" do
    it "verify properly" do
      params = SignedApi::sign_params("POST", "/api/find", {a: "param_a", b: "param_b", c: "param_c"}, "key", "secret", 10)
      expect(SignedApi::verify_signature!("POST", "/api/find", params){|key| "secret"}).to be true

      key = "123456789ABCDEF"
      secret = "123456789ABCDEF0123456789ABCDEF0"
      params = SignedApi::sign_params("GET", "/", {a: "param_a", b: "param_b", c: "param_c"}, key, secret, 10)
      expect(SignedApi::verify_signature!("GET", "/", params){|key| secret}).to be true

      params = SignedApi::sign_params("GET", "/", {}, key, secret, 10)
      expect(SignedApi::verify_signature!("GET", "/", params){|key| secret}).to be true
    end

    it "reject properly" do
      params = SignedApi::sign_params("POST", "/api/find", {a: "param_a", b: "param_b", c: "param_c"}, "key", "secret", 30)
      expect{ SignedApi::verify_signature!("GET", "/api/find", params){|key| "secret"} }.to raise_error(SignedApi::SignatureUnmatchError)
      expect{ SignedApi::verify_signature!("POST", "/api/finds", params){|key| "secret"} }.to raise_error(SignedApi::SignatureUnmatchError)
      expect{ SignedApi::verify_signature!("POST", "api/find", params){|key| "secret"} }.to raise_error(SignedApi::SignatureUnmatchError)
      expect{ SignedApi::verify_signature!("POST", "/api/find", params){|key| "wrongsecret"} }.to raise_error(SignedApi::SignatureUnmatchError)
      expect{ SignedApi::verify_signature!("POST", "/api/find", params){|key| ""} }.to raise_error(SignedApi::SignatureUnmatchError)
      params[:a] = "param_"
      expect{ SignedApi::verify_signature!("POST", "/api/find", params){|key| ""} }.to raise_error(SignedApi::SignatureUnmatchError)
      params[:a] = "param_a"
      params[:x] = "param_x"
      expect{ SignedApi::verify_signature!("POST", "/api/find", params){|key| ""} }.to raise_error(SignedApi::SignatureUnmatchError)
    end

    it "handle exceptional case properly" do
      params = SignedApi::sign_params("POST", "/api/find", {a: "param_a", b: "param_b", c: "param_c"}, "key", "secret", 10)
      expect{ SignedApi::verify_signature!("POST", "", params){|key| nil} }.to raise_error(SignedApi::AuthSecretNotFoundError)

      expect{ SignedApi::verify_signature!("POST", "", params.reject{|k| k==:auth_key}){|key| "secret"} }.to raise_error(SignedApi::MissingParameterError)
      expect{ SignedApi::verify_signature!("POST", "", params.reject{|k| k==:auth_hash}){|key| "secret"} }.to raise_error(SignedApi::MissingParameterError)
      expect{ SignedApi::verify_signature!("POST", "", params.reject{|k| k==:expiry}){|key| "secret"} }.to raise_error(SignedApi::MissingParameterError)
    end

    it "reject expired signature" do
      params = SignedApi::sign_params("POST", "/api/find", {a: "param_a", b: "param_b", c: "param_c"}, "key", "secret", 0)
      sleep 1
      expect{ SignedApi::verify_signature!("POST", "/api/find", params){|key| "secret"} }.to raise_error(SignedApi::SignatureExpiredError)
    end

  end
end

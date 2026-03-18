# frozen_string_literal: true

require "webmock/rspec"

RSpec.describe Supabase::Auth::Client, "OAuth URL construction" do
  let(:url) { "http://localhost:9999" }
  let(:headers) { { "apikey" => "test-api-key" } }
  let(:client) { described_class.new(url: url, headers: headers) }

  before do
    WebMock.disable_net_connect!
  end

  after do
    WebMock.allow_net_connect!
  end

  # -------------------------------------------------------------------
  # AC 1: sign_in_with_oauth returns OAuthResponse with provider and URL
  # -------------------------------------------------------------------
  describe "#sign_in_with_oauth" do
    it "returns an OAuthResponse with provider and url" do
      response = client.sign_in_with_oauth(provider: "google")

      expect(response).to be_a(Supabase::Auth::Types::OAuthResponse)
      expect(response.provider).to eq("google")
      expect(response.url).to be_a(String)
    end

    # -------------------------------------------------------------------
    # AC 2: URL includes correct /authorize endpoint
    # -------------------------------------------------------------------
    it "constructs URL with /authorize endpoint" do
      response = client.sign_in_with_oauth(provider: "google")

      uri = URI.parse(response.url)
      expect(uri.path).to eq("/authorize")
    end

    # -------------------------------------------------------------------
    # AC 3: URL includes provider query parameter
    # -------------------------------------------------------------------
    it "includes provider as query parameter" do
      response = client.sign_in_with_oauth(provider: "github")

      params = URI.decode_www_form(URI.parse(response.url).query).to_h
      expect(params["provider"]).to eq("github")
    end

    it "works with various providers" do
      %w[google github gitlab bitbucket azure facebook apple twitter discord].each do |provider|
        response = client.sign_in_with_oauth(provider: provider)

        params = URI.decode_www_form(URI.parse(response.url).query).to_h
        expect(params["provider"]).to eq(provider)
        expect(response.provider).to eq(provider)
      end
    end

    # -------------------------------------------------------------------
    # AC 4: Custom scopes are appended to URL
    # -------------------------------------------------------------------
    it "includes scopes in URL when provided" do
      response = client.sign_in_with_oauth(
        provider: "google",
        options: { scopes: "openid profile email" }
      )

      params = URI.decode_www_form(URI.parse(response.url).query).to_h
      expect(params["scopes"]).to eq("openid profile email")
    end

    it "does not include scopes param when not provided" do
      response = client.sign_in_with_oauth(provider: "google")

      params = URI.decode_www_form(URI.parse(response.url).query).to_h
      expect(params).not_to have_key("scopes")
    end

    # -------------------------------------------------------------------
    # AC 5: redirect_to is included when provided
    # -------------------------------------------------------------------
    it "includes redirect_to in URL when provided" do
      response = client.sign_in_with_oauth(
        provider: "google",
        options: { redirect_to: "http://example.com/callback" }
      )

      params = URI.decode_www_form(URI.parse(response.url).query).to_h
      expect(params["redirect_to"]).to eq("http://example.com/callback")
    end

    it "does not include redirect_to when not provided" do
      response = client.sign_in_with_oauth(provider: "google")

      params = URI.decode_www_form(URI.parse(response.url).query).to_h
      expect(params).not_to have_key("redirect_to")
    end

    # -------------------------------------------------------------------
    # AC 6: Additional query_params are merged into URL
    # -------------------------------------------------------------------
    it "merges additional query_params into URL" do
      response = client.sign_in_with_oauth(
        provider: "google",
        options: {
          query_params: {
            "access_type" => "offline",
            "prompt" => "consent"
          }
        }
      )

      params = URI.decode_www_form(URI.parse(response.url).query).to_h
      expect(params["access_type"]).to eq("offline")
      expect(params["prompt"]).to eq("consent")
      expect(params["provider"]).to eq("google")
    end

    it "combines scopes, redirect_to, and query_params" do
      response = client.sign_in_with_oauth(
        provider: "github",
        options: {
          scopes: "read:user",
          redirect_to: "http://example.com/cb",
          query_params: { "login" => "user123" }
        }
      )

      params = URI.decode_www_form(URI.parse(response.url).query).to_h
      expect(params["provider"]).to eq("github")
      expect(params["scopes"]).to eq("read:user")
      expect(params["redirect_to"]).to eq("http://example.com/cb")
      expect(params["login"]).to eq("user123")
    end

    it "uses base URL from client configuration" do
      response = client.sign_in_with_oauth(provider: "google")

      uri = URI.parse(response.url)
      expect(uri.scheme).to eq("http")
      expect(uri.host).to eq("localhost")
      expect(uri.port).to eq(9999)
    end

    # -------------------------------------------------------------------
    # PKCE flow: adds code_challenge params when flow_type is pkce
    # -------------------------------------------------------------------
    context "with PKCE flow" do
      let(:pkce_client) { described_class.new(url: url, headers: headers, flow_type: "pkce") }

      it "includes code_challenge and code_challenge_method in URL" do
        response = pkce_client.sign_in_with_oauth(provider: "google")

        params = URI.decode_www_form(URI.parse(response.url).query).to_h
        expect(params).to have_key("code_challenge")
        expect(params).to have_key("code_challenge_method")
        expect(params["code_challenge_method"]).to eq("s256")
      end

      it "stores code_verifier in storage" do
        pkce_client.sign_in_with_oauth(provider: "google")

        storage = pkce_client.instance_variable_get(:@storage)
        storage_key = pkce_client.instance_variable_get(:@storage_key)
        verifier = storage.get_item("#{storage_key}-code-verifier")
        expect(verifier).not_to be_nil
        expect(verifier.length).to be > 0
      end
    end

    context "with implicit flow (default)" do
      it "does not include code_challenge params in URL" do
        response = client.sign_in_with_oauth(provider: "google")

        params = URI.decode_www_form(URI.parse(response.url).query).to_h
        expect(params).not_to have_key("code_challenge")
        expect(params).not_to have_key("code_challenge_method")
      end
    end

    # -------------------------------------------------------------------
    # String vs symbol key access
    # -------------------------------------------------------------------
    it "accepts string keys for top-level credentials" do
      response = client.sign_in_with_oauth("provider" => "google")

      expect(response.provider).to eq("google")
      params = URI.decode_www_form(URI.parse(response.url).query).to_h
      expect(params["provider"]).to eq("google")
    end
  end
end

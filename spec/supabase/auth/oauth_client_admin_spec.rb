# frozen_string_literal: true

require "spec_helper"
require "webmock/rspec"
require "json"

# Verifies the AdminApi OAuth 2.1 client management endpoints match Python
# (supabase-py/src/auth/src/supabase_auth/_sync/gotrue_admin_api.py).
RSpec.describe "AdminApi OAuth client management" do
  let(:base_url) { "http://localhost:9998" }
  let(:admin_api) do
    Supabase::Auth::AdminApi.new(
      url: base_url,
      headers: { "Authorization" => "Bearer service-role-jwt" }
    )
  end

  let(:client_id) { "550e8400-e29b-41d4-a716-446655440000" }

  let(:mock_client_hash) do
    {
      "client_id" => client_id,
      "client_name" => "My App",
      "client_secret" => "secret-value",
      "client_type" => "confidential",
      "token_endpoint_auth_method" => "client_secret_basic",
      "registration_type" => "manual",
      "client_uri" => "https://example.com",
      "logo_uri" => "https://example.com/logo.png",
      "redirect_uris" => ["https://example.com/callback"],
      "grant_types" => ["authorization_code", "refresh_token"],
      "response_types" => ["code"],
      "scope" => "openid email",
      "created_at" => "2024-01-01T00:00:00Z",
      "updated_at" => "2024-01-01T00:00:00Z"
    }
  end

  before { WebMock.disable_net_connect! }
  after { WebMock.allow_net_connect! }

  describe "#_list_oauth_clients" do
    it "GETs /admin/oauth/clients and parses pagination headers" do
      stub_request(:get, "#{base_url}/admin/oauth/clients")
        .with(query: { page: "2", per_page: "10" })
        .to_return(
          status: 200,
          body: { "clients" => [mock_client_hash], "aud" => "authenticated" }.to_json,
          headers: {
            "Content-Type" => "application/json",
            "x-total-count" => "42",
            "link" => '<http://localhost:9998/admin/oauth/clients?page=3&per_page=10>; rel="next", <http://localhost:9998/admin/oauth/clients?page=5&per_page=10>; rel="last"'
          }
        )

      result = admin_api._list_oauth_clients(page: 2, per_page: 10)

      expect(result).to be_a(Supabase::Auth::Types::OAuthClientListResponse)
      expect(result.clients.length).to eq(1)
      expect(result.clients.first.client_id).to eq(client_id)
      expect(result.aud).to eq("authenticated")
      expect(result.total).to eq(42)
      expect(result.next_page).to eq(3)
      expect(result.last_page).to eq(5)
    end

    it "works without pagination params and missing headers" do
      stub_request(:get, "#{base_url}/admin/oauth/clients")
        .to_return(
          status: 200,
          body: { "clients" => [] }.to_json,
          headers: { "Content-Type" => "application/json" }
        )

      result = admin_api._list_oauth_clients

      expect(result.clients).to eq([])
      expect(result.total).to eq(0)
      expect(result.last_page).to eq(0)
      expect(result.next_page).to be_nil
    end
  end

  describe "#_create_oauth_client" do
    it "POSTs the params and returns OAuthClientResponse" do
      params = {
        client_name: "My App",
        redirect_uris: ["https://example.com/callback"]
      }
      stub_request(:post, "#{base_url}/admin/oauth/clients")
        .with(body: params.to_json)
        .to_return(
          status: 200,
          body: mock_client_hash.to_json,
          headers: { "Content-Type" => "application/json" }
        )

      result = admin_api._create_oauth_client(params)

      expect(result).to be_a(Supabase::Auth::Types::OAuthClientResponse)
      expect(result.client.client_id).to eq(client_id)
      expect(result.client.client_secret).to eq("secret-value")
    end
  end

  describe "#_get_oauth_client" do
    it "validates UUID and GETs /admin/oauth/clients/{id}" do
      stub_request(:get, "#{base_url}/admin/oauth/clients/#{client_id}")
        .to_return(status: 200, body: mock_client_hash.to_json, headers: { "Content-Type" => "application/json" })

      result = admin_api._get_oauth_client(client_id)
      expect(result.client.client_name).to eq("My App")
    end

    it "raises ArgumentError on invalid UUID" do
      expect { admin_api._get_oauth_client("not-a-uuid") }.to raise_error(ArgumentError)
    end
  end

  describe "#_update_oauth_client" do
    it "PUTs params to /admin/oauth/clients/{id}" do
      stub_request(:put, "#{base_url}/admin/oauth/clients/#{client_id}")
        .with(body: { client_name: "Renamed" }.to_json)
        .to_return(
          status: 200,
          body: mock_client_hash.merge("client_name" => "Renamed").to_json,
          headers: { "Content-Type" => "application/json" }
        )

      result = admin_api._update_oauth_client(client_id, client_name: "Renamed")
      expect(result.client.client_name).to eq("Renamed")
    end

    it "raises ArgumentError on invalid UUID" do
      expect { admin_api._update_oauth_client("bad", client_name: "x") }.to raise_error(ArgumentError)
    end
  end

  describe "#_delete_oauth_client" do
    it "DELETEs /admin/oauth/clients/{id}" do
      stub = stub_request(:delete, "#{base_url}/admin/oauth/clients/#{client_id}")
        .to_return(status: 200, body: "{}", headers: { "Content-Type" => "application/json" })

      admin_api._delete_oauth_client(client_id)
      expect(stub).to have_been_requested
    end

    it "raises ArgumentError on invalid UUID" do
      expect { admin_api._delete_oauth_client("bad") }.to raise_error(ArgumentError)
    end
  end

  describe "#_regenerate_oauth_client_secret" do
    it "POSTs to /admin/oauth/clients/{id}/regenerate_secret" do
      stub_request(:post, "#{base_url}/admin/oauth/clients/#{client_id}/regenerate_secret")
        .to_return(
          status: 200,
          body: mock_client_hash.merge("client_secret" => "new-secret").to_json,
          headers: { "Content-Type" => "application/json" }
        )

      result = admin_api._regenerate_oauth_client_secret(client_id)
      expect(result.client.client_secret).to eq("new-secret")
    end

    it "raises ArgumentError on invalid UUID" do
      expect { admin_api._regenerate_oauth_client_secret("bad") }.to raise_error(ArgumentError)
    end
  end
end

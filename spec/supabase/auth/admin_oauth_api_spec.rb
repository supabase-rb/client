# frozen_string_literal: true

require "spec_helper"
require "webmock/rspec"
require "json"

# Verifies AdminOAuthApi exposes Python-parity public method names (list_clients,
# create_client, get_client, update_client, delete_client, regenerate_client_secret)
# via admin.oauth, delegating to the underscored implementations on AdminApi.
RSpec.describe Supabase::Auth::AdminOAuthApi do
  let(:base_url) { "http://localhost:9998" }
  let(:admin) do
    Supabase::Auth::AdminApi.new(
      url: base_url,
      headers: { "Authorization" => "Bearer service-role-jwt" }
    )
  end
  let(:oauth) { admin.oauth }

  let(:client_id) { "550e8400-e29b-41d4-a716-446655440000" }

  let(:mock_client_hash) do
    {
      "client_id" => client_id,
      "client_name" => "My App",
      "client_secret" => "secret-value",
      "client_type" => "confidential",
      "redirect_uris" => ["https://example.com/callback"],
      "grant_types" => ["authorization_code"],
      "response_types" => ["code"]
    }
  end

  before { WebMock.disable_net_connect! }
  after { WebMock.allow_net_connect! }

  it "is reachable via admin.oauth and is an AdminOAuthApi" do
    expect(oauth).to be_a(described_class)
  end

  describe "#list_clients" do
    it "delegates to _list_oauth_clients with pagination params" do
      stub_request(:get, "#{base_url}/admin/oauth/clients")
        .with(query: { page: "2", per_page: "10" })
        .to_return(
          status: 200,
          body: { "clients" => [mock_client_hash] }.to_json,
          headers: { "Content-Type" => "application/json" }
        )

      result = oauth.list_clients(page: 2, per_page: 10)

      expect(result).to be_a(Supabase::Auth::Types::OAuthClientListResponse)
      expect(result.clients.first.client_id).to eq(client_id)
    end

    it "works with no params" do
      stub_request(:get, "#{base_url}/admin/oauth/clients")
        .to_return(status: 200, body: { "clients" => [] }.to_json,
                   headers: { "Content-Type" => "application/json" })

      expect(oauth.list_clients.clients).to eq([])
    end
  end

  describe "#create_client" do
    it "POSTs and returns OAuthClientResponse" do
      params = { client_name: "My App", redirect_uris: ["https://example.com/callback"] }
      stub_request(:post, "#{base_url}/admin/oauth/clients")
        .with(body: params.to_json)
        .to_return(status: 200, body: mock_client_hash.to_json,
                   headers: { "Content-Type" => "application/json" })

      result = oauth.create_client(params)

      expect(result).to be_a(Supabase::Auth::Types::OAuthClientResponse)
      expect(result.client.client_id).to eq(client_id)
    end
  end

  describe "#get_client" do
    it "GETs /admin/oauth/clients/{id}" do
      stub_request(:get, "#{base_url}/admin/oauth/clients/#{client_id}")
        .to_return(status: 200, body: mock_client_hash.to_json,
                   headers: { "Content-Type" => "application/json" })

      expect(oauth.get_client(client_id).client.client_name).to eq("My App")
    end

    it "raises ArgumentError on invalid UUID" do
      expect { oauth.get_client("not-a-uuid") }.to raise_error(ArgumentError)
    end
  end

  describe "#update_client" do
    it "PUTs attributes to /admin/oauth/clients/{id}" do
      stub_request(:put, "#{base_url}/admin/oauth/clients/#{client_id}")
        .with(body: { client_name: "Renamed" }.to_json)
        .to_return(
          status: 200,
          body: mock_client_hash.merge("client_name" => "Renamed").to_json,
          headers: { "Content-Type" => "application/json" }
        )

      expect(oauth.update_client(client_id, client_name: "Renamed").client.client_name)
        .to eq("Renamed")
    end

    it "raises ArgumentError on invalid UUID" do
      expect { oauth.update_client("bad", client_name: "x") }.to raise_error(ArgumentError)
    end
  end

  describe "#delete_client" do
    it "DELETEs /admin/oauth/clients/{id}" do
      stub = stub_request(:delete, "#{base_url}/admin/oauth/clients/#{client_id}")
        .to_return(status: 200, body: "{}", headers: { "Content-Type" => "application/json" })

      oauth.delete_client(client_id)
      expect(stub).to have_been_requested
    end

    it "raises ArgumentError on invalid UUID" do
      expect { oauth.delete_client("bad") }.to raise_error(ArgumentError)
    end
  end

  describe "#regenerate_client_secret" do
    it "POSTs to /admin/oauth/clients/{id}/regenerate_secret and returns rotated secret" do
      stub_request(:post, "#{base_url}/admin/oauth/clients/#{client_id}/regenerate_secret")
        .to_return(
          status: 200,
          body: mock_client_hash.merge("client_secret" => "new-secret").to_json,
          headers: { "Content-Type" => "application/json" }
        )

      result = oauth.regenerate_client_secret(client_id)
      expect(result.client.client_secret).to eq("new-secret")
    end

    it "raises ArgumentError on invalid UUID" do
      expect { oauth.regenerate_client_secret("bad") }.to raise_error(ArgumentError)
    end
  end
end

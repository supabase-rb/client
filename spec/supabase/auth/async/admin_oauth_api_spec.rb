# frozen_string_literal: true

require "spec_helper"
require "webmock/rspec"
require "async"
require "supabase/auth/async"

# Async::AdminOAuthApi: thin wrapper that delegates to Async::AdminApi's
# underscored methods. Inherits behavior from the sync wrapper; this spec
# verifies the type tree is wired up correctly and a sample method dispatches.
RSpec.describe Supabase::Auth::Async::AdminOAuthApi do
  let(:base_url) { "http://localhost:9998" }
  let(:admin) do
    Supabase::Auth::Async::AdminApi.new(
      url: base_url,
      headers: { "Authorization" => "Bearer #{TestClients::SERVICE_ROLE_JWT}" }
    )
  end
  let(:oauth) { admin.oauth }

  it "is reachable via async admin.oauth and inherits from sync AdminOAuthApi" do
    expect(oauth).to be_a(described_class)
    expect(described_class.ancestors).to include(Supabase::Auth::AdminOAuthApi)
  end

  # The OAuth 2.1 server isn't enabled on the docker-compose GoTrue image used
  # locally, so we verify dispatch with a WebMock stub rather than a live call.
  describe "#list_clients dispatch" do
    before do
      WebMock.disable_net_connect!
      stub_request(:get, "#{base_url}/admin/oauth/clients")
        .to_return(status: 200, body: { "clients" => [] }.to_json,
                   headers: { "Content-Type" => "application/json" })
    end

    after { WebMock.allow_net_connect! }

    it "delegates to the wrapped admin's _list_oauth_clients" do
      result = nil
      Async do
        result = oauth.list_clients
      end.wait

      expect(result).to be_a(Supabase::Auth::Types::OAuthClientListResponse)
      expect(result.clients).to eq([])
    end
  end
end

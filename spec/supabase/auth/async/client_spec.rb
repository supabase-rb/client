# frozen_string_literal: true

require "spec_helper"
require "async"
require "supabase/auth/async"

# Async::Client end-to-end against the live GoTrue infra (port 9998 autoconfirm).
# Covers the main public surface inherited from sync Client; the goal is to prove
# every inherited HTTP-touching method dispatches through Async::Api correctly.
# Exhaustive method-by-method coverage lives in the sync spec suite; this file
# verifies the wiring.
RSpec.describe Supabase::Auth::Async::Client do
  let(:url) { TestClients::GOTRUE_URL_SIGNUP_ENABLED_AUTO_CONFIRM_ON }
  let(:async_client) { described_class.new(url: url, persist_session: false) }
  let(:user_credentials) { mock_user_credentials }

  def with_signed_up_user
    sync_client = Supabase::Auth::Client.new(url: url, persist_session: false)
    sync_client.sign_up(
      email: user_credentials[:email],
      password: user_credentials[:password]
    )
  end

  before(:each) do
    WebMock.allow_net_connect! if defined?(WebMock)
  rescue Errno::ECONNREFUSED, Supabase::Auth::Errors::AuthRetryableError
    skip "GoTrue infra not running (docker compose -f infra/docker-compose.yml up -d)"
  end

  it "inherits from sync Client (same public API)" do
    expect(described_class.ancestors).to include(Supabase::Auth::Client)
  end

  it "constructs an Async::Api for its HTTP transport" do
    api = async_client.instance_variable_get(:@api)
    expect(api).to be_a(Supabase::Auth::Async::Api)
  end

  it "constructs an Async::AdminApi for admin operations" do
    expect(async_client.admin).to be_a(Supabase::Auth::Async::AdminApi)
  end

  it "exposes Async::AdminOAuthApi via admin.oauth" do
    expect(async_client.admin.oauth).to be_a(Supabase::Auth::Async::AdminOAuthApi)
  end

  describe "sign_up + sign_in_with_password" do
    it "completes the round trip inside Async" do
      response = nil
      Async do
        async_client.sign_up(
          email: user_credentials[:email],
          password: user_credentials[:password]
        )

        response = async_client.sign_in_with_password(
          email: user_credentials[:email],
          password: user_credentials[:password]
        )
      end.wait

      expect(response).to be_a(Supabase::Auth::Types::AuthResponse)
      expect(response.session.access_token).to be_a(String)
      expect(response.user.email).to eq(user_credentials[:email])
    end
  end

  describe "get_user" do
    it "fetches the current user with the active session" do
      with_signed_up_user

      user = nil
      Async do
        async_client.sign_in_with_password(
          email: user_credentials[:email],
          password: user_credentials[:password]
        )
        user_response = async_client.get_user
        user = user_response&.user
      end.wait

      expect(user).not_to be_nil
      expect(user.email).to eq(user_credentials[:email])
    end
  end

  describe "refresh_session" do
    it "refreshes the access token using the refresh token" do
      with_signed_up_user
      original_access = nil
      refreshed_access = nil

      Async do
        signin = async_client.sign_in_with_password(
          email: user_credentials[:email],
          password: user_credentials[:password]
        )
        original_access = signin.session.access_token

        refresh = async_client.refresh_session
        refreshed_access = refresh.session.access_token
      end.wait

      expect(refreshed_access).to be_a(String)
      # New access token may equal old one if issued within the same second, but
      # the refresh call must succeed and return a session.
      expect(refreshed_access).not_to be_empty
    end
  end
end

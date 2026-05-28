# frozen_string_literal: true

require "spec_helper"
require "webmock/rspec"

# Pins MFAApi#challenge_and_verify channel forwarding (nil/sms/whatsapp) so the
# phone-factor channel is never silently dropped between challenge_and_verify
# and the internal challenge call (F-011 in the audit).
RSpec.describe Supabase::Auth::Client, "MFA channel forwarding" do
  let(:url) { "http://localhost:9999" }
  let(:headers) { { "apikey" => "test-api-key" } }
  let(:client) { described_class.new(url: url, headers: headers, persist_session: false) }

  let(:fake_session) do
    Supabase::Auth::Types::Session.new(
      access_token: "fake-access-token",
      refresh_token: "fake-refresh-token",
      token_type: "bearer",
      expires_in: 3600,
      expires_at: Time.now.to_i + 3600
    )
  end

  let(:challenge_response_body) do
    { "id" => "challenge-id", "type" => "phone", "expires_at" => Time.now.to_i + 300 }
  end

  let(:verify_response_body) do
    {
      "access_token" => "mfa-access-token",
      "token_type" => "bearer",
      "expires_in" => 3600,
      "refresh_token" => "mfa-refresh-token",
      "user" => { "id" => "user-1", "email" => "test@example.com" }
    }
  end

  before do
    WebMock.disable_net_connect!
    client.instance_variable_set(:@current_session, fake_session)
  end

  after { WebMock.allow_net_connect! }

  shared_examples "forwards channel to /challenge" do |channel_value|
    it "sends channel=#{channel_value.inspect} in /factors/{id}/challenge body" do
      stub_request(:post, "#{url}/factors/factor-1/challenge")
        .to_return(status: 200, body: challenge_response_body.to_json,
                   headers: { "Content-Type" => "application/json" })
      stub_request(:post, "#{url}/factors/factor-1/verify")
        .to_return(status: 200, body: verify_response_body.to_json,
                   headers: { "Content-Type" => "application/json" })

      client.mfa.challenge_and_verify(
        factor_id: "factor-1",
        code: "123456",
        channel: channel_value
      )

      expect(WebMock).to have_requested(:post, "#{url}/factors/factor-1/challenge")
        .with { |req| JSON.parse(req.body)["channel"] == channel_value }
    end
  end

  describe "#challenge_and_verify" do
    include_examples "forwards channel to /challenge", "sms"
    include_examples "forwards channel to /challenge", "whatsapp"
    include_examples "forwards channel to /challenge", nil
  end

  describe "#challenge directly" do
    it "accepts channel kwarg and forwards it to the challenge endpoint" do
      stub = stub_request(:post, "#{url}/factors/factor-1/challenge")
        .with(body: hash_including("channel" => "whatsapp"))
        .to_return(status: 200, body: challenge_response_body.to_json,
                   headers: { "Content-Type" => "application/json" })

      client.mfa.challenge(factor_id: "factor-1", channel: "whatsapp")

      expect(stub).to have_been_requested
    end
  end
end

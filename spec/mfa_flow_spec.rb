# frozen_string_literal: true

require "spec_helper"
require "jwt"

# Integration tests for MFA flows: enroll → challenge → verify, unenroll,
# list_factors, and get_authenticator_assurance_level.
# Uses mocked HTTP responses (not real API calls).
RSpec.describe "MFA flow integration" do
  let(:mock_user) do
    Supabase::Auth::Types::User.new(
      id: "test-user-id",
      app_metadata: {},
      user_metadata: {},
      aud: "test-aud",
      email: "test@example.com",
      phone: "",
      created_at: Time.parse("2023-01-01T00:00:00Z"),
      confirmed_at: Time.parse("2023-01-01T00:00:00Z"),
      last_sign_in_at: Time.parse("2023-01-01T00:00:00Z"),
      role: "authenticated",
      updated_at: Time.parse("2023-01-01T00:00:00Z")
    )
  end

  let(:mock_session) do
    Supabase::Auth::Types::Session.new(
      access_token: "mock-access-token",
      refresh_token: "mock-refresh-token",
      expires_in: 3600,
      expires_at: Time.now.to_i + 3600,
      token_type: "bearer",
      user: mock_user
    )
  end

  let(:client) do
    Supabase::Auth::Client.new(
      url: "http://localhost:9998",
      auto_refresh_token: false,
      persist_session: false
    )
  end

  def setup_session(client, session)
    client.instance_variable_set(:@current_session, session)
  end

  let(:mock_verify_response) do
    {
      "access_token" => "mfa-access-token",
      "refresh_token" => "mfa-refresh-token",
      "token_type" => "bearer",
      "expires_in" => 3600,
      "expires_at" => Time.now.to_i + 3600,
      "user" => {
        "id" => "test-user-id",
        "app_metadata" => {},
        "user_metadata" => {},
        "aud" => "test-aud",
        "email" => "test@example.com",
        "created_at" => "2023-01-01T00:00:00Z",
        "updated_at" => "2023-01-01T00:00:00Z"
      }
    }
  end

  describe "TOTP MFA flow: enroll → challenge → verify" do
    it "completes full TOTP enrollment, challenge, and verification returning a new session" do
      setup_session(client, mock_session)

      # Step 1: Enroll a TOTP factor
      allow(client).to receive(:_request).and_return(
        { "id" => "factor-totp-1", "type" => "totp", "friendly_name" => "my-totp",
          "totp" => { "qr_code" => "<svg>qr</svg>", "secret" => "JBSWY3DPEHPK3PXP",
                      "uri" => "otpauth://totp/MyApp?secret=JBSWY3DPEHPK3PXP" } }
      )

      enroll_response = client.mfa.enroll(factor_type: "totp", friendly_name: "my-totp", issuer: "MyApp")

      expect(enroll_response).to be_a(Supabase::Auth::Types::AuthMFAEnrollResponse)
      expect(enroll_response.id).to eq("factor-totp-1")
      expect(enroll_response.type).to eq("totp")
      expect(enroll_response.totp.secret).to eq("JBSWY3DPEHPK3PXP")
      expect(enroll_response.totp.qr_code).to start_with("data:image/svg+xml;utf-8,")

      # Step 2: Challenge the factor
      allow(client).to receive(:_request).and_return(
        { "id" => "challenge-1", "type" => "totp", "expires_at" => Time.now.to_i + 300 }
      )

      challenge_response = client.mfa.challenge(factor_id: "factor-totp-1")

      expect(challenge_response).to be_a(Supabase::Auth::Types::AuthMFAChallengeResponse)
      expect(challenge_response.id).to eq("challenge-1")
      expect(challenge_response.factor_type).to eq("totp")

      # Step 3: Verify the challenge — returns new session
      allow(client).to receive(:_request).and_return(mock_verify_response)

      verify_response = client.mfa.verify(
        factor_id: "factor-totp-1",
        challenge_id: "challenge-1",
        code: "123456"
      )

      expect(verify_response).to be_a(Supabase::Auth::Types::AuthMFAVerifyResponse)
      expect(verify_response.access_token).to eq("mfa-access-token")
      expect(verify_response.user).to be_a(Supabase::Auth::Types::User)

      # Session should be updated with new tokens
      updated_session = client.get_session
      expect(updated_session.access_token).to eq("mfa-access-token")
    end
  end

  describe "Phone MFA flow: enroll → challenge (with channel) → verify" do
    it "completes phone factor enrollment with channel forwarding" do
      setup_session(client, mock_session)

      # Step 1: Enroll a phone factor
      allow(client).to receive(:_request).and_return(
        { "id" => "factor-phone-1", "type" => "phone", "friendly_name" => "my-phone" }
      )

      enroll_response = client.mfa.enroll(factor_type: "phone", friendly_name: "my-phone", phone: "+15551234567")

      expect(enroll_response).to be_a(Supabase::Auth::Types::AuthMFAEnrollResponse)
      expect(enroll_response.id).to eq("factor-phone-1")
      expect(enroll_response.type).to eq("phone")
      expect(enroll_response.totp).to be_nil

      # Step 2: Challenge with whatsapp channel
      challenge_body = nil
      allow(client).to receive(:_request) do |_method, _path, **kwargs|
        challenge_body = kwargs[:body]
        { "id" => "challenge-phone-1", "type" => "phone", "expires_at" => Time.now.to_i + 300 }
      end

      challenge_response = client.mfa.challenge(factor_id: "factor-phone-1", channel: "whatsapp")

      expect(challenge_response).to be_a(Supabase::Auth::Types::AuthMFAChallengeResponse)
      expect(challenge_response.id).to eq("challenge-phone-1")
      expect(challenge_body[:channel]).to eq("whatsapp")

      # Step 3: Verify
      allow(client).to receive(:_request).and_return(mock_verify_response)

      verify_response = client.mfa.verify(
        factor_id: "factor-phone-1",
        challenge_id: "challenge-phone-1",
        code: "654321"
      )

      expect(verify_response).to be_a(Supabase::Auth::Types::AuthMFAVerifyResponse)
      expect(verify_response.access_token).to eq("mfa-access-token")
    end
  end

  describe "challenge_and_verify combined flow" do
    it "performs challenge + verify in one call with channel forwarding" do
      setup_session(client, mock_session)

      call_count = 0
      challenge_body = nil
      allow(client).to receive(:_request) do |method, path, **kwargs|
        call_count += 1
        if path.end_with?("/challenge")
          challenge_body = kwargs[:body]
          { "id" => "auto-challenge-id", "type" => "phone", "expires_at" => Time.now.to_i + 300 }
        else
          mock_verify_response
        end
      end

      response = client.mfa.challenge_and_verify(
        factor_id: "factor-phone-1",
        code: "111222",
        channel: "sms"
      )

      # Should have made exactly 2 requests: challenge + verify
      expect(call_count).to eq(2)
      expect(response).to be_a(Supabase::Auth::Types::AuthMFAVerifyResponse)
      expect(response.access_token).to eq("mfa-access-token")

      # Channel should have been forwarded to challenge
      expect(challenge_body[:channel]).to eq("sms")
    end

    it "passes challenge_id from challenge response to verify automatically" do
      setup_session(client, mock_session)

      verify_body = nil
      allow(client).to receive(:_request) do |_method, path, **kwargs|
        if path.end_with?("/challenge")
          { "id" => "auto-generated-challenge-id", "type" => "totp", "expires_at" => Time.now.to_i + 300 }
        else
          verify_body = kwargs[:body]
          mock_verify_response
        end
      end

      client.mfa.challenge_and_verify(factor_id: "factor-1", code: "999888")

      expect(verify_body[:challenge_id]).to eq("auto-generated-challenge-id")
      expect(verify_body[:code]).to eq("999888")
    end
  end

  describe "unenroll after enrollment" do
    it "unenrolls a previously enrolled factor" do
      setup_session(client, mock_session)

      # Enroll first
      allow(client).to receive(:_request).and_return(
        { "id" => "factor-to-remove", "type" => "totp", "friendly_name" => "temp",
          "totp" => { "qr_code" => "<svg/>", "secret" => "S", "uri" => "otpauth://..." } }
      )
      enroll_response = client.mfa.enroll(factor_type: "totp", friendly_name: "temp")
      factor_id = enroll_response.id

      # Unenroll
      allow(client).to receive(:_request).and_return({ "id" => factor_id })

      unenroll_response = client.mfa.unenroll(factor_id: factor_id)

      expect(unenroll_response).to be_a(Supabase::Auth::Types::AuthMFAUnenrollResponse)
      expect(unenroll_response.id).to eq("factor-to-remove")

      expect(client).to have_received(:_request).with("DELETE", "factors/#{factor_id}", anything)
    end
  end

  describe "list_factors with correct categorization" do
    it "returns enrolled factors categorized into totp and phone (verified only)" do
      setup_session(client, mock_session)

      allow(client).to receive(:get_user).and_return(
        Supabase::Auth::Types::UserResponse.new(
          user: Supabase::Auth::Types::User.new(
            id: "uid", aud: "aud", app_metadata: {}, user_metadata: {},
            created_at: Time.now, updated_at: Time.now,
            factors: [
              Supabase::Auth::Types::Factor.new(id: "f1", factor_type: "totp", status: "verified",
                                                friendly_name: "work-totp"),
              Supabase::Auth::Types::Factor.new(id: "f2", factor_type: "phone", status: "verified",
                                                friendly_name: "my-phone"),
              Supabase::Auth::Types::Factor.new(id: "f3", factor_type: "totp", status: "unverified",
                                                friendly_name: "pending-totp"),
              Supabase::Auth::Types::Factor.new(id: "f4", factor_type: "phone", status: "unverified",
                                                friendly_name: "pending-phone")
            ]
          )
        )
      )

      response = client.mfa.list_factors

      expect(response).to be_a(Supabase::Auth::Types::AuthMFAListFactorsResponse)

      # All factors returned regardless of status
      expect(response.all.length).to eq(4)

      # Only verified factors in categorized arrays
      expect(response.totp.length).to eq(1)
      expect(response.totp.first.id).to eq("f1")
      expect(response.totp.first.factor_type).to eq("totp")

      expect(response.phone.length).to eq(1)
      expect(response.phone.first.id).to eq("f2")
      expect(response.phone.first.factor_type).to eq("phone")
    end
  end

  describe "get_authenticator_assurance_level" do
    it "returns correct AAL levels based on JWT and verified factors" do
      # JWT with aal1 and password method
      payload = {
        "aal" => "aal1",
        "amr" => [{ "method" => "password", "timestamp" => Time.now.to_i }],
        "sub" => "user-id",
        "exp" => Time.now.to_i + 3600
      }
      jwt = JWT.encode(payload, "test-secret", "HS256")

      user_with_verified_factor = Supabase::Auth::Types::User.new(
        id: "uid", aud: "aud", app_metadata: {}, user_metadata: {},
        created_at: Time.now, updated_at: Time.now,
        factors: [
          Supabase::Auth::Types::Factor.new(id: "f1", factor_type: "totp", status: "verified")
        ]
      )

      session_with_factors = Supabase::Auth::Types::Session.new(
        access_token: jwt, refresh_token: "r", expires_in: 3600,
        expires_at: Time.now.to_i + 3600, token_type: "bearer",
        user: user_with_verified_factor
      )
      setup_session(client, session_with_factors)

      response = client.mfa.get_authenticator_assurance_level

      expect(response).to be_a(Supabase::Auth::Types::AuthMFAGetAuthenticatorAssuranceLevelResponse)
      expect(response.current_level).to eq("aal1")
      # With verified factors, next_level should be aal2
      expect(response.next_level).to eq("aal2")
      expect(response.current_authentication_methods.length).to eq(1)
      expect(response.current_authentication_methods.first["method"]).to eq("password")
    end

    it "returns nil levels when no session exists" do
      response = client.mfa.get_authenticator_assurance_level

      expect(response.current_level).to be_nil
      expect(response.next_level).to be_nil
      expect(response.current_authentication_methods).to eq([])
    end

    it "returns current AAL as next_level when no verified factors exist" do
      payload = { "aal" => "aal1", "amr" => [], "sub" => "user-id", "exp" => Time.now.to_i + 3600 }
      jwt = JWT.encode(payload, "test-secret", "HS256")

      session = Supabase::Auth::Types::Session.new(
        access_token: jwt, refresh_token: "r", expires_in: 3600,
        expires_at: Time.now.to_i + 3600, token_type: "bearer",
        user: Supabase::Auth::Types::User.new(
          id: "uid", aud: "aud", app_metadata: {}, user_metadata: {},
          created_at: Time.now, updated_at: Time.now, factors: []
        )
      )
      setup_session(client, session)

      response = client.mfa.get_authenticator_assurance_level

      expect(response.current_level).to eq("aal1")
      expect(response.next_level).to eq("aal1")
    end
  end
end

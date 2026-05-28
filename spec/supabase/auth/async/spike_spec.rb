# frozen_string_literal: true

# Spike: prove Supabase::Auth::Async::Client#sign_in_with_password works against
# a live GoTrue server using Faraday + async-http-faraday + ::Async, and that N
# concurrent calls in one Async block actually run concurrently (not serially).
#
# Requires the docker-compose infra (port 9998 — autoconfirm-on) to be running.
# Skips if it isn't, so the rest of the suite isn't blocked.

require "spec_helper"
require "async"
require "supabase/auth/async/client"

RSpec.describe Supabase::Auth::Async::Client do
  let(:url) { TestClients::GOTRUE_URL_SIGNUP_ENABLED_AUTO_CONFIRM_ON }
  let(:async_client) { described_class.new(url: url) }

  let(:user_credentials) { mock_user_credentials }

  before(:each) do
    WebMock.allow_net_connect! if defined?(WebMock)
    # The autoconfirm port (9998) auto-confirms emails on sign_up, so the user can
    # sign in immediately. Admin#create_user does NOT auto-confirm, so we go through
    # the public signup path here.
    sync_client = Supabase::Auth::Client.new(url: url, persist_session: false)
    sync_client.sign_up(
      email: user_credentials[:email],
      password: user_credentials[:password]
    )
  rescue Errno::ECONNREFUSED, Supabase::Auth::Errors::AuthRetryableError
    skip "GoTrue infra not running (docker compose -f infra/docker-compose.yml up -d)"
  end

  describe "#sign_in_with_password (single call)" do
    it "returns AuthResponse with a populated session.access_token" do
      response = nil
      Async do
        response = async_client.sign_in_with_password(
          email: user_credentials[:email],
          password: user_credentials[:password]
        )
      end.wait

      expect(response).to be_a(Supabase::Auth::Types::AuthResponse)
      expect(response.session).not_to be_nil
      expect(response.session.access_token).to be_a(String)
      expect(response.user.email).to eq(user_credentials[:email])
    end

    it "raises AuthInvalidCredentialsError when password missing" do
      Async do
        expect {
          async_client.sign_in_with_password(email: user_credentials[:email])
        }.to raise_error(Supabase::Auth::Errors::AuthInvalidCredentialsError)
      end.wait
    end
  end

  describe "concurrency proof" do
    # 5 concurrent sign-ins run in one Async block. If async-http-faraday is wired
    # correctly, total wall time stays close to a single request's time. If the
    # adapter blocks the thread between requests, wall time scales ~5x.
    it "runs N concurrent sign_in_with_password calls in fiber-parallel" do
      # Warm up + measure a baseline single-call latency.
      baseline_t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      Async do
        async_client.sign_in_with_password(
          email: user_credentials[:email],
          password: user_credentials[:password]
        )
      end.wait
      baseline_ms = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - baseline_t0) * 1000

      n = 5
      concurrent_t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      responses = []
      Async do |task|
        tasks = Array.new(n) do
          task.async do
            async_client.sign_in_with_password(
              email: user_credentials[:email],
              password: user_credentials[:password]
            )
          end
        end
        responses = tasks.map(&:wait)
      end.wait
      concurrent_ms = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - concurrent_t0) * 1000

      expect(responses.length).to eq(n)
      responses.each do |r|
        expect(r.session.access_token).to be_a(String)
      end

      # Sanity threshold: concurrent total should be < 3x the baseline (we expect ~1x
      # in a fiber-parallel setup; serial execution would hit ~n × baseline = 5x).
      expect(concurrent_ms).to be < (baseline_ms * 3),
                               "Expected ~#{baseline_ms.round}ms concurrent (fiber-parallel), got #{concurrent_ms.round}ms — adapter may be blocking"
    end
  end
end

# frozen_string_literal: true

module Supabase
  module Auth
    module Async
      # Async counterpart to {Supabase::Auth::AdminOAuthApi}.
      #
      # Behavior is identical — it delegates to the wrapped {AdminApi}'s
      # underscored methods. The wrapped admin uses the async Faraday adapter,
      # so calls inside `Async do ... end` yield to the reactor on I/O.
      class AdminOAuthApi < Supabase::Auth::AdminOAuthApi
      end
    end
  end
end

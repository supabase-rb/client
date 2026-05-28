# frozen_string_literal: true

module Supabase
  module Auth
    # OAuth 2.1 client administration. Mirrors supabase-py's SyncGoTrueAdminOAuthAPI.
    # Only relevant when the OAuth 2.1 server is enabled in Supabase Auth.
    # Accessed via {AdminApi#oauth}; delegates to the underscored implementations on AdminApi.
    class AdminOAuthApi
      # @param admin [AdminApi]
      def initialize(admin)
        @admin = admin
      end

      # @param params [Hash, Types::PageParams, nil] optional :page / :per_page
      # @return [Types::OAuthClientListResponse]
      def list_clients(params = nil)
        @admin._list_oauth_clients(params)
      end

      # @param params [Hash] new client attributes (client_name, redirect_uris, etc.)
      # @return [Types::OAuthClientResponse]
      def create_client(params)
        @admin._create_oauth_client(params)
      end

      # @param client_id [String] OAuth client UUID
      # @return [Types::OAuthClientResponse]
      def get_client(client_id)
        @admin._get_oauth_client(client_id)
      end

      # @param client_id [String] OAuth client UUID
      # @param params [Hash] attributes to update
      # @return [Types::OAuthClientResponse]
      def update_client(client_id, params)
        @admin._update_oauth_client(client_id, params)
      end

      # @param client_id [String] OAuth client UUID
      def delete_client(client_id)
        @admin._delete_oauth_client(client_id)
      end

      # @param client_id [String] OAuth client UUID
      # @return [Types::OAuthClientResponse] response with rotated client_secret
      def regenerate_client_secret(client_id)
        @admin._regenerate_oauth_client_secret(client_id)
      end
    end
  end
end

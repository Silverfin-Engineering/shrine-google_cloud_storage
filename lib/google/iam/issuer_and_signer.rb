# frozen_string_literal: true
require "google/apis/iamcredentials_v1"

module Google
  module IAM
    module IssuerAndSigner
      class MetadataServerNotFoundError < StandardError; end
      class MetadataServerError < StandardError; end

      # Inspired by https://github.com/rails/rails/blob/bc727a04b7dcac8211b1bda5ea714ce6988b4c1d/activestorage/lib/active_storage/service/gcs_service.rb#L199-L209
      def issuer
        @@issuer ||= email_from_metadata_server
      end

      def email_from_metadata_server
        env = Google::Cloud.env
        raise MetadataServerNotFoundError, "No Google::Cloud environment metadata present" if !env.metadata?

        email = env.lookup_metadata("instance", "service-accounts/default/email")
        email.presence or raise MetadataServerError, "No email found in Google::Cloud environment metadata"
      end

      # Inspired by https://github.com/googleapis/google-cloud-ruby/blob/f0fc4b35418a05288283c67b43562a84c5a5c6e7/google-cloud-storage/lib/google/cloud/storage/file.rb#L1834-L1866
      def signer
        lambda do |string_to_sign|
          iam_client = Google::Apis::IamcredentialsV1::IAMCredentialsService.new

          scopes = ["https://www.googleapis.com/auth/iam"]
          iam_client.authorization = Google::Auth.get_application_default(scopes)

          request = Google::Apis::IamcredentialsV1::SignBlobRequest.new(
            payload: string_to_sign
          )
          resource = "projects/-/serviceAccounts/#{issuer}"
          response = iam_client.sign_service_account_blob(resource, request)
          response.signed_blob
        end
      end
    end
  end
end

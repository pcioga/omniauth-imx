# frozen_string_literal: true

require 'omniauth-oauth2'
require 'httparty'
require 'jwt'

module OmniAuth
  module Strategies
    class Imx < OmniAuth::Strategies::OAuth2
      JWKS_URL = 'https://auth.immutable.com/.well-known/jwks.json'

      option :name, 'imx'

      def request_phase
        raise NotImplementedError, 'Frontend should handle this!'
      end

      def callback_phase
        # Get the tokens from the request (frontend should pass them)
        id_token = request.params['id_token']
        access_token = request.params['access_token']

        if id_token && access_token
          auth_hash = OmniAuth::AuthHash.new({
                                               'uid' => uid,
                                               'info' => info,
                                               'extra' => extra
                                             })
          env['omniauth.auth'] = auth_hash
          Rails.logger.info "AUTH HASH: #{auth_hash}"

          params = { next_url: request.params['next_url'] }
          env['omniauth.params'] = params.with_indifferent_access

          call_app!
        else
          fail!(:invalid_credentials, 'Missing tokens')
        end
      end

      uid do
        id_token_payload['sub']
      end

      info do
        {
          email: id_token_payload['email']
        }
      end

      extra do
        {
          raw_info: id_token_payload
        }
      end

      # Helper method to decode the ID token (you might need to install the 'jwt' gem for this)
      def id_token_payload
        rsa_key = fetch_rsa_key
        return unless rsa_key

        begin
          @id_token_payload ||= JWT.decode(
            request.params['id_token'],
            rsa_key,
            true,
            {
              algorithm: 'RS256',
              verify_expiration: true,
              verify_iss: true,
              iss: 'https://auth.immutable.com/'
            }
          ).first
        rescue JWT::DecodeError => e
          Rails.logger.error "JWT Decode Error: #{e.message}"
          {}
        end
      rescue ::JWT::DecodeError
        {}
      end

      private

      def fetch_rsa_key
        header = decode_header
        return unless header

        jwks = fetch_jwks
        matching_key = jwks.find { |key| key['kid'] == header['kid'] }
        build_rsa_key(matching_key) if matching_key
      end

      def decode_header
        header_segment = request.params['id_token'].split('.').first
        decoded_header = Base64.urlsafe_decode64(header_segment)
        JSON.parse(decoded_header)
      rescue StandardError
        nil
      end

      def fetch_jwks
        response = HTTParty.get(JWKS_URL)
        if response.success?
          JSON.parse(response.body)['keys']
        else
          Rails.logger.error "Failed to fetch JWKS: #{response.code} #{response.message}"
          []
        end
      rescue HTTParty::Error => e
        Rails.logger.error "HTTParty Error: #{e.message}"
        []
      rescue StandardError => e
        Rails.logger.error "Standard Error: #{e.message}"
        []
      end

      def build_rsa_key(key_data)
        n = Base64.urlsafe_decode64(key_data['n'])
        e = Base64.urlsafe_decode64(key_data['e'])

        sequence = OpenSSL::ASN1::Sequence.new([
                                                 OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(n, 2)),
                                                 OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(e, 2))
                                               ])
        OpenSSL::PKey::RSA.new(sequence.to_der)
      end
    end
  end
end

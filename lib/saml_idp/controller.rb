# encoding: utf-8
require 'openssl'
require 'base64'
require 'time'
require 'uuid'
require 'saml_idp/request'
require 'saml_idp/logout_response_builder'
module SamlIdp
  module Controller
    extend ActiveSupport::Concern

    included do
      helper_method :saml_acs_url if respond_to? :helper_method
    end

    attr_accessor :algorithm

    protected

    def saml_request
      @saml_request ||= Struct.new(:request_id) do
        def authn_request?
          true
        end

        def issuer
          nil
        end

        def acs_url
          nil
        end
      end.new(nil)
    end

    def validate_saml_request
      decode_request(params[:SAMLRequest])
      if (http_redirect_binding? && !valid_http_redirect_binding_signature?) || !valid_saml_request?
        if Rails::VERSION::MAJOR >= 4
          head :forbidden
        else
          render nothing: true, status: :forbidden
        end
      end
    end

    def decode_request(raw_saml_request)
      @saml_request = Request.from_deflated_request(raw_saml_request)
    end

    def authn_context_classref
      Saml::XML::Namespaces::AuthnContext::ClassRef::PASSWORD
    end

    def encode_authn_response(principal, opts = {})
      response_id = get_saml_response_id
      reference_id = opts[:reference_id] || get_saml_reference_id
      audience_uri = opts[:audience_uri] || saml_request.issuer || saml_acs_url[/^(.*?\/\/.*?\/)/, 1]
      opt_issuer_uri = opts[:issuer_uri] || issuer_uri
      my_authn_context_classref = opts[:authn_context_classref] || authn_context_classref
      acs_url = opts[:acs_url] || saml_acs_url
      expiry = opts[:expiry] || 60*60
      session_expiry = opts[:session_expiry]
      encryption_opts = opts[:encryption] || nil

      SamlResponse.new(
        reference_id,
        response_id,
        opt_issuer_uri,
        principal,
        audience_uri,
        saml_request_id,
        acs_url,
        (opts[:algorithm] || algorithm || default_algorithm),
        my_authn_context_classref,
        expiry,
        encryption_opts,
        session_expiry
      ).build
    end

    def encode_logout_response(principal, opts = {})
      SamlIdp::LogoutResponseBuilder.new(
        get_saml_response_id,
        (opts[:issuer_uri] || issuer_uri),
        saml_logout_url,
        saml_request_id,
        (opts[:algorithm] || algorithm || default_algorithm)
      ).signed
    end

    def encode_response(principal, opts = {})
      if saml_request.authn_request?
        encode_authn_response(principal, opts)
      elsif saml_request.logout_request?
        encode_logout_response(principal, opts)
      else
        raise "Unknown request: #{saml_request}"
      end
    end

    def issuer_uri
      (SamlIdp.config.base_saml_location.present? && SamlIdp.config.base_saml_location) ||
        (defined?(request) && request.url.to_s.split("?").first) ||
        "http://example.com"
    end

    def valid_saml_request?
      saml_request.valid?(!http_redirect_binding?)
    end

    def http_redirect_binding?
      params[:Signature].present? && params[:SigAlg].present?
    end

    def valid_http_redirect_binding_signature?
      # todo add check on SP validate_signature setting
      puts 'http_redirect_binding signature validation ....'
      type = params.keys.find{|p| p.start_with? 'SAML'}
      query_string = OneLogin::RubySaml::Utils.build_query(type: type, data: params[type], relay_state: params['RelayState'], sig_alg: params['SigAlg'])
      cert = OpenSSL::X509::Certificate.new(saml_request.service_provider.cert)
      sig_alg = ::XMLSecurity::BaseDocument.new.algorithm(params[:SigAlg])
      signature = params[:Signature]
      OneLogin::RubySaml::Utils.verify_signature(cert: cert, sig_alg: sig_alg, signature: signature, query_string: query_string)
    rescue
      false
    end

    def saml_request_id
      saml_request.request_id
    end

    def saml_acs_url
      saml_request.acs_url
    end

    def saml_logout_url
      saml_request.logout_url
    end

    def get_saml_response_id
      UUID.generate
    end

    def get_saml_reference_id
      UUID.generate
    end

    def default_algorithm
      OpenSSL::Digest::SHA256
    end
  end
end

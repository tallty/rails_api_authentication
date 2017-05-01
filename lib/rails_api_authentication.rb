require "rails_api_authentication/version"
require "rails_api_authentication/configuration"
require "rails_api_authentication/auth_action"
require "rails_api_authentication/auth_session"
require "rails_api_authentication/auth_token"
require "rails_api_authentication/authable"
require "rails_api_authentication/acts_as_authenticationable"
require "rails_api_authentication/acts_as_authentication_handler"

module RailsApiAuthentication
  extend Configuration

  private

  def self.ensure_models_can_act_as_token_authenticatables model_adapters
    model_adapters.each do |model_adapter|
      model_adapter.base_class.send :extend, RailsApiAuthentication::ActsAsAuthenticationable
    end
  end

  def self.ensure_controllers_can_act_as_token_authentication_handlers controller_adapters
    controller_adapters.each do |controller_adapter|
      controller_adapter.base_class.send :extend, RailsApiAuthentication::ActsAsAuthenticationHandler
    end
  end

  available_model_adapters = load_available_adapters RailsApiAuthentication.model_adapters
  ensure_models_can_act_as_token_authenticatables available_model_adapters

  available_controller_adapters = load_available_adapters RailsApiAuthentication.controller_adapters
  ensure_controllers_can_act_as_token_authentication_handlers available_controller_adapters
end

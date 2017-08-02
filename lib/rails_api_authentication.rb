require "rails_api_authentication/version"
require "rails_api_authentication/configuration"
require "rails_api_authentication/auth_action"
require "rails_api_authentication/auth_session"
require "rails_api_authentication/code_session"
require "rails_api_authentication/auth_password"
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

  # Private: Load the available adapters.
  #
  # adapters_short_names - Array of names of the adapters to load if available
  #
  # Example
  #
  #    load_available_adapters ['unavailable_adapter', 'available_adapter']
  #    # => [RailsApiAuthentication::Adapters::AvailableAdapter]
  #
  # Returns an Array of available adapters
  def self.load_available_adapters adapters_short_names
    available_adapters = adapters_short_names.collect do |short_name|
      next if short_name == 'rails' && (ActiveSupport.respond_to?(:version) && ActiveSupport.version >= Gem::Version.new('4.1.0'))
      next if short_name == 'rails_api' && (ActiveSupport.respond_to?(:version) && ActiveSupport.version >= Gem::Version.new('5.0.0'))
      adapter_name = "rails_api_authentication/adapters/#{short_name}_adapter"
      if adapter_dependency_fulfilled?(short_name) && require(adapter_name)
        adapter_name.camelize.constantize
      end
    end
    available_adapters.compact!

    available_adapters
  end

  def self.adapter_dependency_fulfilled? adapter_short_name
    dependency = RailsApiAuthentication.adapters_dependencies[adapter_short_name]

    if !respond_to?(:qualified_const_defined?) || (ActiveSupport.respond_to?(:version) && ActiveSupport.version.to_s =~ /^5\.0/)
      # See https://github.com/gonzalo-bulnes/simple_token_authentication/pull/229/commits/74eda6c28cd0b45636c466de56f2dbaca5c5b629#r57507423
      const_defined?(dependency)
    else
      qualified_const_defined?(dependency)
    end
  end

  available_model_adapters = load_available_adapters RailsApiAuthentication.model_adapters
  ensure_models_can_act_as_token_authenticatables available_model_adapters

  available_controller_adapters = load_available_adapters RailsApiAuthentication.controller_adapters
  ensure_controllers_can_act_as_token_authentication_handlers available_controller_adapters
end

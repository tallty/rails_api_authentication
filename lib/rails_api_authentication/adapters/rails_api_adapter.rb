require 'action_controller'
require 'rails_api_authentication/adapter'

module RailsApiAuthentication
  module Adapters
    class RailsAPIAdapter
      extend RailsApiAuthentication::Adapter

      def self.base_class
        ::ActionController::API
      end
    end

    # make the adpater available even if the 'API' acronym is not defined
    RailsApiAdapter = RailsAPIAdapter
  end
end


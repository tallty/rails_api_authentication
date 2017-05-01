require 'action_controller'
require 'rails_api_authentication/adapter'

module RailsApiAuthentication
  module Adapters
    class RailsMetalAdapter
      extend RailsApiAuthentication::Adapter

      def self.base_class
        ::ActionController::Metal
      end
    end
  end
end

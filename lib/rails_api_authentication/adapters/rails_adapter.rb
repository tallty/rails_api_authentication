require 'action_controller'
require 'rails_api_authentication/adapter'

module RailsApiAuthentication
  module Adapters
    class RailsAdapter
      extend RailsApiAuthentication::Adapter

      def self.base_class
        ::ActionController::Base
      end
    end
  end
end

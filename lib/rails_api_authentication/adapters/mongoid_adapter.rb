require 'mongoid'
require 'rails_api_authentication/adapter'

module RailsApiAuthentication
  module Adapters
    class MongoidAdapter
      extend RailsApiAuthentication::Adapter

      def self.base_class
        ::Mongoid::Document
      end
    end
  end
end

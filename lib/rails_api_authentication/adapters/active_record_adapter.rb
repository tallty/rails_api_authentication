require 'active_record'
require 'rails_api_authentication/adapter'

module RailsApiAuthentication
  module Adapters
    class ActiveRecordAdapter
      extend RailsApiAuthentication::Adapter

      def self.base_class
        ::ActiveRecord::Base
      end
    end
  end
end

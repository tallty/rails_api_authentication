module RailsApiAuthentication
  module Configuration
    mattr_accessor :controller_adapters
    mattr_accessor :model_adapters
    mattr_accessor :adapters_dependencies

    @@controller_adapters = ['rails', 'rails_api', 'rails_metal']
    @@model_adapters = ['active_record', 'mongoid']
    @@adapters_dependencies = { 'active_record' => 'ActiveRecord::Base',
                                'mongoid'       => 'Mongoid::Document',
                                'rails'         => 'ActionController::Base',
                                'rails_api'     => 'ActionController::API',
                                'rails_metal'   => 'ActionController::Metal' }
  end
end

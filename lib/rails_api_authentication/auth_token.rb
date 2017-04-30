module RailsApiAuthentication
  class AuthToken < Ohm::Model
    # Authentication Token, should be unique
    attribute :token
    # authable model id, relate to the actual model
    attribute :oid
    # authable model class, relate to the actual model
    attribute :klass
    # client authentication platform, etc: ios, android, web
    attribute :platform
    # client authentication vertion, etc: 4.1.2
    attribute :version

    index :token
    unique :token
    index :klass

    def self.create(klass, params = {})
      params[:klass] = klass
      params[:token] = SecureRandom.uuid62
      super params
    end
  end
end
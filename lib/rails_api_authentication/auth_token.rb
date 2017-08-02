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
    # oauth type, etc: "wechat" "facebook"
    attribute :oauth_type
    # oauth id, like wechat openid
    attribute :oauth_id

    index :token
    unique :token
    index :klass
    index :oauth_type
    index :oauth_id

    def self.create(klass, params = {})
      params[:klass] = klass
      params[:token] = SecureRandom.uuid62
      super params
    end
  end
end
module RailsApiAuthentication
  module Authable
    extend ActiveSupport::Concern

    DIGEST = Digest::SHA2.new

    included do
      attr_accessor :token

      def logout
        AuthToken.find(token: token)&.first&.delete if token.present?
      end

      def update_password password
        raise(UserError.new(401, '-1', 'password is blank')) if password.blank?
        self.update(@auth_password => generate_password(password))
      end

      def reset_password password, valid_code
        update_password(password) if self.class.valid?(self.send(@auth_key), valid_code)
      end
    end

    module ClassMethods
      attr_reader :auth_key, :auth_password, :valid_key
      
      def auth_for params
        @auth_key = params[:auth_key]&.to_sym || :name
        @auth_password = params[:auth_password]&.to_sym || :password
      end

      def valid_for params
        @valid_key = params[:key]&.to_sym || :valid_code
        @valid_expire = params[:expire]&.to_sym || 60
        @valid_length = params[:length]&.to_sym || 4
      end

      def generate_valid_code name
        code = (0..9).to_a.sample(@valid_length).join
        $redis.setex("#{self}::#{name}", @valid_expire, code)
        code
      end

      def login(name, password)
        user = self.find_by(@auth_key => name)
        raise(UserError.new(401, '-1', 'Unauthorized')) if user.nil?
        salted = user.password.split(':')
        raise(UserError.new(401, '-1', 'Unauthorized')) unless salt(password, salted[1]) == salted[0]
        AuthToken.create(self, { oid: user.id })
      end

      def auth!(request)
        user = auth(request)
        user.nil? ? raise(UserError.new(401, '-1', 'Unauthorized')) : user
      end

      def register(name, password, attrs={})
        raise(UserError.new(401, '-1', 'password is blank')) if password.blank?
        raise(UserError.new(401, '-1', 'valid token is not correct')) unless valid?(name, attrs.delete(@valid_key))
        self.create!({@auth_key => name, @auth_password => generate_password(password)}.merge attrs)
      rescue ActiveRecord::RecordInvalid => e
        raise UserError.new(401, '-1', e.message)
      end

      def register_with(attrs={})
        attrs = attrs.clone
        name = attrs.delete @auth_key
        password = attrs.delete @auth_password
        register(name, password, attrs)
      end

      private

      def salt(password, suffix)
        5.times { password = DIGEST.digest(password + suffix) }
        password.unpack('H*')[0]
      end

      def generate_password(password)
        suffix = SecureRandom.hex 8
        "#{salt(password, suffix)}:#{suffix}"
      end

      def valid? name, valid_code
        @valid_key.blank? || (valid_code.present? && valid_code == $redis.get("#{self}::#{name}"))
      end

      def auth(request)
        token = request.env["HTTP_#{self.to_s.upcase}_TOKEN"] || request.env["#{self.to_s.upcase}_TOKEN"]
        auth = AuthToken.find(token: token)&.first
        if auth.nil?
          nil
        else
          user = self.find_by(id: auth.oid)
          user.token = auth.token
          user
        end
      end
    end
  end

  class UserError < RuntimeError
    attr_reader :status, :code, :message
    def initialize(status, code, message)
      super()
      @status = status
      @code = code
      @message = message
    end
  end
end


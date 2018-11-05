module RailsApiAuthentication
  module Authable
    extend ActiveSupport::Concern

    DIGEST = Digest::SHA2.new

    included do
      attr_accessor :token, :auth

      def logout
        AuthToken.find(token: token)&.first&.delete if token.present?
      end

      def password_raw= password
        self.update_password(password)
      end

      def update_password password
        raise(UserError.new(400, '-1', 'password is blank')) if password.blank?
        auth_password = self.class.auth_password
        self.update(auth_password => self.class.send(:generate_password, password))
      end

      def reset_password password, valid_code
        auth_key = self.class.auth_key
        update_password(password) if self.class.valid!(self.send(auth_key), valid_code)
      end
    end

    module ClassMethods
      attr_reader :valid_key, :oauth_enable, :oauth_only

      def auth_for params
        @auth_key = params[:auth_key]&.to_sym || :name
        @auth_password = params[:auth_password]&.to_sym || :password
      end

      def auth_key
        @auth_key || superclass.auth_key
      end

      def auth_password
        @auth_password || superclass.auth_password
      end

      def valid_for params
        @valid_key = params[:key]&.to_sym || :valid_code
        @valid_expire = params[:expire]&.to_sym || 600
        @valid_length = params[:length]&.to_sym || 4
        @valid_god = params[:god]
      end

      def code_for params
        @auth_key = params[:auth_key]&.to_sym || :name
        valid_for params
      end

      def oauth_for params={}
        @oauth_enable = params[:enable] || true
        @oauth_only = params[:only] || false
      end

      def generate_valid_code name
        code = (0..9).to_a.sample(@valid_length).join
        $redis.setex("#{self}::#{name}", @valid_expire, code)
        code
      end

      def code_login name, code, params={}
        raise(UserError.new(401, '-1', "The authorization need password")) if @auth_password.present?
        valid! name, code
        user = self.find_or_create_by(auth_key => name)
        raise(UserError.new(401, '-1', 'Unauthorized')) if user.nil?
        AuthToken.create(self, oauth_params(params).merge({ oid: user.id }) )
      rescue ActiveRecord::RecordInvalid => e
        raise UserError.new(400, '-1', e.message)
      end

      def login(name, password, params={})
        user = self.find_by(auth_key => name)
        raise(UserError.new(401, '-1', 'Unauthorized')) if user.nil?
        salted = user.password.split(':')
        raise(UserError.new(401, '-1', 'Unauthorized')) unless salted[1].present? && salt(password, salted[1]) == salted[0]
        AuthToken.create(self, oauth_params(params).merge({ oid: user.id }) )
      end

      def oauth_login(oauth_type, oauth_id)
        if @oauth_only.present?
          user = self.find_or_create_by oauth_type: oauth_type, oauth_id: oauth_id
          AuthToken.create(
            self, {oid: user.id, oauth_type: oauth_type, oauth_id: oauth_id }
          )
        else
          auth = AuthToken.find(oauth_type: oauth_type, oauth_id: oauth_id)&.first
          user = self.find_by(id: auth&.oid)
          raise(UserError.new(401, '-1', 'Unauthorized')) unless user.present?
          auth
        end
      end

      def oauth_relate(token, oauth_type, oauth_id)
        auth = AuthToken.find(token: token)&.first
        if auth.present? && self.find_by(id: auth.oid).present?
          AuthToken.find(oauth_type: oauth_type, oauth_id: oauth_id)&.each { |auth_token| auth_token.delete }
          auth.update(oauth_type: oauth_type, oauth_id: oauth_id)
        else
          raise(UserError.new(401, '-1', 'Unauthorized')) unless user.present?
        end
      end

      def auth!(request)
        token = request.env["HTTP_#{token_key}_TOKEN"] || request.env["#{token_key}_TOKEN"]
        user = auth(token)
        user || raise(UserError.new(401, '-1', 'Unauthorized'))
      end

      attr_writer :token_key

      def token_key
        @token_key ||= self.to_s.upcase
      end

      def register(name, password, attrs={})
        raise(UserError.new(400, '-1', 'password is blank')) if password.blank?
        valid! name, attrs.delete(@valid_key)
        user = self.create!({auth_key => name, @auth_password => generate_password(password)})
        user.token = AuthToken.create(self, oauth_params(attrs).merge({ oid: user.id }) ).token
        user
      rescue ActiveRecord::RecordInvalid => e
        raise UserError.new(400, '-1', e.message)
      end

      def register_with(attrs={})
        attrs = attrs.clone
        name = attrs.delete auth_key
        password = attrs.delete @auth_password
        register(name, password, attrs)
      end

      def valid! name, valid_code
        raise(UserError.new(401, '-1', 'valid token is not correct')) unless valid?(name, valid_code)
        true
      end

      private

      def oauth_params params
        params.select { |k, v| [:oauth_type, :oauth_id].include? k&.to_sym  }
      end

      def salt(password, suffix)
        5.times { password = DIGEST.digest(password + suffix) }
        password.unpack('H*')[0]
      end

      def generate_password(password)
        suffix = SecureRandom.hex 8
        "#{salt(password, suffix)}:#{suffix}"
      end

      def valid? name, valid_code
        @valid_key.blank? ||
        ( @valid_god.present? && valid_code == @valid_god ) ||
        ( valid_code.present? && valid_code == $redis.get("#{self}::#{name}") )
      end

      def auth(token)
        auth = AuthToken.find(token: token)&.first
        if auth && (user = find_by(id: auth.oid))
          user.token = auth.token
          user.auth = auth
          user
        end
      end
    end
  end
end


module RailsApiAuthentication
  module AuthSession
    extend ActiveSupport::Concern

    included do
    end

    def create
      auth_key = self.class.klass.auth_key
      auth_password = self.class.klass.auth_password
      @auth_token = self.class.klass.login(session_params.delete(auth_key), session_params.delete(auth_password), session_params)
      render json: { token: @auth_token.token }, status: 200
    rescue UserError => e
      render json: { error: e.message }, status: e.status
    end

    def destroy
      self.send("current_#{self.class.klass_sym}")&.logout
      render json: { message: "logout successful" }, status: 200
    end

    private 
      def session_params
        auth_key = self.class.klass.auth_key
        auth_password = self.class.klass.auth_password
        oauth_enable = self.class.oauth_enable
        if oauth_enable
          params.require(self.class.klass_sym).permit(auth_key, auth_password, :oauth_type, :oauth_id)
        else
          params.require(self.class.klass_sym).permit(auth_key, auth_password)
        end
      end

    module ClassMethods
      attr_reader :klass, :klass_sym
      def auth_session klass_sym
        @klass = klass_sym.to_s.camelize.constantize
        @klass_sym = klass_sym
      end
    end
  end
end

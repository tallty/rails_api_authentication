module RailsApiAuthentication
  module AuthSession
    extend ActiveSupport::Concern

    included do
    end

    def create
      auth_key = self.class.klass.auth_key
      auth_password = self.class.klass.auth_password
      @auth_token = self.class.klass.login(session_params[auth_key], session_params[auth_password])
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
        params.require(self.class.klass_sym).permit(auth_key, auth_password)
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

module RailsApiAuthentication
  module CodeSession
    extend ActiveSupport::Concern

    included do
    end

    def create
      auth_key = self.class.klass.auth_key
      valid_key = self.class.klass.valid_key
      @auth_token = self.class.klass.code_login(session_params[auth_key], session_params[valid_key])
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
        valid_key = self.class.klass.valid_key
        params.require(self.class.klass_sym).permit(auth_key, valid_key)
      end

    module ClassMethods
      attr_reader :klass, :klass_sym
      def code_session klass_sym
        @klass = klass_sym.to_s.camelize.constantize
        @klass_sym = klass_sym
      end
    end
  end
end

module RailsApiAuthentication
  module AuthPassword
    extend ActiveSupport::Concern

    included do
    end

    # Reset password with token
    def create
      auth_password = self.class.klass.auth_password
      valid_key = self.class.klass.valid_key
      self.send("current_#{self.class.klass_sym}")&.reset_password(reset_password_params[auth_password], reset_password_params[valid_key])
      render json: { meesage: "reset password successful"}, status: 200
    rescue UserError => e
      render json: { error: e.message }, status: e.status
    end

    # Update password when the auth is pass
    def update
      auth_password = self.class.klass.auth_password
      self.send("current_#{self.class.klass_sym}")&.update_password(password_params[auth_password])
      render json: { meesage: "update password successful"}, status: 200
    rescue UserError => e
      render json: { error: e.message }, status: e.status
    end

    private
      def password_params
        auth_password = self.class.klass.auth_password
        params.require(self.class.klass_sym).permit(auth_password)
      end

      def reset_password_params
        auth_password = self.class.klass.auth_password
        valid_key = self.class.klass.valid_key
        params.require(self.class.klass_sym).permit(
          auth_password, valid_key
        )
      end

    module ClassMethods
      attr_reader :klass, :klass_sym
      def auth_password klass_sym
        @klass = klass_sym.to_s.camelize.constantize
        @klass_sym = klass_sym
      end
    end
  end
end

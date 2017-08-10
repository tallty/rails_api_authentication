module RailsApiAuthentication
  module OauthSession
    extend ActiveSupport::Concern

    included do
    end

    def create
      @auth_token = self.class.klass.oauth_login(session_params.delete(:oauth_type), session_params.delete(:oauth_id))
      render json: { token: @auth_token.token }, status: 200
    rescue UserError => e
      render json: { error: e.message }, status: e.status
    end

    def update
      @auth_token = self.class.klass.oauth_relate(
        self.send("current_#{self.class.klass_sym}")&.token,
        session_params.delete(:oauth_type),
        session_params.delete(:oauth_id),
      )
      render json: { token: @auth_token.token }, status: 200
    rescue UserError => e
      render json: { error: e.message }, status: e.status
    end

    def destroy
      self.send("current_#{self.class.klass_sym}")&.logout
      render json: { message: "logout successful" }, status: 200
    end

    def session_params
      params.require(self.class.klass_sym).permit(:oauth_type, :oauth_id)
    end

    module ClassMethods
      attr_reader :klass, :klass_sym
      def oauth_session klass_sym
        @klass = klass_sym.to_s.camelize.constantize
        @klass_sym = klass_sym
      end
    end
  end
end

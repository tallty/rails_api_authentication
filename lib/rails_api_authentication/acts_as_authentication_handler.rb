module RailsApiAuthentication
  module ActsAsAuthenticationHandler
    def acts_as_auth_action(klass_sym, options={})
      include RailsApiAuthentication::AuthAction
      auth_action klass_sym, options
    end

    def acts_as_auth_session(klass_sym)
      include RailsApiAuthentication::AuthAction
      include RailsApiAuthentication::AuthSession
      auth_action klass_sym, only: [:destroy]
      auth_session klass_sym
    end

    def acts_as_auth_password(klass_sym)
      include RailsApiAuthentication::AuthAction
      include RailsApiAuthentication::AuthPassword
      auth_action klass_sym, only: [:update]
      auth_password klass_sym
    end
  end
end

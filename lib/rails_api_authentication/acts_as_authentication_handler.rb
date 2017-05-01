module RailsApiAuthentication
  module ActsAsAuthenticationHandler
    def acts_as_auth_action(klass_sym, options={})
      include RailsApiAuthentication::AuthAction
      auth_action klass_sym, options
    end

    def acts_as_auth_session(klass_sym)
      include RailsApiAuthentication::AuthSession
      auth_session klass_sym
    end
  end
end

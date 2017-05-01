module RailsApiAuthentication
  module ActsAsAuthenticationable
    def acts_as_authentication(params = {})
      include RailsApiAuthentication::Authable
      auth_for params
    end
  end
end

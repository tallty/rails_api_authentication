module RailsApiAuthentication
  module ActsAsAuthenticationable
    def acts_as_authentication(params = {})
      include RailsApiAuthentication::Authable
      auth_for params
    end

    def acts_as_validable(params={})
      include RailsApiAuthentication::Authable
      valid_for params
    end

    def acts_as_code_authentication params={}
      include RailsApiAuthentication::Authable
      code_for params
    end

    def acts_as_oauthable params
      include RailsApiAuthentication::Authable
      oauth_for params
    end
  end
end

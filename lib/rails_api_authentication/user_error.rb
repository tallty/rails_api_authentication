module RailsApiAuthentication
  class UserError < RuntimeError
    attr_reader :status, :code, :message
    def initialize(status, code, message)
      super()
      @status = status
      @code = code
      @message = message
    end
  end
end
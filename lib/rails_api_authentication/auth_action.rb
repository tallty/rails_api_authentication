module RailsApiAuthentication
  module AuthAction
    extend ActiveSupport::Concern

    included do
      private :perform
    end

    def perform
      klass = self.class.action_class
      @current_auth = klass.send(:auth!, request)
    rescue UserError => e
      render json: e.message, status: e.status
    end

    module ClassMethods
      def auth_action klass_sym, options={}
        prepend_before_action :perform, options
        @klass = klass_sym.to_s.camelize.constantize
        define_method("current_#{klass_sym}") { @current_auth || nil }
      end

      def action_class
        @klass
      end
    end
  end
end

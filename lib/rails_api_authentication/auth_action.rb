module RailsApiAuthentication
  module AuthAction
    extend ActiveSupport::Concern

    included do
      private :perform
    end

    def perform
      klasses = self.class.action_classes
      klasses.each do |klass|
        @current_auth = klass.auth!(request) rescue next
        sym = klass.name.underscore.gsub('/', '_').to_sym
        instance_variable_set("@current_#{sym}", @current_auth)
        break
      end
      render(json: "Unauthorized", status: 401) if @current_auth.nil?
    end

    module ClassMethods
      def auth_action klass_sym, options={}
        prepend_before_action :perform, options
        define_method("current_auth") { @current_auth }

        @klasses = Array(klass_sym).map do |sym|
          define_method("current_#{sym}") { @current_auth }
          sym.to_s.camelize.constantize
        end
      end

      def action_classes
        @klasses || superclass.action_classes
      end
    end
  end
end

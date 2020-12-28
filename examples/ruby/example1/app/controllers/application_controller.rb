class ApplicationController < ActionController::Base

    def test(options)
        system("ls #{options}") # #nohorus
    end
end


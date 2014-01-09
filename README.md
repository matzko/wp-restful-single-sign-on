# RESTful Single Sign-On Plugin

RESTful Single Signon Plugin is a WordPress plugin that allows you authenticate WordPress users with a RESTful identity provider, such as a Rails application using Devise with JSON responses enabled (see below).

## Integrating with a Rails Application 
### Using Devise
Devise no longer [responds to JSON out of the box](https://github.com/plataformatec/devise/wiki/How-To:-Upgrade-to-Devise-2.2), and for good reason: responding with the resource typically returns way too much information.

So if you enable JSON responses, **make sure** that your resource exposes only the properties it should (more info below).

#### Enabling Devise JSON responses
in `config/application.rb` add the following:
``` ruby
config.to_prepare do
  DeviseController.respond_to :html, :json
end
```

#### Controlling Data in the JSON Response
If your Devise resource is the `User` model, add something like the following method to `app/models/user.rb`:

``` ruby
def as_json options={}
	{
		email: self.email,
		first_name: self.first_name,
		last_name: self.last_name,
	}
end
```

This returns only the email, first name, and last name `User` properties.

=== RESTful Single Sign-On Plugin ===
Contributors: filosofo
Donate link: https://github.com/matzko/wp-restful-single-sign-on
Tags: Rails, SSO, REST, authentication, auth
Requires at least: 3.8
Tested up to: 3.8
Stable tag: 1.0.2
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

RESTful Single Signon Plugin is a WordPress plugin that allows you authenticate WordPress users with a RESTful identity provider.

== Description ==

RESTful Single Signon Plugin is a WordPress plugin that allows you authenticate WordPress users with a RESTful identity provider, such as a Rails application using Devise with JSON responses enabled (see below).

See the FAQ for more info on how you can use this plugin to integrate with a Rails application, for example.


== Installation ==

1. Upload `wp-restful-single-sign-on` to the `/wp-content/plugins/` directory
1. Activate RESTful Single Sign-On through the 'Plugins' menu in WordPress

== Frequently Asked Questions ==

= How can I use this plugin to integrate with a Rails application? =

##### Using Devise
Devise no longer [responds to JSON out of the box](https://github.com/plataformatec/devise/wiki/How-To:-Upgrade-to-Devise-2.2), and for good reason: responding with the resource typically returns way too much information.

So if you enable JSON responses, **make sure** that your resource exposes only the properties it should (more info below).

###### Enabling Devise JSON responses
in `config/application.rb` add the following:
`
config.to_prepare do
  DeviseController.respond_to :html, :json
end
`

###### Controlling Data in the JSON Response
If your Devise resource is the `User` model, add something like the following method to `app/models/user.rb`:

`
def as_json options={}
	{
		email: self.email,
		first_name: self.first_name,
		last_name: self.last_name,
	}
end
`
This returns only the email, first name, and last name `User` properties.

== Changelog ==

= 1.0.2 = 
Handle erroroneous requests with grace.

= 1.0 =
Initial release of plugin

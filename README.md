# SignedApi

SignedApi gem offers easy way to make your web APIs secure by using secret key based signature authentication.
This uses the similar way as AWS's signed URLs.

## Installation

Add this line to your application's Gemfile:

    gem 'signed_api'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install signed_api

## Usage

### Client side
You can easily sign your params by sign_params method
```ruby
  signed_params = SignedApi::sign_params('GET', '/api/search', {a: 'param_a', b: 'param_b', c: 'param_c'}, 'SOME_KEY', 'SOME_SECRET_STRING', 60)
```
or you can directly make a signed URL like this.
```ruby
  signed_url = SignedApi::get_signed_url('https://example.com', 'GET', '/api/search', {a: 'param_a', b: 'param_b', c: 'param_c'}, 'SOME_KEY', 'SOME_SECRET_STRING', 60)
```

### Server side
You can verify the request easily.
```ruby
  begin
    SignedApi::verify_signature!(method, path, params) {|key| secrets[key]}
  rescue
    # log error and return error to the client
  end
```

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

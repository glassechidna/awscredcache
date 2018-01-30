# `awscredcache`

This is a Golang package that emulates the AWS CLI credential caching behaviour.
It saves a JSON representation of assumed roles (or MFA-authenticated session 
tokens) in the `~/.aws` directory. It is designed to be used as a standard
AWS credentials provider, e.g.

```
provider := awscredcache.NewAwsCacheCredProvider("profileName")
creds := credentials.NewCredentials(provider)
sess, err := session.NewSession(&aws.Config{Credentials: creds})
```

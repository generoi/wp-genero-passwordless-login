# wp-passwordless-login

Allows users to login to their accounts if they have access to an email account with a particular domain.

1. Visit regular /wp-login.php site
2. Fill in your email as the username and leave the password field empty, submit.
3. Open your email and click the login link.
4. Done.

## Filters

```php
// Filter which email domains are allowed to use the auth type
add_filter('passwordless_domains', [
  'example.com',
  'gogle.com',
]);
```

https://user-images.githubusercontent.com/302736/209352322-ab13609b-d9e1-401d-a193-60b4bf71fe0a.mp4

<?php

/*
Plugin Name:  WP Passwordless Login
Plugin URI:   https://genero.fi
Description:  Let users log in without a password
Version:      1.0.0
Author:       Genero
Author URI:   https://genero.fi/
License:      MIT License
*/

namespace Genero\PasswordlessLogin;

use WP_Error;
use WP_User;

defined('ABSPATH') or die();

define('PASSWORDLESS_NONCE_NAME', '_passwordless_nonce');
define('PASSWORDLESS_NONCE_ACTION', 'passwordless_login_request');
define('PASSWORDLESS_TOKEN_TTL', MINUTE_IN_SECONDS * 10);

/**
 * Add a nonce field to login form.
 */
add_action('login_form', function () {
    echo wp_nonce_field(
        PASSWORDLESS_NONCE_ACTION,
        PASSWORDLESS_NONCE_NAME,
        false,
        false
    );
});

/**
 * Attempt the authentication when visitor lands on wp-login.php from the token
 * link in the email.
 *
 * Note that this runs on priority 18, one before the step that sends the auth
 * link.
 *
 * @param WP_User|WP_Error|null $user
 */
add_filter('authenticate', function ($user) {
    if ($user instanceof WP_User) {
        return $user;
    }

    $token = sanitize_key($_GET['token'] ?? '');
    $uid = sanitize_key($_GET['uid'] ?? '');
    $nonce = sanitize_key($_GET['nonce'] ?? '');

    if (! $token || ! $uid || ! $nonce) {
        return $user;
    }

    // Avoid link protection techniques in email clients.
    if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'HEAD') {
        return $user;
    }

    if (isValidTokenLogin($uid, $token, $nonce)) {
        delete_user_meta($uid, "passwordless_{$uid}");
        delete_user_meta($uid, "passwordless_{$uid}_expiration");

        return get_user_by('id', $uid);
    }

    $error = new WP_Error();
    $error->add('passwordless_error', __('The passwordless login was unsucessful.', 'wp-passwordless-login'));
    return $error;
}, 18);

/**
 * Check if the user is attempting and is allowed to authenticate by email. This
 * attempt is recognized by leaving the password field empty which in the next
 * auth step (priority 20), would trigger an "empty password" error.
 *
 * If the email exists as a user account and is allowed to authenticate by email
 * we send a token authorized link that's valid for 10 minutes to the users
 * email address and shortcircuit all other auth methods by returning an
 * "error".
 *
 * @param WP_User|WP_Error|null $user
 */
add_filter('authenticate', function ($user, string $username, string $password) {
    if ($user instanceof WP_User) {
        return $user;
    }

    $nonce = $_POST[PASSWORDLESS_NONCE_NAME] ?? '';
    if (! wp_verify_nonce($nonce, PASSWORDLESS_NONCE_ACTION)) {
        return $user;
    }

    // Act on passwordless login only
    if (! empty($password) || empty($username) || ! is_email($username)) {
        return $user;
    }

    // Only act on allowed domain
    $passwordlessDomains = apply_filters('passwordless_domains', []);
    if (! empty($passwordlessDomains)) {
        $domain = explode('@', $username);
        $domain = array_pop($domain);
        if (! in_array($domain, $passwordlessDomains)) {
            return $user;
        }
    }

    $account = get_user_by('email', $username);
    if (! $account) {
        return $user;
    }

    $redirect = sanitize_url($_GET['redirect_to'] ?? '');
    $loginUrl = generateLoginUrl($account, $nonce, $redirect);
    if (! sendLoginLink($username, $loginUrl)) {
        return $user;
    }

    $error = new WP_Error();
    $error->add('email_sent', __('Please check your email to finish login.', 'wp-passwordless-login'));

    return $error;
}, 19, 3);

/**
 * Validate that a token is valid for the user and hasn't expired.
 */
function isValidTokenLogin(int $uid, string $token, string $nonce): bool
{
    $storedHash = get_user_meta($uid, "passwordless_{$uid}", true);
    $expiration = get_user_meta($uid, "passwordless_{$uid}_expiration", true);

    $time = time();
    $isValidToken = wp_check_password($token . $expiration, $storedHash);
    $isValidNonce = wp_verify_nonce($nonce, PASSWORDLESS_NONCE_ACTION);
    $isExpired = $expiration < $time;

    if ($isValidToken && $isValidNonce && ! $isExpired) {
        return true;
    }
    return false;
}

/**
 * Send a login link to the recipient.
 */
function sendLoginLink(string $recipient, string $loginUrl): bool
{
    $recipient = filter_var($recipient, FILTER_VALIDATE_EMAIL);
    if (! $recipient) {
        return false;
    }

    $siteName = esc_attr(get_bloginfo('name'));

    $subject = sprintf(__('Passwordless login to: %s', 'wp-passwordless-login'), $siteName);
    $message = sprintf(
        __(
            'Ahoy! <br><br>Log in to %s by visiting this url: <a href="%s" target="_blank">%s</a>',
            'wp-passwordless-login'
        ),
        $siteName,
        esc_url($loginUrl),
        esc_url($loginUrl),
    );

    return wp_mail($recipient, $subject, $message, [
        'Content-type: text/html; charset=UTF-8',
    ]);
}

/**
 * Build a URL that allows users to authenticate by opening it in their browser.
 * This URL points to /wp-login.php and includes the user id, a short lived auth
 * token and the nonce that was used to initially submit the form.
 */
function generateLoginUrl(WP_User $user, string $nonce, string $redirect): string
{
    $url = site_url('wp-login.php');
    $url = add_query_arg([
        'uid' => $user->ID,
        'token' => createToken($user),
        'nonce' => $nonce,
    ], $url);

    if ($redirect) {
        add_query_arg('redirect_to', $redirect, $url);
    }

    return $url;
}

/**
 * Issue a short lived token that allows the user to authenticate.
 */
function createToken(WP_User $user): string
{
    $action = "passwordless_{$user->ID}";
    $time = time();
    $salt = wp_generate_password(32);

    $token  = wp_hash($salt . $action . $time);
    $expiration = $time + PASSWORDLESS_TOKEN_TTL;

    $storedHash = wp_hash_password($token . $expiration);
    update_user_meta($user->ID, $action, $storedHash);
    update_user_meta($user->ID, "{$action}_expiration", $expiration);
    return $token;
}

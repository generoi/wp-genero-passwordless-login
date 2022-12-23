<?php

/*
Plugin Name:  Genero Passwordless Login
Plugin URI:   https://genero.fi
Description:  Let genero adminsitrators log in without a password
Version:      1.0.0
Author:       Genero
Author URI:   https://genero.fi/
License:      MIT License
*/

namespace Genero\PasswordlessLogin;

define('PASSWORDLESS_NONCE_NAME', '_passwordless_nonce');
define('PASSWORDLESS_NONCE_ACTION', 'passwordless_login_request');
define('PASSWORDLESS_VALID_EMAIL_DOMAIN', 'genero.fi');
define('PASSWORDLESS_ADMIN_ACCOUNT', 'gadmin');

use Exception;
use PasswordHash;
use WP_Error;
use WP_User;

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
 * Attempt the login when having landed from an email link.
 *
 * @param WP_User|WP_Error|null $user
 */
add_filter('authenticate', function ($user, string $username, string $password) {
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
    $error->add('passwordless_error', __('The passwordless login was unsucessful.'));
    return $error;
}, 18, 3);

/**
 * Take over the regular login authentication (which has priority 20) and send
 * the login by email when not submitting a password.
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

    // Only act on our domain
    $domain = explode('@', $username);
    $domain = array_pop($domain);
    if ($domain !== PASSWORDLESS_VALID_EMAIL_DOMAIN) {
        return $user;
    }

    $account = get_user_by('login', PASSWORDLESS_ADMIN_ACCOUNT);
    if (! $account) {
        return $user;
    }

    $redirect = sanitize_url($_GET['redirect_to'] ?? '');
    $loginUrl = generateLoginUrl($account, $nonce, $redirect);
    if (! sendLoginLink($username, $loginUrl)) {
        return $user;
    }

    $error = new WP_Error();
    $error->add('email_sent', __('Please check your email to finish login.'));

    return $error;
}, 19, 3);

function isValidTokenLogin(int $uid, string $token, string $nonce): bool
{
    $storedHash = get_user_meta($uid, "passwordless_{$uid}", true);
    $expiration = get_user_meta($uid, "passwordless_{$uid}_expiration", true);

    require_once ABSPATH . 'wp-includes/class-phpass.php';
    $hasher = new PasswordHash(8, true);
    $time = time();

    $isValidToken = $hasher->CheckPassword($token . $expiration, $storedHash);
    $isValidNonce = wp_verify_nonce($nonce, PASSWORDLESS_NONCE_ACTION);
    $isExpired = $expiration < $time;

    if ($isValidToken && $isValidNonce && ! $isExpired) {
        return true;
    }
    return false;
}

function sendLoginLink(string $recipient, string $loginUrl): bool
{
    $recipient = filter_var($recipient, FILTER_VALIDATE_EMAIL);
    if (! $recipient) {
        return false;
    }

    $siteName = esc_attr(get_bloginfo('name'));

    $subject = sprintf(__('Passwordless login on: %s'), $siteName);
    $message = sprintf(
        __('Ahoy! <br><br>Log in to %s by visiting this url: <a href="%s" target="_blank">%s</a>'),
        $siteName,
        esc_url($loginUrl),
        esc_url($loginUrl),
    );

    return wp_mail($recipient, $subject, $message, [
        'Content-type: text/html; charset=UTF-8',
    ]);
}

function generateLoginUrl(WP_User $user, string $nonce, string $redirect): string
{
    $url = site_url('wp-login.php');
    $url = add_query_arg([
        'uid' => $user->ID,
        'token' =>  createToken($user),
        'nonce' => $nonce,
    ], $url);

    if ($redirect) {
        add_query_arg('redirect_to', $redirect, $url);
    }

    return $url;
}

function createToken(WP_User $user): string
{
    $action = "passwordless_{$user->ID}";
    $time = time();
    // random salt
    $key = wp_generate_password(20, false);

    require_once ABSPATH . 'wp-includes/class-phpass.php';
    $hasher = new PasswordHash(8, true);
    $string = $key . $action . $time;

    $token  = wp_hash($string);
    $expiration = $time + MINUTE_IN_SECONDS * 10;

    $storedHash = $hasher->HashPassword($token . $expiration);
    update_user_meta($user->ID, $action, $storedHash);
    update_user_meta($user->ID, "{$action}_expiration", $expiration);
    return $token;
}

<?php
/*
Plugin Name: Authentication: ISGweb for iMIS
Plugin URI: http://owlwatch.com
Description: This plugin authenticates users against a iMIS database with ISGweb
Version: 1.0.0
Author: Mark Fabrizio <fabrizim@owlwatch.com>
Author URI: http://owlwatch.com
License: GPLv2 or later
*/

function init_isgweb_auth(){
  
  if( class_exists('ISGwebAuth_Plugin') ){
    return;
  }
  /********************************************************
  *  Reqires Snap
  *********************************************************/
  if( !class_exists('Snap') ){
    add_action('admin_notices', function(){
      ?>
      <div class="error">
        <p>"Authentication: ISGweb for iMIS" requires the
        <a href="https://github.com/fabrizim/Snap">Snap plugin</a>.
        </p>
      </div>
      <?
    });
    return;
  }
  
  define( 'ISGWEB_AUTH_DIR', dirname(__FILE__) );
  define( 'ISGWEB_AUTH_URL', plugins_url('/', __FILE__) );
  
  Snap_Loader::register('ISGwebAuth', ISGWEB_AUTH_DIR.'/lib');
  Snap::inst('ISGwebAuth_Plugin');
  
}

add_action('plugins_loaded', 'init_isgweb_auth');


if ( !function_exists('wp_validate_auth_cookie') ){
  /**
   * Validates authentication cookie.
   *
   * The checks include making sure that the authentication cookie is set and
   * pulling in the contents (if $cookie is not used).
   *
   * Makes sure the cookie is not expired. Verifies the hash in cookie is what is
   * should be and compares the two.
   *
   * @since 2.5.0
   *
   * @param string $cookie Optional. If used, will validate contents instead of cookie's
   * @param string $scheme Optional. The cookie scheme to use: auth, secure_auth, or logged_in
   * @return bool|int False if invalid cookie, User ID if valid.
   */
  function wp_validate_auth_cookie($cookie = '', $scheme = '') {
    init_isgweb_auth();
    if( class_exists('ISGwebAuth_Plugin') ){
      // lets see if we have a Token...
      $type = get_site_option( 'isgweb_type' );
      if( $type == 'isgweb' || $type == 'both' ){
        $user_id = Snap::inst('ISGwebAuth_Plugin')->get_user_id_from_token();
        if( $user_id ) return $user_id;
      }
      else if( $type == 'imis' ){
        $user_id = Snap::inst('ISGwebAuth_Plugin')->determine_current_user( null );
        if( $user_id ) return $user_id;
      }
    }
    if ( ! $cookie_elements = wp_parse_auth_cookie($cookie, $scheme) ) {
      /**
       * Fires if an authentication cookie is malformed.
       *
       * @since 2.7.0
       *
       * @param string $cookie Malformed auth cookie.
       * @param string $scheme Authentication scheme. Values include 'auth', 'secure_auth',
       *                       or 'logged_in'.
       */
      do_action( 'auth_cookie_malformed', $cookie, $scheme );
      return false;
    }
  
    $scheme = $cookie_elements['scheme'];
    $username = $cookie_elements['username'];
    $hmac = $cookie_elements['hmac'];
    $token = $cookie_elements['token'];
    $expired = $expiration = $cookie_elements['expiration'];
  
    // Allow a grace period for POST and AJAX requests
    if ( defined('DOING_AJAX') || 'POST' == $_SERVER['REQUEST_METHOD'] ) {
      $expired += HOUR_IN_SECONDS;
    }
  
    // Quick check to see if an honest cookie has expired
    if ( $expired < time() ) {
      /**
       * Fires once an authentication cookie has expired.
       *
       * @since 2.7.0
       *
       * @param array $cookie_elements An array of data for the authentication cookie.
       */
      do_action( 'auth_cookie_expired', $cookie_elements );
      return false;
    }
  
    $user = get_user_by('login', $username);
    if ( ! $user ) {
      /**
       * Fires if a bad username is entered in the user authentication process.
       *
       * @since 2.7.0
       *
       * @param array $cookie_elements An array of data for the authentication cookie.
       */
      do_action( 'auth_cookie_bad_username', $cookie_elements );
      return false;
    }
  
    $pass_frag = substr($user->user_pass, 8, 4);
  
    $key = wp_hash( $username . '|' . $pass_frag . '|' . $expiration . '|' . $token, $scheme );
    $hash = hash_hmac( 'sha256', $username . '|' . $expiration . '|' . $token, $key );
  
    if ( ! hash_equals( $hash, $hmac ) ) {
      /**
       * Fires if a bad authentication cookie hash is encountered.
       *
       * @since 2.7.0
       *
       * @param array $cookie_elements An array of data for the authentication cookie.
       */
      do_action( 'auth_cookie_bad_hash', $cookie_elements );
      return false;
    }
  
    $manager = WP_Session_Tokens::get_instance( $user->ID );
    if ( ! $manager->verify( $token ) ) {
      do_action( 'auth_cookie_bad_session_token', $cookie_elements );
      return false;
    }
  
    // AJAX/POST grace period set above
    if ( $expiration < time() ) {
      $GLOBALS['login_grace_period'] = 1;
    }
  
    /**
     * Fires once an authentication cookie has been validated.
     *
     * @since 2.7.0
     *
     * @param array   $cookie_elements An array of data for the authentication cookie.
     * @param WP_User $user            User object.
     */
    do_action( 'auth_cookie_valid', $cookie_elements, $user );
    if( get_user_meta($user->ID,'EMAIL',true) ){
      // this failed the Token test, so keep them logged out here
      return false;
    }
    return $user->ID;
  }
}
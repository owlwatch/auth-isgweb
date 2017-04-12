<?php

class ISGwebAuth_Plugin extends Snap_Wordpress_Plugin
{
  protected $ns = 'auth_isgweb';
  protected $_wrapper;
  protected $_remoteRequestTime;
  protected $_remoteTimeout = false;
  protected $_timedoutUser = false;
  
  public function get_isg_wrapper()
  {
    if( isset($this->_isg_wrapper) ) return $this->_isg_wrapper;
    $this->_isg_wrapper = new ISGwebAuth_ISGWrapper(
      get_site_option('isgweb_url'),
      array(
        'Authentication'    => get_site_option('isgweb_password')
      ),
      get_site_option('isgweb_uiroot')
    );
    return $this->_isg_wrapper;
  }
  
  public function get_imis_wrapper()
  {
    if( isset($this->_imis_wrapper) ) return $this->_imis_wrapper;
    $this->_imis_wrapper = new ISGwebAuth_IMISWrapper(
      get_site_option('imis_url')
    );
    return $this->_imis_wrapper;
  }
  
  /**
   * @wp.filter             wp_redirect
   */
  public function debug_redirect( $location, $status )
  {
    global $wp_current_filter;
    error_log( 'is_admin? '.is_admin()?'yes':'no' );
    error_log( 'script_filename? '.$_SERVER['PHP_SELF'] );
    
    return $location;
  }
  
  /**
   * @wp.action             network_admin_menu
   */
  public function add_settings_menu_page()
  {
    add_submenu_page(
      'settings.php',
      'ISGweb for iMIS',
      'ISGweb for iMIS',
      'manage_network_options',
      'isgweb-auth-settings',
      array(&$this, 'network_settings_page')
    );
  }
  
  public function network_settings_page()
  {
    $form = new Snap_Wordpress_Form2_Form();
    
    $form->add_field('isgweb_type', 'radios', array(
      'label' => 'Integration',
      'options' => [
        'isgweb' => 'ISGweb Only',
        'imis'   => 'iMIS Only',
        'both'   => 'ISGweb and iMIS'
      ]
    ));
    
    $form->add_field('isgweb_url', 'text', array('label' => 'ISGweb Service URL'));
    $form->add_field('isgweb_uiroot', 'text', array('label' => 'ISGWeb UI Root Domain'));
    $form->add_field('isgweb_password', 'text', array('label' => 'ISGWeb Security Password'));
    
    $form->add_field('imis_url', 'text', array('label'=>'iMIS Service URL'));
    $form->add_field('imis_login_cookie', 'text', array('label'=>'iMIS Login Cookie'));
    $form->add_field('imis_user', 'text', array('label'=>'iMIS Admin User'));
    $form->add_field('imis_password', 'password', array('label'=>'iMIS Admin Password'));
    $form->add_field('imis_query', 'text', array('label'=>'iMIS Query Path'));
    
    $form->add_field('isgweb_cookie_domain', 'text', array('label' => 'Cookie Domain'));
    $form->add_field('isgweb_allowed_domains', 'textarea', array('label'=>'Allowed Authentication Domains (one per line)'));
    $form->set_data( $_POST );
    
    if( $_SERVER['REQUEST_METHOD'] == 'POST' && wp_verify_nonce( @$_POST['_wpnonce'], 'isgweb-auth' ) ){
      // lets do some option saving...
      foreach( $form->get_fields() as $field ){
        update_site_option($field->get_name(), $field->get_value());
      }
    }
    
    foreach( $form->get_fields() as $field ){
      $field->set_value( get_site_option($field->get_name()) );
    }
    
    Snap::inst('Snap_Wordpress_Form2_Decorator_Admin');
    include ISGWEB_AUTH_DIR.'/options.php';
  }
  
  
  /**
   * @wp.filter             authenticate
   * @wp.priority           30
   */
  public function authenticate($user, $username, $password)
  {
    if( $user instanceof WP_User && !get_user_meta($user->ID,'EMAIL',true) ){
      return $user;
    }
    
    if( $this->_remoteTimeout ){
      // we are having trouble connecting to the authentication
      // server...
      $e = new ISGwebAuth_Exception_Timeout();
      return new WP_Error('isgwebauth_timeout', apply_filters('isgwebauth_message', $e->getMessage(), $e));
      //return false;
    }
    
    try {
      $type = get_site_option( 'isgweb_type' );

      $result = [];
      // lets check against the ISGweb db
      if( in_array( $type, ['isgweb', 'both'] ) ) {
        $result = array_merge( $result, $this->get_isg_wrapper()->authenticateUser( $username, $password ) );
      }
      if( in_array( $type, ['imis', 'both'] ) ) {
        $imisResult = $this->get_imis_wrapper()->authenticateUser( $username, $password );
        $result = array_merge( $result, $imisResult );
      }
    }
    catch( ISGwebAuth_Exception_Timeout $e ){
      error_log( 'Login Error, ISGwebAuth_Exception_Timeout: '.$e->getMessage() );
      $this->_remoteTimeout = true;
      return new WP_Error('isgwebauth_timeout', apply_filters('isgwebauth_message', $e->getMessage(), $e));
    }
    catch( ISGwebAuth_Exception_InvalidCredentials $e ){
      error_log( 'Login Error, ISGwebAuth_Exception_InvalidCredentials: '.$e->getMessage() );
      $this->_remoteTimeout = true;
      return new WP_Error('isgwebauth_invalid', apply_filters('isgwebauth_message', $e->getMessage(), $e));
    }
    catch( Exception $e ){
      error_log( 'Login Error, Exception: '.$e->getMessage() );
      return new WP_Error('isgwebauth_generic', apply_filters('isgwebauth_message', $e->getMessage(), $e));
    }
    
    if( $result && is_array($result) && isset($result['USER_COOKIE']) ){
      $user =  $this->get_user( $result );
      return $user;
    }
    return false;
  }
  
  /**
   * @wp.action             init
   */
  public function disable_dm_login()
  {
    if( is_user_logged_in() && get_user_meta( get_current_user_id(), 'EMAIL', true) ){
      remove_action( 'template_redirect', 'remote_login_js', 10 );
    }
    if( isset( $_GET['__lt'] ) ){
      $url = remove_query_arg('__lt');
      if( !self::decrypt( $_GET['__lt'] ) ){
        $url = add_query_arg( '__no_isgweb_user', 1, $url );
      }
      else {
        $url = add_query_arg( time(), '', $url );
      }
      wp_redirect( $url );
      exit;
    }
  }
  
  /**
   * @wp.filter             determine_current_user
   * @wp.priority           11
   */
  public function determine_current_user( $user_id )
  {
    if( $user_id ){
      //if( is_admin() ) return $user_id;
      // lets check to see if this user has an 'EMAIL'
      if( !($email = get_user_meta($user_id,'EMAIL',true)) ){
        return $user_id;
      }
    }
    
    $type = get_site_option( 'isgweb_type' );
    
    if( $type === 'isgweb' || $type === 'both' ){
      $user_id =  $this->get_user_id_from_token();
      // update cookies?
      if( $user_id && ($token = get_user_meta( $user_id, 'TOKEN', true )) ){
        $result = [
          'TOKEN'       => $token
        ];
        $this->update_cookies( $result );
      }
    }
    if( ($type === 'imis' || $type === 'both') ){
      $result = $this->get_imis_wrapper()->getCurrentUser();
      if( $result && isset( $result['EMAIL'] ) ){
        $user = $this->get_user( $result );
        if( $user && !is_wp_error( $user ) ){
          $user_id = $user->ID;
          //echo $user_id;
        }
      }
    }
    return $user_id;
  }
  
  /**
   * @wp.filter             ["show_password_fields"]
   */
  public function disable_password_fields( $value, $user )
  {
    if( get_user_meta( $user->ID, 'EMAIL', true) ){
      return false;
    }
    return $value;
  }
  
  public function get_user_id_from_token()
  {
    static $result;
    if( isset( $result ) ){
      return $result;
    }
    
    $result = false;
    
    $token = @$_COOKIE['Token'];
    if( isset( $_GET['__lt'] ) ){
      $token = self::decrypt( $_GET['__lt'] );
      if( $_GET['test'] ){
        header('content-type: text/plain');
        echo $_GET['__lt']."\n";
        die( $token );
      }
    }
    if( !$token ) {
      return false;
    }
    
    if( !isset($_GET['__lt']) ){
      $user_id = get_site_transient('tok_'.$token);
      if( $user_id ){
        error_log( $_SERVER['REMOTE_ADDR']. ' - Authenticating from tok (cache) transient');
        $result = $user_id;
        return $user_id;
      }
      
      // also, lets check for a timeout situation...
      if( ($user_id = get_site_transient( 'to_'.$token )) ){
        error_log( $_SERVER['REMOTE_ADDR']. ' - Authenticating from to (timeout) transient');
        $this->_timedoutUser = true;
        $result = $user_id;
        return $user_id;
      }
    }
    
    $start = microtime();
    try {
      $result = $this->get_isg_wrapper()->authenticateToken( $token );
    }
    catch(ISGwebAuth_Exception_InvalidToken $e ){
      error_log( $_SERVER['REMOTE_ADDR'].' - ISGwebAuth_Exception_InvalidToken' );
      // lets delete that token
      setcookie('Token', null, -1, '/', get_site_option('isgweb_cookie_domain') );
      return false;
    }
    catch(ISGwebAuth_Exception_Timeout $e){
      $this->_remoteTimeout = true;
      error_log( $_SERVER['REMOTE_ADDR'].' - ISGwebAuth_Exception_Timeout' );
      // before we bail, lets just see if we can find this user based
      // on token
      $users = get_users([
        'meta_key'          => 'TOKEN',
        'meta_value'        => $token,
        'number'            => 1
      ]);
      
      if( is_wp_error( $users ) || !count( $users ) ){
        return false;
      }
      error_log( $_SERVER['REMOTE_ADDR'].' - ISGwebAuth_Exception_Timeout - authenticating from user meta TOKEN' );
      $user = $users[0];
      // lets keep them logged in for 1 minutes
      set_site_transient('to_'.$token, $user->ID, 60*1 );
      $result = $user->ID;
      $this->_timedoutUser = true;
      return $user->ID;
      
    }
    catch(Exception $e){
      return false;
    }
    
    
    $this->_remoteRequestTime = microtime() - $start;
    
    if( $result && is_array($result) && isset($result['TOKEN'] ) ){
      if( 'both' === get_site_option( 'isgweb_type' ) ){
        unset( $result['USER_COOKIE'] );
      }
      $user = $this->get_user( $result );
      if( $user instanceof WP_User ){
        $result = $user->ID;
        $cache_time = 2;
        set_site_transient('tok_'.$token, $user->ID, 60*$cache_time );
        return $user->ID;
      }
    }
    return false;
  }
  
  /**
   * @wp.action
   * @wp.priority 1000
   */
  public function wp_footer()
  {
    echo sprintf( "\n<!-- ISGweb Authentication took %1.2f seconds -->\n", $this->_remoteRequestTime );
    if( $this->_timedoutUser ){
      echo sprintf( "<!-- ISGweb Authentication using Timeout User -->\n" );
    }
  }
  
  protected function get_user( $result )
  {
    // find by
    $email = @$result['EMAIL'];
    if( !$email ) return false;
    $user = get_user_by( 'email', $email );
    if( $user === false ){
      // create this dude.
      $email = isset( $result['EMAIL'] ) ? $result['EMAIL'] : null;
      $userdata = array(
        'user_email'  => $email,
        'user_login'  => $email,
        'first_name'  => isset($result['FIRSTNAME'])?$result['FIRSTNAME']:'',
        'last_name'   => isset($result['LASTNAME'])?$result['LASTNAME']:'',
      );
      
      $user_id = wp_insert_user( $userdata );
      $user = new WP_User( $user_id );
    }
    
    if( !$user instanceof WP_User ) return false;
    
    // update user meta with updated name
    $user_id = $user->ID;
    add_filter( 'init', function() use($user_id, $result){
      wp_update_user([
        'ID'            => $user_id,
        'first_name'    => $result['FIRSTNAME'],
        'last_name'     => $result['LASTNAME'],
        'display_name'  => $result['FULL_NAME']
      ]);
    });
    
    if( !is_user_member_of_blog( $user->ID, get_current_blog_id() ) ){
      add_user_to_blog( get_current_blog_id(), $user->ID, 'subscriber');
    }
    
    // update the meta data from the result
    foreach( $result as $key => $value ){
      update_user_meta( $user->ID, $key, $value );
    }
    
    $this->update_cookies( $result );
    
    return $user;
  }
  
  protected function update_cookies( $result )
  {
    
    if( !isset( $result['USER_COOKIE'] ) ) return;
    $cookie_domain = get_site_option('isgweb_cookie_domain');
    $cookies = explode('|', $result['USER_COOKIE']);
    
    preg_match( '/([^\.]+\.[^\.]+)$/', $cookie_domain, $cookie_domain_base );
    $current_domain = parse_url( home_url(), PHP_URL_HOST );
    preg_match( '/([^\.]+\.[^\.]+)$/', $current_domain, $home_domain_base );
    if( $cookie_domain_base[1] != $home_domain_base[1] ){
      // we should set the cookies for the home domain...
      $cookie_domain = $home_domain_base[1];
    }
    
    
    if( isset( $result['TOKEN'] ) ){
      if( 'isgweb' === get_site_option( 'isgweb_type' ) ){
        $cookies = ['Token='.$result['TOKEN']];
      }
      else {
        $cookies[] = 'Token='.$result['TOKEN'];
      }
    }
    
    foreach( $cookies as $cookie ){
      list($name, $value) = explode('=', $cookie, 2);
      
      // ignore this cookie
      if( $name == 'ASP.NET_SessionId' ){
        continue;
      }
      
      if( $value ){
        setcookie($name, $value, time() + (60 * 60 * 24 * 14), '/', $cookie_domain );
      }
    }
  }
  
  /**
   * @wp.action
   */
  public function settings_init()
  {
    add_settings_field(
      $this->ns.'_types',
      __('Post Types allowed on Front Page', $this->ns),
      array(&$this, 'settings_field'),
      'reading'
    );
    
    register_setting('reading', $this->ns.'_types');
  }
  
  /**
   * @wp.action       wp_logout
   * @wp.priority     5
   */
  public function on_logout()
  {
    //  we need to remove our transients...
    if( ($token = @$_COOKIE['Token']) ){
      delete_transient( 'to_'.$token );
      delete_transient( '_tok_'.$token );
    }
    
    $cookie_domain = get_site_option('isgweb_cookie_domain');
    foreach( array('Token','ASP.NET_SessionId','LOGINSESSIONID','Login','iMIS_Login') as $cookie ){
      setcookie( $cookie, '', time() - (60 * 60 * 24 * 100), '/', $cookie_domain );
      setcookie( $cookie, '', time() - (60 * 60 * 24 * 100), '/', COOKIE_DOMAIN );
    }
  }
  
  /**
   * @wp.action
   * @wp.priority   100
   */
  public function wp_login($login, $user)
  {
    // allow for external redirects
    if( isset($_REQUEST['redirect_to']) &&
        strpos($_REQUEST['redirect_to'],'http') === 0 &&
        $this->is_redirect_allowed( $_REQUEST['redirect_to'])
    ){
      $redirect = $_REQUEST['redirect_to'];
      if( parse_url( network_home_url(), PHP_URL_HOST ) !==
          parse_url( $redirect, PHP_URL_HOST ) ){
        // lets add a login token...
        $token = get_user_meta( $user->ID, 'TOKEN', true);
        $redirect = add_query_arg( '__lt', self::encrypt($token), $redirect );
      }
      if( $user->ID == 4 ){
        //die( $redirect );
      }
      wp_redirect( $redirect );
      exit;
    }
  }
  
  /**
   * @wp.action
   */
  public function template_redirect()
  {
    
    if( class_exists('Theme_My_Login') &&
        is_page() && is_user_logged_in() &&
        Theme_My_Login::is_tml_page('login', get_the_ID()) &&
        isset($_REQUEST['redirect_to']) &&
        $this->is_redirect_allowed( $_REQUEST['redirect_to'])
    ){
      wp_redirect($_REQUEST['redirect_to']);
      exit;
    }
    
    // else, remove the _login_token from the url...
    if( isset( $_GET['__lt'] ) ){
      //wp_redirect( add_query_arg( '__lt', false ) );
      //exit;
    }
  }
  
  public function is_redirect_allowed($redirect)
  {
    // allow all domains for now.
    if( 1 ) return true;
    $domains = array_filter( explode("\n", get_site_option('isgweb_allowed_domains')));
    $domains[] = parse_url(home_url(), PHP_URL_HOST);
    if( $domains ) foreach( $domains as $domain ){
      $allowed[] = $domain;
    }
    $host = parse_url($redirect, PHP_URL_HOST);
    foreach( $allowed as $domain ){
      $domain = str_replace('.', '\\.', $domain);
      if( preg_match('#'.$domain.'$#', $host) ){
        return true;
      }
    }
    return false;
  }
  
  public static function encrypt( $text )
  {
    
    return trim(
      base64_encode(
        openssl_encrypt( $text, 'AES-256-CBC', AUTH_SALT )
      )
    );
    
  }
  public static function decrypt( $text )
  {
    return trim(
      openssl_decrypt( base64_decode( $text ), 'AES-256-CBC', AUTH_SALT )
    );
  }
  
}

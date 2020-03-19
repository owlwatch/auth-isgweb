<?php

class ISGwebAuth_Plugin extends Snap_Wordpress_Plugin
{
    protected $ns = 'auth_isgweb';
    protected $_wrapper;
    protected $_remoteRequestTime;
    protected $_remoteTimeout = false;
    protected $_timedoutUser = false;
    protected $_is_logging_out = false;


    public function get_isg_wrapper()
    {
        if (isset($this->_isg_wrapper)) {
            return $this->_isg_wrapper;
        }
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
        if (isset($this->_imis_wrapper)) {
            return $this->_imis_wrapper;
        }
        $this->_imis_wrapper = new ISGwebAuth_IMISWrapper(
            get_site_option('imis_url')
        );
        return $this->_imis_wrapper;
    }

    /**
     * @wp.action init
     * @wp.priority 1
     */
    public function disable_saml_for_localhost()
    {
        //error_log( 'disable_saml? '.$_SERVER['REMOTE_ADDR'] );
        if ($_SERVER['REMOTE_ADDR'] !== '69.167.155.34') {
            return;
        }
        add_filter( 'pre_option_saml_login_url', function () {
            return false;
        });
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

    /**
     * @wp.action             init
     */
    public function add_site_settings_menu_page()
    {
        if (function_exists('acf_add_options_sub_page')) {
            acf_add_options_sub_page(array(
                'menu_title'  => 'RiSE Settings',
                'menu_slug'   => 'rise-settings',
                'page_title'  => 'RiSE Settings',
                'parent_slug' => 'options-general.php',
                'post_id'     => 'rise-settings'
            ));
        }
    }


    public function network_settings_page()
    {
        $form = new Snap_Wordpress_Form2_Form();

        $form->add_field('isgweb_type', 'radios', array(
            'label' => 'Integration',
            'options' => [
                'isgweb' => 'ISGweb Only',
                'imis'   => 'iMIS Only',
                'both'   => 'ISGweb and iMIS',
                'sync'   => 'Sync only via iMIS'
            ]
        ));

        $form->add_field('isgweb_sync_enabled', 'radios', array(
            'label' => 'Enable Sync',
            'options'=> [
                'no'=>'No','yes'=>'Yes'
            ]
        ));
        $form->add_field('isgweb_sync_interval', 'text', array('label' => 'Sync Interval', 'default'=> '60'));

        $form->add_field('isgweb_url', 'text', array('label' => 'ISGweb Service URL'));
        $form->add_field('isgweb_uiroot', 'text', array('label' => 'ISGWeb UI Root Domain'));
        $form->add_field('isgweb_password', 'text', array('label' => 'ISGWeb Security Password'));

        $form->add_field('imis_url', 'text', array('label'=>'iMIS Service URL'));
        $form->add_field('imis_login_cookie', 'text', array('label'=>'iMIS Login Cookie'));
        $form->add_field('imis_user', 'text', array('label'=>'iMIS Admin User'));
        $form->add_field('imis_password', 'password', array('label'=>'iMIS Admin Password'));
        $form->add_field('imis_query', 'text', array('label'=>'iMIS Query Path'));
        $form->add_field('imis_timeout', 'text', array('label'=>'iMIS Timeout'));

        $form->add_field('isgweb_cookie_domain', 'text', array('label' => 'Cookie Domain'));
        $form->add_field('isgweb_allowed_domains', 'textarea', array('label'=>'Allowed Authentication Domains (one per line)'));
        $form->set_data($_POST);

        if ($_SERVER['REQUEST_METHOD'] == 'POST' && wp_verify_nonce(@$_POST['_wpnonce'], 'isgweb-auth')) {
            // lets do some option saving...
            foreach ($form->get_fields() as $field) {
                update_site_option($field->get_name(), $field->get_value());
            }
        }

        foreach ($form->get_fields() as $field) {
            $field->set_value(get_site_option($field->get_name()));
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
        $type = get_site_option('isgweb_type');

        if ('sync' === $type) {
            return $user;
        }

        if ($user instanceof WP_User && !get_user_meta($user->ID, 'EMAIL', true)) {
            return $user;
        }

        if ($this->_remoteTimeout) {
            // we are having trouble connecting to the authentication
        // server...
            $e = new ISGwebAuth_Exception_Timeout();
            return new WP_Error('isgwebauth_timeout', apply_filters('isgwebauth_message', $e->getMessage(), $e));
        //return false;
        }

        try {
            $result = [];
        // lets check against the ISGweb db
            if (in_array($type, ['isgweb', 'both'])) {
                $result = array_merge($result, $this->get_isg_wrapper()->authenticateUser($username, $password));
            }
            if (in_array($type, ['imis', 'both'])) {
                $imisResult = $this->get_imis_wrapper()->authenticateUser($username, $password);
                $result = array_merge($result, $imisResult);
            }
        } catch (ISGwebAuth_Exception_Timeout $e) {
            error_log('Login Error, ISGwebAuth_Exception_Timeout: '.$e->getMessage());
            $this->_remoteTimeout = true;
            return new WP_Error('isgwebauth_timeout', apply_filters('isgwebauth_message', $e->getMessage(), $e));
        } catch (ISGwebAuth_Exception_InvalidCredentials $e) {
            error_log('Login Error, ISGwebAuth_Exception_InvalidCredentials: '.$e->getMessage());
            $this->_remoteTimeout = true;
            return new WP_Error('isgwebauth_invalid', apply_filters('isgwebauth_message', $e->getMessage(), $e));
        } catch (Exception $e) {
            error_log('Login Error, Exception: '.$e->getMessage());
            return new WP_Error('isgwebauth_generic', apply_filters('isgwebauth_message', $e->getMessage(), $e));
        }

        if ($result && is_array($result) && isset($result['USER_COOKIE'])) {
            $user =  $this->get_user($result);
            return $user;
        }
          return false;
    }

  /**
   * @wp.action             init
   */
    public function disable_dm_login()
    {
        if ('sync' === get_site_option('isgweb_type')) {
            return;
        }
        if (is_user_logged_in() && get_user_meta(get_current_user_id(), 'EMAIL', true)) {
            remove_action('template_redirect', 'remote_login_js', 10);
        }
        if (isset($_GET['__lt'])) {
            $url = remove_query_arg('__lt');
            if (!self::decrypt($_GET['__lt'])) {
                $url = add_query_arg('__no_isgweb_user', 1, $url);
            } else {
                $url = add_query_arg(time(), '', $url);
            }
            wp_redirect($url);
            exit;
        }
    }

  /**
   * @wp.filter             determine_current_user
   * @wp.priority           11
   */
    public function determine_current_user($user_id)
    {
        if ('sync' === get_site_option('isgweb_type')) {
            if ($user_id && get_user_meta($user_id, 'EMAIL', true)) {
                $this->sync($user_id);
            }
            return $user_id;
        }
        if ($user_id) {
            //if( is_admin() ) return $user_id;
        // lets check to see if this user has an 'EMAIL'
            if (!($email = get_user_meta($user_id, 'EMAIL', true))) {
                return $user_id;
            }
        }

        $type = get_site_option('isgweb_type');

        if ($type === 'isgweb' || $type === 'both') {
            $user_id =  $this->get_user_id_from_token();
        // update cookies?
            if ($user_id && ($token = get_user_meta($user_id, 'TOKEN', true))) {
                $result = [
                'TOKEN'       => $token
                  ];
                $this->update_cookies($result);
            }
        }
        if (($type === 'imis' || $type === 'both')) {
            $result = $this->get_imis_wrapper()->getCurrentUser();
            if ($result && isset($result['EMAIL'])) {
                $user = $this->get_user($result);
                if ($user && !is_wp_error($user)) {
                    $user_id = $user->ID;
            //echo $user_id;
                }
            }
        }
        return $user_id;
    }

    public function sync($user_id, $force=false)
    {
        static $synced = [];

        if (get_site_option('isgweb_sync_enabled') == 'no') {
            return;
        }

        if (isset($synced[$user_id])) {
            return;
        }

        $syncInterval = get_site_option('isgweb_sync_interval');
        if (!$syncInterval) {
            $syncInterval = 0;
        }

        $lastSync = get_user_meta($user_id, '_last_sync', true);
        if (!$force && $lastSync && microtime(true) - $lastSync < (float) $syncInterval) {

            return;
        }
        $wrapper = $this->get_imis_wrapper();
        try {
            $result = $wrapper->getUserById(get_user_meta($user_id, 'ID', true));
            if ($result) {
                foreach ($result as $key => $value) {
                    update_user_meta($user_id, $key, $value);
                }
            }
            else {

            }
            $lastSync = microtime(true);
            update_user_meta($user_id, '_last_sync', $lastSync);
            $synced[$user_id] = true;
        } catch (Exception $e) {
            // could not Sync
            error_log( $e->getMessage() );
        }
    }

  /**
   * @wp.filter             ["show_password_fields"]
   */
    public function disable_password_fields($value, $user)
    {
        if (get_user_meta($user->ID, 'EMAIL', true)) {
            //return false;
        }
        return $value;
    }

    public function get_user_id_from_token()
    {
        static $result;
        if (isset($result)) {
            return $result;
        }

        $result = false;

        $token = @$_COOKIE['Token'];
        if (isset($_GET['__lt'])) {
            $token = self::decrypt($_GET['__lt']);
            if ($_GET['test']) {
                header('content-type: text/plain');
                echo $_GET['__lt']."\n";
                die($token);
            }
        }
        if (!$token) {
            return false;
        }

        if (!isset($_GET['__lt'])) {
            $user_id = get_site_transient('tok_'.$token);
            if ($user_id) {
                $result = $user_id;
                return $user_id;
            }

            // also, lets check for a timeout situation...
            if (($user_id = get_site_transient('to_'.$token))) {
                $this->_timedoutUser = true;
                $result = $user_id;
                return $user_id;
            }
        }

        $start = microtime();
        try {
            $result = $this->get_isg_wrapper()->authenticateToken($token);
        } catch (ISGwebAuth_Exception_InvalidToken $e) {
            error_log($_SERVER['REMOTE_ADDR'].' - ISGwebAuth_Exception_InvalidToken');
            // lets delete that token
            setcookie('Token', null, -1, '/', get_site_option('isgweb_cookie_domain'));
            return false;
        } catch (ISGwebAuth_Exception_Timeout $e) {
            $this->_remoteTimeout = true;
            error_log($_SERVER['REMOTE_ADDR'].' - ISGwebAuth_Exception_Timeout');
            // before we bail, lets just see if we can find this user based
            // on token
            $users = get_users([
            'meta_key'          => 'TOKEN',
            'meta_value'        => $token,
            'number'            => 1
            ]);

            if (is_wp_error($users) || !count($users)) {
                return false;
            }
            error_log($_SERVER['REMOTE_ADDR'].' - ISGwebAuth_Exception_Timeout - authenticating from user meta TOKEN');
            $user = $users[0];
            // lets keep them logged in for 1 minutes
            set_site_transient('to_'.$token, $user->ID, 60*1);
            $result = $user->ID;
            $this->_timedoutUser = true;
            return $user->ID;
        } catch (Exception $e) {
            return false;
        }


        $this->_remoteRequestTime = microtime() - $start;

        if ($result && is_array($result) && isset($result['TOKEN'])) {
            if ('both' === get_site_option('isgweb_type')) {
                unset($result['USER_COOKIE']);
            }
            $user = $this->get_user($result);
            if ($user instanceof WP_User) {
                $result = $user->ID;
                $cache_time = 2;
                set_site_transient('tok_'.$token, $user->ID, 60*$cache_time);
                return $user->ID;
            }
        }
        return false;
    }

    /**
    * @-wp.action
    * @wp.priority 1000
    */
    public function wp_footer()
    {
        echo sprintf("\n<!-- ISGweb Authentication took %1.2f seconds -->\n", $this->_remoteRequestTime);
        if ($this->_timedoutUser) {
            echo sprintf("<!-- ISGweb Authentication using Timeout User -->\n");
        }
    }

    protected function get_user($result)
    {
        // find by
        $email = @$result['EMAIL'];
        if (!$email) {
            return false;
        }
        $user = get_user_by('email', $email);
        if ($user === false) {
            // create this dude.
            $email = isset($result['EMAIL']) ? $result['EMAIL'] : null;
            $userdata = array(
                'user_email'  => $email,
                'user_login'  => $email,
                'first_name'  => isset($result['FIRSTNAME'])?$result['FIRSTNAME']:'',
                'last_name'   => isset($result['LASTNAME'])?$result['LASTNAME']:'',
            );

            $user_id = wp_insert_user($userdata);
            $user = new WP_User($user_id);
        }

        if (!$user instanceof WP_User) {
            return false;
        }

        // update user meta with updated name
        $user_id = $user->ID;
        add_filter('init', function () use ($user_id, $result) {
            wp_update_user([
                'ID'            => $user_id,
                'first_name'    => $result['FIRSTNAME'],
                'last_name'     => $result['LASTNAME'],
                'display_name'  => $result['FULL_NAME']
            ]);
        });

        if (!is_user_member_of_blog($user->ID, get_current_blog_id())) {
            add_user_to_blog(get_current_blog_id(), $user->ID, 'subscriber');
        }

        // update the meta data from the result
        foreach ($result as $key => $value) {
            update_user_meta($user->ID, $key, $value);
        }

        $this->update_cookies($result);

        return $user;
    }

    protected function update_cookies($result)
    {
        if (!isset($result['USER_COOKIE'])) {
            return;
        }
        $cookie_domain = get_site_option('isgweb_cookie_domain');
        $cookies = explode('|', $result['USER_COOKIE']);

        preg_match('/([^\.]+\.[^\.]+)$/', $cookie_domain, $cookie_domain_base);
        $current_domain = parse_url(home_url(), PHP_URL_HOST);
        preg_match('/([^\.]+\.[^\.]+)$/', $current_domain, $home_domain_base);
        if ($cookie_domain_base[1] != $home_domain_base[1]) {
            // we should set the cookies for the home domain...
            $cookie_domain = $home_domain_base[1];
        }


        if (isset($result['TOKEN'])) {
            if ('isgweb' === get_site_option('isgweb_type')) {
                $cookies = ['Token='.$result['TOKEN']];
            } else {
                $cookies[] = 'Token='.$result['TOKEN'];
            }
        }

        foreach ($cookies as $cookie) {
            list($name, $value) = explode('=', $cookie, 2);

            // ignore this cookie
            if ($name == 'ASP.NET_SessionId') {
                continue;
            }

            if ($value) {
                setcookie($name, $value, time() + (60 * 60 * 24 * 14), '/', $cookie_domain);
            }
        }
    }

    /**
    * @wp.action       wp_logout
    * @wp.priority     5
    */
    public function on_logout()
    {
        if ('sync' === get_site_option('isgweb_type')) {
            return;
        }

        //  we need to remove our transients...
        if (($token = @$_COOKIE['Token'])) {
            delete_transient('to_'.$token);
            delete_transient('_tok_'.$token);
        }

        $cookie_domain = get_site_option('isgweb_cookie_domain');
        foreach (array('Token','ASP.NET_SessionId','LOGINSESSIONID','Login','iMIS_Login') as $cookie) {
            setcookie($cookie, '', time() - (60 * 60 * 24 * 100), '/', $cookie_domain);
            setcookie($cookie, '', time() - (60 * 60 * 24 * 100), '/', COOKIE_DOMAIN);
        }
    }

    /**
    * @wp.action
    * @wp.priority   100
    */
    public function wp_login($login, $user=null)
    {

        // allow for external redirects
        if (isset($_REQUEST['redirect_to']) &&
            strpos($_REQUEST['redirect_to'], 'http') === 0 &&
            $this->is_redirect_allowed($_REQUEST['redirect_to'])
        ) {
            $redirect = $_REQUEST['redirect_to'];
            if (parse_url(network_home_url(), PHP_URL_HOST) !==
              parse_url($redirect, PHP_URL_HOST)) {
                // lets add a login token...
                $token = get_user_meta($user->ID, 'TOKEN', true);
                $redirect = add_query_arg('__lt', self::encrypt($token), $redirect);
            }
            if ($user->ID == 4) {
                //die( $redirect );
            }
            wp_redirect($redirect);
            exit;
        }
    }

    /**
    * @wp.action
    */
    public function template_redirect()
    {
        if (class_exists('Theme_My_Login') &&
            is_page() && is_user_logged_in() &&
            Theme_My_Login::is_tml_page('login', get_the_ID()) &&
            isset($_REQUEST['redirect_to']) &&
            $this->is_redirect_allowed($_REQUEST['redirect_to'])
            ) {
            wp_redirect($_REQUEST['redirect_to']);
            exit;
        }

        // else, remove the _login_token from the url...
        if (isset($_GET['__lt'])) {
            //wp_redirect( add_query_arg( '__lt', false ) );
          //exit;
        }
    }

    public function is_redirect_allowed($redirect)
    {
        // allow all domains for now.
        if (1) {
            return true;
        }
        $domains = array_filter(explode("\n", get_site_option('isgweb_allowed_domains')));
        $domains[] = parse_url(home_url(), PHP_URL_HOST);
        if ($domains) {
            foreach ($domains as $domain) {
                $allowed[] = $domain;
            }
        }
        $host = parse_url($redirect, PHP_URL_HOST);
        foreach ($allowed as $domain) {
            $domain = str_replace('.', '\\.', $domain);
            if (preg_match('#'.$domain.'$#', $host)) {
                return true;
            }
        }
        return false;
    }

    public static function encrypt($text)
    {
        return trim(
            base64_encode(
                openssl_encrypt($text, 'AES-256-CBC', AUTH_SALT)
            )
        );
    }
    public static function decrypt($text)
    {
        return trim(
            openssl_decrypt(base64_decode($text), 'AES-256-CBC', AUTH_SALT)
        );
    }

    // /**
    //  * @wp.filter option_saml_logout_url
    //  */
    // public function capture_saml_logout($value)
    // {
    //     $this->_is_logging_out = true;
    //     return $value;
    // }

    // /**
    //  * @wp.filter pre_option_mo_saml_sp_base_url
    //  */
    // public function saml_slo_relay($value)
    // {
    //     if ($this->_is_logging_out && isset($_REQUEST['redirect_to'])) {
    //         return $_REQUEST['redirect_to'];
    //     } elseif ($this->is_logging_out) {
    //         return home_url();
    //     }
    //     return $value;
    // }

    /**
     * @wp.action init
     */
    public function default_relay_state()
    {
        if ($GLOBALS['pagenow'] !== 'wp-login.php') {
            return;
        }

        error_log( print_r( $_REQUEST, 1 ) );

        if (isset($_REQUEST['action']) && $_REQUEST['action'] === 'logout') {
            $_REQUEST['redirect_to'] = home_url();
            return;
        }

        if (isset($_REQUEST['redirect_to'])) {
            return;
        }

        // otherwise, lets find the default login for this site
        if (function_exists('get_field') && $url = get_field('saml_login_default', 'rise-settings')) {
            if (strpos( $url, '/' ) === 0) {
                $url = home_url( $url );
            }
            $_REQUEST['redirect_to'] = $url;
        } else {
            $_REQUEST['redirect_to'] = home_url();
        }
    }

    /**
     * @wp.action wp_authenticate
     * @wp.priority 1
     */
    public function logout_on_reauth()
    {
        $type = get_site_option('isgweb_type');

        if ('sync' === $type) {
            return;
        }
        if (isset($_REQUEST['reauth']) && $_REQUEST['reauth'] == '1') {
            global $current_user;
            $current_user = null;
            add_filter('determine_current_user', function ($id) {
                return 0;
            }, 999, 1);
        }
    }

    /**
    * @-wp.action wp_footer
    */
    public function add_iframe()
    {
        if ('sync' !== get_site_option('isgweb_type')) {
            return;
        }
        $user_id = is_user_logged_in() ?
        get_user_meta(get_current_user_id(), 'ID', true) :
        false;

        if ('' === $user_id) {
            // this is a WP user...
            return;
        }

        $parts = parse_url(home_url());
        $current_uri = "{$parts['scheme']}://{$parts['host']}" . add_query_arg(null, null);
        $auth_url = add_query_arg('reauth', '1', wp_login_url($current_uri));
        $logout_url = wp_logout_url($current_uri); ?>

        <a href="<?php echo wp_logout_url($current_uri); ?>"
           id="asa-session-state-logout-url"
           style="display: none;"
        ></a>
        <script type="text/javascript">
        (function(){
            var user_id = <?php echo json_encode($user_id); ?>;
            var auth_url = <?php echo json_encode($auth_url); ?>;

            function receiveMessage( e ){
                var iframe = document.getElementById( 'asa-session-state' );
                if( e.source !==  ( iframe.contentWindow || iframe ) ){
                    return;
                }

                var uid = e.data;

                if( !( uid === 'false' || uid.match(/^\d+$/) ) ){
                    return;
                }

                if( uid === 'false' ) uid = false;

                if( uid === user_id ){
                    return;
                }

                if( !uid ){
                    window.location = document.getElementById('asa-session-state-logout-url').href;
                }
                else {
                    if( user_id && uid ){
                        jQuery.post('<?= admin_url( 'admin-ajax.php' ) ?>', {
                            action: 'auth_isgweb_logout'
                        }).success(function(){
                            window.location = auth_url;
                        });
                    }
                    else {
                        window.location = auth_url;
                    }
                }
            }
            window.addEventListener('message', receiveMessage, false);
        })();
        </script>
        <iframe
            id="asa-session-state"
            src="https://my.americanstaffing.net/securesso/securesessioncheck.aspx"
            style="position: absolute; top: -10000em; left: -10000em; height: 1px; width: 1px;"
        ></iframe>
        <?php
    }

    /**
     * Ajax action to logout behind the scenes
     *
     * @wp.ajax
     */
    public function auth_isgweb_logout()
    {
        wp_destroy_current_session();
        wp_clear_auth_cookie();
        echo json_encode(['success' => true]);
        exit;
    }
}

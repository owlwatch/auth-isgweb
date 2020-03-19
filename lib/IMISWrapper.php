<?php
/**
 * Class to handle ISGweb SOAP requests and responses.
 *
 * This code was originally from the Druapl iMIS ISGweb module
 *
 * @see https://drupal.org/project/imis_isgweb
 */
class iSGwebAuth_IMISWrapper
{
    private $wsdlRoot;
    private $wsdlKeys;
    private $uiRoot;
    public $errors;

    public function __construct(
        $wsdlRoot,
        $wsdlKeys = array(
          'Membership' => 'membership/membershipwebservice',
          'Query' => 'query/queryservice'
        )
    ) {
        $this->wsdlRoot = trim($wsdlRoot, '/') . '/';
        $this->wsdlKeys = $wsdlKeys;
        $this->errors = array();
    }

    /**
     * Authentication web service methods
     */
    public function authenticateUser($username, $password)
    {
        $response = $this->call('Membership', 'LoginUserAndProvideCookies', array(
          'username' => $username,
          'password' => $password,
          'staffUser' => false
        ));

        // this should be a string...
        if (!$response || !is_string($response)) {
            throw new ISGwebAuth_Exception_InvalidCredentials("The username or password you provided are invalid.");
<<<<<<< HEAD
        }

        $user = [];

        $user['USER_COOKIE'] = $response;

        // lets also create a cookie jar
        $cookies = array_map(function ($str) {
            list($key, $value) = explode('=', $str, 2);
            return compact('key', 'value');
        }, explode('|', $response));

        $username = $this->call('Membership', 'GetUserName', '', $cookies);

        if (!$username || !is_string($username)) {
            throw new ISGwebAuth_Exception_InvalidCredentials("The username or password you provided are invalid.");
        }

=======
        }

        $user = [];

        $user['USER_COOKIE'] = $response;

        // lets also create a cookie jar
        $cookies = array_map(function ($str) {
            list($key, $value) = explode('=', $str, 2);
            return compact('key', 'value');
        }, explode('|', $response));

        $username = $this->call('Membership', 'GetUserName', '', $cookies);

        if (!$username || !is_string($username)) {
            throw new ISGwebAuth_Exception_InvalidCredentials("The username or password you provided are invalid.");
        }

>>>>>>> 6adf5a73ed7e035c912f77e9f688d8249fbe3c56
        $response = $this->call('Query', 'GetResultsWithParameters', [
            'queryPath' => '$/_ASA_IQA/SSO/UserDataStub',
            'parameters' => $username,
        ], $this->getStaffUserCookies());

        return array_merge($response, $user);
    }

    public function getStaffUserCookies()
    {
        if (!($cookies = get_transient('imis_login'))) {
            // now we need to login with our staff user
            $user = get_site_option('imis_user');
            $pass = get_site_option('imis_password');

            try {
                $response = $this->call('Membership', 'LoginUserAndProvideCookies', array(
                    'username' => $user,
                    'password' => $pass,
                    'staffUser' => 'true'
                ));
            }
            catch( Exception $e ){
                error_log( print_r( ['LoginAndProvideCookies error' => $e], 1 ) );
                throw $e;
            }

            error_log( print_r( ['LoginAndProvideCookies response' => $response], 1 ) );

            if (!$response || !is_string($response)) {
                throw new Exception('Invalid iMIS admin user');
            }

            // lets also create a cookie jar
            $cookies = array_map(function ($str) {
                list($key, $value) = explode('=', $str, 2);
                return compact('key', 'value');
            }, explode('|', $response));


            set_transient('imis_login', $cookies, 60 * 60 * 24);
        }

        return $cookies;
    }

    public function getCurrentUser()
    {
        $cookieName = get_site_option('imis_login_cookie');

        if (!isset($_COOKIE[$cookieName])) {
            return false;
        }

        $username = $this->call('Membership', 'GetUserName', '', [
            ['key'=>$cookieName, 'value'=>$_COOKIE[$cookieName]],
            ['key'=>'ASP_NET_SessionId', 'value'=>@$_COOKIE['ASP_NET_SessionId']]
        ]);


        if (!$username || !is_string($username)) {
            return false;
        }

        $queryPath = get_site_option('imis_query');
        if (!$queryPath) {
            $queryPath = '$/_ASA_IQA/SSO/UserDataStub';
        }

        $response = $this->call('Query', 'GetResultsWithParameters', [
            'queryPath' => $queryPath,
            'parameters' => $username,
        ], $this->getStaffUserCookies());

        return $response;
    }

    public function getUserById($user_id)
    {
        $queryPath = get_site_option('imis_query');
        if (!$queryPath) {
            $queryPath = '$/_ASA_IQA/SSO/UserProfile1';
        }

        try {
            $response = $this->call('Query', 'GetResultsWithParameters', [
                'queryPath' => $queryPath,
                'parameters' => $user_id,
              ], $this->getStaffUserCookies());
            return $response;
        } catch (Exception $e) {
            error_log( $e );
            return false;
        }
    }

    public function api()
    {
        return call_user_func_array( [$this, 'call'], func_get_args() );
    }

    /**
     * Internal utility methods
     */
    private function call($service, $method, $params, $cookies = null)
    {
        $timeout = get_site_option('imis_timeout');
        $socketTimeout = ini_set('default_socket_timeout', $timeout ?: 10 );

        $request  = array('parameters' => $params);
        $response = null;

        $start = microtime(true);
<<<<<<< HEAD

        // Get SOAP response

        $url = $this->wsdlRoot . $this->wsdlKeys[$service] . '.asmx?wsdl';


        $client = new SoapClient($url, array(
            'cache_wsdl'    => WSDL_CACHE_DISK,
            //'timeout'       => 2000,
            'compression'   => SOAP_COMPRESSION_ACCEPT | SOAP_COMPRESSION_GZIP,
            'trace'         => true,
            'exceptions'    => true,
            'cookies'       => '',
            'keep_alive'    => true,
        ));

        try {
            if ($cookies && count($cookies)) {
                foreach ($cookies as $cookie) {
                    $client->__setCookie($cookie['key'], $cookie['value']);
                }
            }
            $response = $client->__soapCall($method, $request);
            $response = (string) $client->__getLastResponse();

            //print_r( $response );


        // A note on why we're not using $client->__soapCall() response:
        //   The PHP SOAP client was choking on the ~85K records that were
        //   being returned in the SOAP response. It was able to pull back
        //   the raw data, but failed consistently when there were more
        //   than a few thousand records involved. As such, we're directly
        //   processing the raw XML below.
        } catch (SoapFault $e1) {
            ini_set('default_socket_timeout', $socketTimeout);
            $this->errors[] = $e1->getMessage();
            error_log( print_r( ['SoapFault'=> $e1 ], 1 ));
            error_log($_SERVER['REMOTE_ADDR'].' - ISGwebAuth_ExceptionTimeout '.$method.' time: '. number_format((microtime(true)-$start), 2).'s');
            throw new ISGwebAuth_Exception_Timeout();
        } catch (Exception $e2) {
            ini_set('default_socket_timeout', $socketTimeout);
            $this->errors[] = $e2->getMessage();
            error_log($_SERVER['REMOTE_ADDR'].' - ISGwebAuth_ExceptionTimeout '.$method.' time: '. number_format((microtime(true)-$start), 2).'s');
            throw new ISGwebAuth_Exception_Timeout();
        }
        ini_set('default_socket_timeout', $socketTimeout);
        error_log($_SERVER['REMOTE_ADDR'].' - ISGweb '.$method.' time: '. number_format((microtime(true)-$start), 2).'s');

        try {
            $upload_dir = wp_upload_dir();
            $db_file = $upload_dir['basedir'].'/imis-timing.db';
            $db = new SQLite3( $db_file );

            $db->exec('CREATE TABLE IF NOT EXISTS logs (
                date text,
                ip text,
                method text,
                timing real
            )');

            $stmt = $db->prepare("
                INSERT INTO logs (date, ip, method, timing)
                    VALUES (:date, :ip, :method, :timing)"
            );
            $stmt->bindValue(':date', date('Y-m-d H:i:s'));
            $stmt->bindValue(':ip', $_SERVER['REMOTE_ADDR']);
            $stmt->bindValue(':method', $method);
            $stmt->bindValue(':timing', (microtime(true)-$start));

            $stmt->execute();
        } catch (Exception $e) {
            error_log( print_r( $e->getTrace(), 1 ) );
        }
=======

        // Get SOAP response

        $url = $this->wsdlRoot . $this->wsdlKeys[$service] . '.asmx?wsdl';


        $client = new SoapClient($url, array(
            'cache_wsdl'    => WSDL_CACHE_DISK,
            //'timeout'       => 2000,
            'compression'   => SOAP_COMPRESSION_ACCEPT | SOAP_COMPRESSION_GZIP,
            'trace'         => true,
            'exceptions'    => true,
            'cookies'       => '',
            'keep_alive'    => true,
        ));

        try {
            if ($cookies && count($cookies)) {
                foreach ($cookies as $cookie) {
                    $client->__setCookie($cookie['key'], $cookie['value']);
                }
            }
            $response = $client->__soapCall($method, $request);
            $response = (string) $client->__getLastResponse();

            //print_r( $response );


        // A note on why we're not using $client->__soapCall() response:
        //   The PHP SOAP client was choking on the ~85K records that were
        //   being returned in the SOAP response. It was able to pull back
        //   the raw data, but failed consistently when there were more
        //   than a few thousand records involved. As such, we're directly
        //   processing the raw XML below.
        } catch (SoapFault $e1) {
            ini_set('default_socket_timeout', $socketTimeout);
            $this->errors[] = $e1->getMessage();
            error_log( print_r( ['SoapFault'=> $e1 ], 1 ));
            error_log($_SERVER['REMOTE_ADDR'].' - ISGwebAuth_ExceptionTimeout '.$method.' time: '. number_format((microtime(true)-$start), 2).'s');
            throw new ISGwebAuth_Exception_Timeout();
        } catch (Exception $e2) {
            ini_set('default_socket_timeout', $socketTimeout);
            $this->errors[] = $e2->getMessage();
            error_log($_SERVER['REMOTE_ADDR'].' - ISGwebAuth_ExceptionTimeout '.$method.' time: '. number_format((microtime(true)-$start), 2).'s');
            throw new ISGwebAuth_Exception_Timeout();
        }
        ini_set('default_socket_timeout', $socketTimeout);
        error_log($_SERVER['REMOTE_ADDR'].' - ISGweb '.$method.' time: '. number_format((microtime(true)-$start), 2).'s');
>>>>>>> 6adf5a73ed7e035c912f77e9f688d8249fbe3c56

        // Process response
        $data = null;



        // Some ISGweb methods return strings instead of XML
        if (strpos($response, '<') == 0 && strpos( $response, '<'.$method.'Result>' ) > -1) {
            $values    =
              $map       = array();
            $parser    = xml_parser_create();

            libxml_use_internal_errors(true);
            xml_parse_into_struct($parser, $response, $values, $map);
            xml_parser_free($parser);

            $resultKey = strtoupper($method . 'Result');
            if (isset($map[$resultKey]) && is_array($map[$resultKey])) {
                $map_ix  = $map[strtoupper($method . 'Result')][0];
                $xml     = trim($values[$map_ix]['value']);

                if (strpos($xml, '<') === 0) {

                    $obj     = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_ERR_FATAL | LIBXML_PARSEHUGE);
                    $error   = libxml_get_errors();

                    // Check for XML parsing errors
                    if( !empty( $error ) && $error[0]->code == 5 ){
                        $xml = '<QueryResultSet>'.$xml.'</QueryResultSet>';
                        libxml_clear_errors();
                        $obj = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_ERR_FATAL | LIBXML_PARSEHUGE);
                        $error   = libxml_get_errors();
                    }

                    if (!empty($error)) {
                        foreach ($error as $e) {
                            $this->errors[] = $e;
                        }
                        libxml_clear_errors();
                        return false;
                    }

                    $data = $this->objectToArray($obj);
                } else {
                    $data = $xml;
                }
            }
        } else {
            $data = $response;
            echo $data;
        }
        return $data;
    }

    private function objectToArray($arrObjData, $arrSkipIndices = array())
    {
        $arrData = array();

        // if input is object, convert into array
        if (is_object($arrObjData)) {
            $arrObjData = get_object_vars($arrObjData);
        }

        if (is_array($arrObjData)) {
            foreach ($arrObjData as $index => $value) {
                if (is_object($value) || is_array($value)) {
                    $value = $this->objectToArray($value, $arrSkipIndices);
                }
                if (in_array($index, $arrSkipIndices)) {
                    continue;
                }
                $arrData[$index] = $value;
            }
        }
        return $arrData;
    }
}

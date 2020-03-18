<?php

/**
 *
 * phpIPAM API client to work with phpIPAM APIv2
 *
 *
 */
class phpipam_api_client  {

    /**
     * Debug flag for curl
     *
     * (default value: false)
     *
     * @var bool
     * @access public
     */
    public $debug = false;

    /**
     * API server URL
     *
     * (default value: false)
     *
     * @var bool
     * @access private
     */
    private $api_url = false;

    /**
     * API APP identifier
     *
     * (default value: false)
     *
     * @var bool
     * @access private
     */
    private $api_app_id = false;

    /**
     * API key
     *
     * (default value: false)
     *
     * @var bool
     * @access private
     */
    private $api_key = false;

    /**
     * Flag if we need to encrypt API communication
     *
     * (default value: false)
     *
     * @var bool
     * @access private
     */
    private $api_encrypt = false;

    /**
     * phpipam account username / passwork for authentication
     *
     * (default value: false)
     *
     * @var bool
     * @access private
     */
    private $api_username = false;
    private $api_password = false;

    /**
     * Holder for CUrL connection
     *
     * (default value: false)
     *
     * @var bool
     * @access private
     */
    private $Connection = false;

    /**
     * Access token for phpipam
     *
     * (default value: false)
     *
     * @var bool
     * @access private
     */
    private $token = false;

    /**
     * When token expires
     *
     * (default value: false)
     *
     * @var bool
     * @access private
     */
    private $token_expires = false;

    /**
     * api_server_method
     *
     * (default value: false)
     *
     * @var bool|mixed
     * @access private
     */
    private $api_server_method = false;

    /**
     * api_server_controller (sections, subnets, ...)
     *
     * (default value: false)
     *
     * @var bool|mixed
     * @access private
     */
    private $api_server_controller = false;

    /**
     * Identifiers to add to URL
     *
     * (default value: false)
     *
     * @var bool
     * @access private
     */
    private $api_server_identifiers = false;

    /**
     * List of valid API methods
     *
     * @var mixed
     * @access private
     */
    private $api_server_valid_methods = array(
        "OPTIONS", "GET", "POST", "PATCH", "DELETE"
    );

    /**
     * HTTP error codes for responses
     *
     * @var mixed
     * @access public
     */
    public $error_codes = array(
        // OK
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        // Client errors
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        415 => "Unsupported Media Type",
        // Server errors
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        511 => "Network Authentication Required"
    );

    /**
     * Set result format
     *
     * (default value: array("json", "array", "object", "xml"))
     *
     * @var string
     * @access private
     */
    private $result_format_available = array("json", "array", "object", "xml");

    /**
     * Result format
     *
     *  json/array/object/xml
     *
     * (default value: "json")
     *
     * @var string
     * @access private
     */
    private $result_format = "json";

    /**
     * To store result
     *
     * @var mixed
     * @access private
     */
    public $result = array(
        "success" => true,
        "code"    => 204,
        "message" => ""
    );

    /**
     * Reponse headers
     *
     * @var array
     */
    public $response_headers = array ();




    /**
     * __construct function.
     *
     * @access public
     * @param bool|mixed $api_url (default: false)
     * @param bool|mixed $app_id (default: false)
     * @param bool|mixed $api_key (default: false)
     * @param bool|mixed $username (default: false)
     * @param bool|mixed $password (default: false)
     * @param mixed $result_format (default: "json")
     */
    public function __construct($api_url = false, $app_id = false, $api_key = false, $username = false, $password = false, $result_format = "json") {
        // set app server URL if provided
        if ($api_url!==false) {
            $this->set_api_url ($api_url);
        }
        // set app_id if provided
        if ($app_id!==false) {
            $this->set_api_app_id ($app_id);
        }
        // set api key if provided
        if ($api_key!==false) {
            $this->set_api_key ($api_key);
        }
        // set user/pass if provided
        if ($username!==false && $password!==false) {
            $this->set_api_authparams ($username, $password);
        }
        // set result format if provided
        if (strlen($result_format)>0) {
            $this->set_result_format ($result_format);
        }
        // check for required php extensions
        $this->validate_php_extensions ();
    }

    /**
     * Saves error and exits script
     *
     * @access public
     * @param mixed $content
     * @return void
     */
    public function exception ($content) {
        //set result parameters
        $this->result = array(
            'code'    => 400,
            'success' => false,
            'message' => $content
        );
        // print result
        $this->print_result ();
        // die
        die();
    }

    /**
     * Returns last result
     *
     * @access public
     * @return void
     */
    public function get_result () {
        # output result
        if ($this->result_format=="json") {
            return json_encode($this->result);
        }
        elseif ($this->result_format=="array") {
            return $this->result;
        }
        elseif ($this->result_format=="object") {
            return (object) $this->result;
        }
        elseif ($this->result_format=="xml") {
            // new SimpleXMLElement object
            $xml = new SimpleXMLElement('<'.$_GET['controller'].'/>');
            // generate xml from result
            $this->array_to_xml($xml, $this->result);
            // return XML result
            return $xml->asXML();
        }
    }

    /**
     * Prints last result
     *
     * @access public
     * @return void
     */
    public function print_result () {
        # output result
        if ($this->result_format=="json") {
            print json_encode($this->result);
        }
        elseif ($this->result_format=="array") {
            var_dump($this->result);
        }
        elseif ($this->result_format=="object") {
            var_dump( (object) $this->result);
        }
        elseif ($this->result_format=="xml") {
            // new SimpleXMLElement object
            $xml = new SimpleXMLElement('<apiclient/>');
            // generate xml from result
            $this->array_to_xml($xml, $this->result);
            // return XML result
            print $xml->asXML();
        }
    }

    /**
     * Transforms array to XML
     *
     * @access private
     * @param SimpleXMLElement $object
     * @param array $data
     * @return void
     */
    private function array_to_xml(SimpleXMLElement $object, array $data) {
        // loop through values
        foreach ($data as $key => $value) {
            // if spaces exist in key replace them with underscores
            if(strpos($key, " ")>0)	{ $key = str_replace(" ", "_", $key); }

            // if key is numeric append item
            if(is_numeric($key)) $key = "item".$key;

            // if array add child
            if (is_array($value)) {
                $new_object = $object->addChild($key);
                $this->array_to_xml($new_object, $value);
            }
            // else write value
            else {
                $object->addChild($key, $value);
            }
        }
    }

    /**
     * Check if all extensions are present
     *
     * @access private
     * @return void
     */
    private function validate_php_extensions () {
        // Required extensions
        $required_ext  = array("openssl", "curl");
        // mcrypt for crypted extensions
        if($this->api_key !== false)
            $required_ext[] = "mcrypt";
        // json
        if($this->result_format == "json")
            $required_ext[] = "json";
        // xml
        if($this->result_format == "xml")
            $required_ext[] = "xmlreader";

        // Available extensions
        $available_ext = get_loaded_extensions();

        // check
        foreach ($required_ext as $e) {
            if(!in_array($e, $available_ext)) {
                $this->exception("Missing php extension ($e)");
            }
        }
    }

    /**
     * Debugging flag
     *
     * @access public
     * @param bool $debug (default: false)
     * @return void
     */
    public function set_debug ($debug = false) {
        if(is_bool($debug)) {
            $this->debug = $debug;
        }
    }

    /**
     * Checks requested result format and saves it
     *
     * @access public
     * @param string $result_format (default: "json")
     * @return void
     */
    public function set_result_format ($result_format = "json") {
        if (strlen($result_format)>0) {
            if (!in_array($result_format, $this->result_format_available)) {
                $this->exception ("Invalid result format");
            }
            else {
                // recheck extensions
                $this->validate_php_extensions ();
                // set
                $this->result_format = $result_format;
            }
        }
    }

    /**
     * Set API url parameter
     *
     * @access public
     * @param mixed $api_url
     * @return void
     */
    public function set_api_url ($api_url) {
        // we need http/https
        if(strpos($api_url, "http://")!==false || strpos($api_url, "https://")!==false) {
            // trim
            $api_url = trim($api_url);
            // add last / if missing
            if (substr($api_url, -1)!=="/") { $api_url .= "/"; }
            // save
            $this->api_url = $api_url;
        }
        else {
            $this->exception("Invalid APP id");
        }
    }

    /**
     * Sets api app_id variable
     *
     * @access public
     * @param bool $id (default: false)
     * @return void
     */
    public function set_api_app_id ($app_id = false) {
        if ($app_id!==false) {
            // name must be more than 2 and alphanumberic
            if(strlen($app_id)<3 || strlen($app_id)>12 || !ctype_alnum($app_id)) {
                $this->exception("Invalid APP id");
            }
            else {
                $this->api_app_id = $app_id;
            }
        }
        else {
            $this->exception("Invalid APP id");
        }
    }

    /**
     * Set api key
     *
     * @access public
     * @param bool $api_key (default: false)
     * @return void
     */
    public function set_api_key ($api_key = false) {
        if ($api_key!==false) {
            $this->api_key = $api_key;

            // set encrypt flag
            $this->api_encrypt = true;
        }
        else {
            $this->exception("Invalid APP id");
        }
    }

    /**
     * Sets username/password for URL auth
     *
     * @access public
     * @param bool $username (default: false)
     * @param bool $password (default: false)
     * @return void
     */
    public function set_api_authparams ($username = false, $password = false) {
        if($username===false || $password===false) {
            $this->exception("Invalid username or password");
        }
        else {
            $this->api_username = $username;
            $this->api_password = $password;
        }
    }

    /**
     * Sreets api method.
     *
     * @access public
     * @param string $method (default: "GET")
     * @return void
     */
    public function set_api_method ($method = "GET") {
        // validate
        $this->set_api_method_validate ($method);
        // set
        $this->api_server_method = strtoupper($method);
    }

    /**
     * Validates API method against available
     *
     * @access private
     * @param mixed $method
     * @return void
     */
    private function set_api_method_validate ($method) {
        if(!in_array(strtoupper($method), $this->api_server_valid_methods)) {
            $this->exception("Invalid method $method");
        }
    }

    /**
     * Sets API controller - required
     *
     * @access public
     * @param bool $controller (default: false)
     * @return void
     */
    public function set_api_controller ($controller = false) {
        if($controller!==false) {
            $this->api_server_controller = strtolower($controller);
        }
    }

    /**
     * Sets additional identifiers to be passed to URL directly
     *
     *  e.g.:  /api/appid/controller/<identifier1>/<identifier2>/
     *
     * @access public
     * @param mixed $identifiers
     * @return void
     */
    public function set_api_identifiers ($identifiers) {
        $this->api_server_identifiers = false;         // clear this to forget any previous settings
        if(is_array($identifiers)) {
            if(sizeof($identifiers)>0 && !$this->api_encrypt) {
                // reset
                $this->api_server_identifiers = implode("/", $identifiers);
            }
            elseif (sizeof($identifiers)>0 && $this->api_encrypt) {
                $this->api_server_identifiers = array();
                foreach ($identifiers as $cnt=>$i) {
                    if($cnt==0) { $this->api_server_identifiers['id']   = $i; }
                    else        { $this->api_server_identifiers['id'.($cnt+1)] = $i; }
                }

            }
        }
    }











    /* @api-server communication --------------- */

    /**
     * Executes request to API server
     *
     * @access public
     * @param bool $method (default: false)
     * @param bool $controller (default: false)
     * @param array $identifiers (default: array())
     * @param array $params (default: array())
     * @param bool $token_file (default: false)
     * @return void
     */
    public function execute ($method = false, $controller = false, $identifiers = array(), $params = array(), $token_file = false) {
        // check and set method
        $this->set_api_method ($method);
        // set api controller
        $this->set_api_controller ($controller);
        // set api identifiers
        $this->set_api_identifiers ($identifiers);

        // set connection
        $this->curl_set_connection ($token_file);
        // save params
        $this->curl_set_params ($params);
        // set HTTP method
        $this->curl_set_http_method ();

        // if not encrypted set params
        if(!$this->api_encrypt) {
            // add token to header, authenticate if it fails
            $this->curl_add_token_header ($token_file);
        }
        // if token is set execute
        if ($this->token !== false) {
            // execute
            $res = $this->curl_execute ();
            // save result
            $this->result = (array) $res;

            // check for invalid token and retry
            if ($this->result['code']=="401" && $token_file!==false) {
                // remove old token
                $this->delete_token_file ($token_file);
                // auth again
                $this->curl_add_token_header ($token_file);
                // execute
                $res = $this->curl_execute ();
                // save result
                $this->result = (array) $res;
            }
        }
        // exncrypted request
        elseif ($this->api_encrypt) {
            // execute
            $res = $this->curl_execute ();
            // save result
            $this->result = (array) $res;
        }
        // save reult
        $this->curl_save_headers ();
    }

    /**
     * Opens cURL resource and sets initial parameters
     *
     * @access private
     * @param mixed $token_file
     * @return void
     */
    private function curl_set_connection ($token_file) {
        // check if it exists
        if ($this->Connection===false) {
            // Get cURL resource
            $this->Connection = curl_init();

            // set URL
            if($this->api_server_controller===false)    { $url = $this->api_url.$this->api_app_id."/"; }
            else                                        { $url = $this->api_url.$this->api_app_id.str_replace("//", "/", "/".$this->api_server_controller."/".$this->api_server_identifiers."/"); }

            // set default curl options and params
            curl_setopt_array($this->Connection, array(
                CURLOPT_RETURNTRANSFER => 1,
                CURLOPT_URL => $url,
                CURLOPT_HEADER => 0,
                CURLOPT_VERBOSE => $this->debug,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_HTTPHEADER => array("Content-Type: application/json"),
                CURLOPT_USERAGENT => 'phpipam-api php class',
                // ssl
                CURLOPT_SSL_VERIFYHOST => false,
                CURLOPT_SSL_VERIFYPEER => false,
                // save headers
                CURLINFO_HEADER_OUT => true
            )
        );
        }
    }

    /**
     * Adds params to request if required
     *
     * @access private
     * @param mixed $params
     * @return void
     */
    private function curl_set_params ($params) {
        // params set ?
        if (is_array($params) && !$this->api_encrypt ) {
            if (sizeof($params)>0) {
                if ($this->api_server_method === 'GET')
                    curl_setopt($this->Connection, CURLOPT_URL, $this->api_url.$this->api_app_id.str_replace("//", "/", "/".$this->api_server_controller."/".$this->api_server_identifiers."/?".http_build_query($params)));
                else
                    curl_setopt($this->Connection, CURLOPT_POSTFIELDS, json_encode($params));
            }
        }
        // encrypt
        elseif ($this->api_encrypt) {
            // empty
            if(!is_array($params)) $params = array();
            if(!is_array($this->api_server_identifiers)) $this->api_server_identifiers = array();

            // join identifiers and parameters
            $params = array_merge($this->api_server_identifiers, $params);
            $params['controller'] = $this->api_server_controller;

            // create encrypted request
            $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
            $iv = openssl_random_pseudo_bytes($ivlen);
            $encrypted_request = base64_encode(openssl_encrypt(json_encode($params),$cipher,$this->api_key,$options=OPENSSL_RAW_DATA, $iv));

            // escape +
            $encrypted_request = urlencode($encrypted_request);

            // reset url
            curl_setopt($this->Connection, CURLOPT_URL, $this->api_url."?app_id=".$this->api_app_id."&enc_request=".$encrypted_request);
        }
    }

    /**
     * Sets HTTP method to use for queries
     *
     * @access private
     * @return void
     */
    private function curl_set_http_method () {
        curl_setopt($this->Connection, CURLOPT_CUSTOMREQUEST, $this->api_server_method);
    }

    /**
     * Adds token to http header
     *
     * @access private
     * @param mixed $token_file
     * @return void
     */
    private function curl_add_token_header ($token_file) {
        if($token_file!==false) {
            // open file and save token
            $token = @file($token_file);
            // save token
            if(isset($token[0])) {
                $this->token = trim($token[0]);
                $this->token_expires = trim($token[1]);

                // is token still valid ?
                if (strlen($this->token)<2 && $this->token_expires < time()) {
                    // initiate authentication
                    $this->curl_authenticate ();
                    //save token to file
                    $this->write_token_file ($token_file);
                }
            }
            else {
                $this->curl_authenticate ();
                //save token to file
                $this->write_token_file ($token_file);

            }
        }
        // token not saved, try to retrieve it
        else {
            $this->curl_authenticate ();
        }

        // add token to headers
        $this->curl_add_http_header ("token", $this->token);
    }

    /**
     * Adds http headers
     *
     * @access private
     * @param mixed $name
     * @param mixed $value
     * @return void
     */
    private function curl_add_http_header ($name, $value) {
        $headers = array(
            "Content-Type: application/json",
            "$name: $value"
        );
        // save
        curl_setopt($this->Connection, CURLOPT_HTTPHEADER, $headers);
    }

    /**
     * Writes token to token file
     *
     * @access private
     * @param mixed $filename
     * @return void
     */
    private function write_token_file ($filename) {
        //save token
        try {
            $myfile = fopen($filename, "w");
            fwrite($myfile, $this->token);
            fwrite($myfile, "\n");
            fwrite($myfile, $this->token_expires);
            // close file
            fclose($myfile);
        }
        catch ( Exception $e ) {
            $this->exception("Cannot write file $filename");
        }
    }

    /**
     * Removes token file if expired / invalid
     *
     * @access private
     * @param mixed $token_file
     * @return void
     */
    private function delete_token_file ($token_file) {
        //save token
        try {
            $myfile = fopen($token_file, "w");
            fwrite($myfile, "");
            // close file
            fclose($myfile);
        }
        catch ( Exception $e ) {
            $this->exception("Cannot write file $token_file");
        }
    }

    /**
     * Executes request.
     *
     * @access private
     * @return void
     */
    private function curl_execute () {
        // send request and save response
        $resp = curl_exec($this->Connection);

        // curl error check
        if (curl_errno($this->Connection)) {
            $this->exception("Curl error: ".curl_error($this->Connection));
        }
        else {
            // return result object
            return json_decode($resp);
        }
    }

    /**
     * Store result code
     *
     * @method curl_save_result_code
     * @return void
     */
    private function curl_save_headers () {
        // save result and result code
        $this->response_headers = curl_getinfo($this->Connection);
    }

    /**
     * send authenticate request and save token if provided, otherwise throw error.
     *
     * @access private
     * @return void
     */
    private function curl_authenticate () {
        // Get cURL resource
        $c_auth = curl_init();

        // set default curl options and params
        curl_setopt_array($c_auth, array(
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_URL => $this->api_url.$this->api_app_id."/user/",
            CURLOPT_HEADER => 0,
            CURLOPT_VERBOSE => $this->debug,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_USERAGENT => 'phpipam-api php class',
            // ssl
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_SSL_VERIFYPEER => 0,
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => array(
                'Content-Length: 0',
                'Authorization: Basic '. base64_encode($this->api_username.":".$this->api_password)
            )
        )
    );
        // send request and save response
        $resp = curl_exec($c_auth);

        // curl error check
        if (curl_errno($c_auth)) {
            $this->exception("Curl error: ".curl_error($c_auth));
        }
        else {
            // return result object
            $auth_resp = json_decode($resp);
            // ok ?
            if ($auth_resp->code == 200) {
                if (isset($auth_resp->data->token)) {
                    // save token
                    $this->token = $auth_resp->data->token;
                    $this->token_expires = strtotime($auth_resp->data->expires);
                }
                else {
                    $this->exception("Cannot obtain access token");
                }
            }
            // error
            else {
                // save response
                $this->result = $auth_resp;
            }
        }
    }

}


?>

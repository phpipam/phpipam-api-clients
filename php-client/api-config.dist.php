<?php

# set error reporting
error_reporting(E_ALL ^ E_NOTICE ^ E_STRICT);

# api params
$api_url    = "http://127.0.0.1/api/";     // server url
$api_app_id = "myapp";                     // application id
$api_key    = false;                       // api key - only for encrypted methods, otherwise must be false
$api_encrypt_base64 = false;			   // Use base64 instead of using encrypted methods (Requires PHPIPAM is running on port 443 or HTTPS)

# set username / password for authentication, not needed for encrypted communications
$api_username = "apiusername";
$api_password = "apipassword";

# save token or not ?
#   false => dont save, check each time
#   filename => will save token to filename provided
$token_file = "token.txt";

# set result format json/object/array/xml
$result_format = "json";

?>
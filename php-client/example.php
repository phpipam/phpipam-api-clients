<?php

/**
 *
 * example usage of phpipam_api_client class
 *
 *
 */

# include config file and api client class file
require("api-config.php");
require("class.phpipam-api.php");

# init object with settings from
$API = new phpipam_api_client ($api_url, $api_app_id, $api_key, $api_username, $api_password, $result_format);
# debug - only to debug curl
$API->set_debug (false);
# execute - result is stored to $API->result, save it to own array if multiple calls needed after execute
$API->execute ("GET", "sections", array(5), array(), $token_file);
# ger result
$result = $API->get_result();

# print result
print_r($result);
?>
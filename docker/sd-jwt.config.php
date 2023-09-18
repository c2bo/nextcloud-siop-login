<?php
$CONFIG = array (
  'apps_paths' => 
    array (
      0 => 
      array (
        'path' => '/var/www/html/apps',
        'url' => '/apps',
        'writable' => false,
      ),
      1 => 
      array (
        'path' => '/var/www/html/custom_apps',
        'url' => '/custom_apps',
        'writable' => true,
      ),
    ),
  'trusted_domains' => 
    array (
      0 => 'localhost:8080',
      1 => '*.ngrok.io',
      2 => 'desktop.local.fcloud.ovh',
      3 => '*.ngrok-free.app'
  ),
  'memcache.local' => '\OC\Memcache\APCu',
  'overwriteprotocol' => 'https',
  'oidc_login_auto_redirect' => false,
  'oidc_login_redir_fallback' => false,
  'oidc_login_hide_password_form' => false,
  'oidc_login_use_sd_jwt' => true,
  'oidc_login_attributes' => 
    array (
        'id' => 'email',
        'mail' => 'email'
    ),
  'oidc_login_join_attributes' =>
    array(
      'name' => array('first_name', 'last_name', 'givenName', 'familyName'),
  ),
  'oidc_login_sdjwt_config' => array(
    'trusted_issuers' => array(
      'https://issuer-openid4vc.ssi.tir.budru.de',
    ),
  ),
  'oidc_login_request_domain' => 'openid4vp://',
  'oidc_create_groups' => true,
  'oidc_login_disable_registration' => false,
  'oidc_login_tls_verify' => true,
  'oidc_login_code_challenge_method' => 'S256',
  'oidc_login_use_request_uri' => true,
  'oidc_login_client_id_scheme' => 'redirect_uri',
  'oidc_login_verifier_attestation_cert' =>  './config/acme/acme.crt',
  'oidc_login_verifier_attestation_privkey' =>  './config/acme/acme.pem',
  'debug' => true,
  'loglevel' => '0',
  'default_phone_region' => 'DE',
);
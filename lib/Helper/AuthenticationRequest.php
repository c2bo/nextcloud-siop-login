<?php

namespace OCA\OIDCLogin\Helper;

use OC\User\LoginException;
use OCA\OIDCLogin\Db\RequestObject;
use OCA\OIDCLogin\Credentials\Anoncreds\AnoncredHelper;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\KeyManagement\KeyConverter\ECKey

class AuthenticationRequest
{
    private $appName;
    private $urlGenerator;
    private $timeFactory;
    private $config;
    private $requestObjectMapper;
    private $nonce;

    private $presentationDefinition;
    private $registration = Null;

    public function __construct($appName, $urlGenerator, $timeFactory, $config, $requestObjectMapper, $nonce, $presentationID, $logger)
    {
        $this->appName = $appName;
        $this->urlGenerator = $urlGenerator;
        $this->timeFactory = $timeFactory;
        $this->config = $config;
        $this->requestObjectMapper = $requestObjectMapper;
        $this->nonce = $nonce;
        
        if ($this->config->getSystemValue('oidc_login_use_sd_jwt', false)) {
            $this->presentationDefinition = SdJwtPresentationExchangeHelper::createPresentationDefinition($presentationID);
        } else {
            $schemaConfig = $this->config->getSystemValue('oidc_login_anoncred_config', array());
            $acHelper = new AnoncredHelper($schemaConfig, $logger);
            $schemaAttr = $acHelper->getSchemaAttributes();
            $acHelper->close();
            $jsonldConfig = $this->config->getSystemValue('oidc_login_jsonld_config', array());
            $this->presentationDefinition = PresentationExchangeHelper::createPresentationDefinition(
                                                    $schemaConfig,
                                                    $schemaAttr,
                                                    $jsonldConfig,
                                                    $presentationID
                                                );

            $this->registration = array(
                'vp_formats' => array(
                    'ac_vp' => array(
                        'proof_type' => array('CLSignature2019')
                    ),
                    'ldp_vc' => array(
                        'proof_type' => array('BbsBlsSignature2020')
                    ),
                    'ldp_vp' => array(
                        'proof_type' => array('BbsBlsSignature2020')
                    ),
                ),
            );
        }
    }

    public function createOnDevice(): string
    {
        $redirectUri = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.callback');
        return $this->createAuthenticationRequest($redirectUri);
    }

    public function createCrossDevice(): string
    {
        $redirectUri = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.callback');
        return $this->createAuthenticationRequest($redirectUri, 'direct_post');
    }

    private function createAuthenticationRequest($redirectUri, $responseMode = null): string
    {
        $schema = $this->config->getSystemValue('oidc_login_request_domain', 'openid://');
        $useRequestUri = $this->config->getSystemValue('oidc_login_use_request_uri', true);
        $client_id_scheme = $this->config->getSystemValue('oidc_login_client_id_scheme', 'redirect_uri');

        $arData = array(
            'response_type' => 'vp_token',
            'redirect_uri' => $redirectUri,         
            'nonce' => $this->nonce
        );

        if (!empty($responseMode)) {
            $arData['response_mode'] = $responseMode;
        }
        
        $jws = null;
        if ($useRequestUri) {
            $arData['presentation_definition'] = $this->presentationDefinition;
            if (!is_null($this->registration)) {
                $arData['registration'] = $this->registration;
            }
            if (!empty($client_id_scheme)) {
                switch($client_id_scheme){
                    case 'redirect_uri':
                        // client_id_scheme == redirect_uri --> client id must equal redirect uri
                        // Authorization request MUST NOT be signed
                        $arData['client_id_scheme'] = 'redirect_uri';
                        $arData['client_id'] = $redirectUri;
                    case 'verifier_attestation':
                        // client_id_scheme == verifier_attestation -->
                        // - Client Identifier MUST equal the sub claim value
                        // - request MUST be signed with the private key corresponding
                        //   to the public key in the cnf claim in the Verifier attestation JWT
                        $arData['client_id_scheme'] = 'verifier_attestation';
                        // For the current demo implementation, we expect the private key to issue ourselves a verifier_attestation
                        // private key needs to be P256
                        $verifier_attestation_privkey = $this->config->getSystemValue('oidc_login_verifier_attestation_privkey');
                        $verifier_attestation_cert = $this->config->getSystemValue('oidc_login_verifier_attestation_cert');
                        // wallet attestation key not found
                        if(is_null($verifier_attestation_privkey) || is_null($verifier_attestation_cert)) {
                            throw new LoginException("verifier_attestation set but files not configured");
                        }
                        $cert_raw = file_get_contents($verifier_attestation_cert);

                        algorithmManager = new AlgorithmManager([new ES256()]);
                        $jwk = JWKFactory::createFromKeyFile($verifier_attestation_privkey);
                        $jwsBuilder = new JWSBuilder($algorithmManager);
                        $jws = $jwsBuilder
                                ->create()
                                ->withPayload(json_encode($arData))
                                ->addSignature($jwk, ['alg' => 'ES256'])
                                ->build();
                    default:
                        throw new LoginException("unsupported client_id_scheme set");
                }
            } else {
                // if nothing is set, we default to the old behavior
                $arData['client_id_scheme'] = 'redirect_uri';
                $arData['client_id'] = $redirectUri;
            }
            if (is_null($jws)) {
                // Create request object as JWT signed with the none algorithm
                $algorithmManager = new AlgorithmManager([new None()]);
                $jwk = JWKFactory::createNoneKey();
                $jwsBuilder = new JWSBuilder($algorithmManager);
                $jws = $jwsBuilder
                            ->create()
                            ->withPayload(json_encode($arData))
                            ->addSignature($jwk, ['alg' => 'none'])
                            ->build();
            }
            $serializer = new CompactSerializer();
            $token = $serializer->serialize($jws, 0);
 
            // Create request_uri with a random id
            $requestUri = $this->urlGenerator->linkToRouteAbsolute(
                $this->appName.'.login.requestObject', 
                array('id' => bin2hex(random_bytes(16)))
            );

            // Save request object to the database
            $requestObject = new RequestObject();
            $requestObject->setRequestUri($requestUri);
            $requestObject->setRequestObject($token);
            $requestObject->setCreationTimestamp($this->timeFactory->getTime());
            $this->requestObjectMapper->insert($requestObject);

            // After JAR specification
            $arDataRequestUri['client_id'] = $redirectUri;
            $arDataRequestUri['request_uri'] = $requestUri;
            return $schema . "?" . http_build_query($arDataRequestUri);
        } else {
            $arData['presentation_definition'] = json_encode($this->presentationDefinition);
            $arData['registration'] = json_encode($this->registration);

            return $schema . "?" . http_build_query($arData);
        }
    }
}

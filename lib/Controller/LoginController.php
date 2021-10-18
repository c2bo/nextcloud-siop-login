<?php

namespace OCA\OIDCLogin\Controller;

use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\JSONResponse;
use OCP\Files\IAppData;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IConfig;
use OCP\IUserSession;
use OCP\IUserManager;
use OCP\IURLGenerator;
use OCP\IGroupManager;
use OCP\ISession;
use OCP\AppFramework\Utility\ITimeFactory;
use OC\User\LoginException;
use OC\Authentication\Token\DefaultTokenProvider;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Db\DoesNotExistException;
use OCA\OIDCLogin\LibIndyWrapper\LibIndy;
use OCA\OIDCLogin\LibIndyWrapper\LibIndyException;
use OCA\OIDCLogin\Db\Token;
use OCA\OIDCLogin\Db\TokenMapper;
use OCA\OIDCLogin\Helper\PeHelper;
use OCA\OIDCLogin\Helper\AnoncredHelper;

require_once __DIR__ . '/../../3rdparty/autoload.php';

use Endroid\QrCode\Builder\Builder;
use Endroid\QrCode\Encoding\Encoding;
use Endroid\QrCode\ErrorCorrectionLevel\ErrorCorrectionLevelHigh;
use Endroid\QrCode\RoundBlockSizeMode\RoundBlockSizeModeMargin;
use Endroid\QrCode\Writer\SvgWriter;

use Jose\Component\Core\JWK;
use Jose\Easy\Load;
use OCA\OIDCLogin\Helper\PresentationExchangeHelper;

use function Safe\json_decode;

class LoginController extends Controller
{
    /** @var IConfig */
    private $config;
    /** @var IURLGenerator */
    private $urlGenerator;
    /** @var IUserManager */
    private $userManager;
    /** @var IUserSession */
    private $userSession;
    /** @var IGroupManager */
    private $groupManager;
    /** @var ISession */
    private $session;
    /** @var IL10N */
    private $l;
    /** @var \OCA\Files_External\Service\GlobalStoragesService */
    private $storagesService;
    /** @var IAppData */
    private $appData;


    public function __construct(
        $appName,
        IRequest $request,
        IConfig $config,
        IURLGenerator $urlGenerator,
        IUserManager $userManager,
        IUserSession $userSession,
        IGroupManager $groupManager,
        ISession $session,
        IL10N $l,
        IAppData $appData,
        TokenMapper $tokenMapper,
        ITimeFactory $timeFactory,
        $storagesService
    ) {
        parent::__construct($appName, $request);
        $this->config = $config;
        $this->urlGenerator = $urlGenerator;
        $this->userManager = $userManager;
        $this->userSession = $userSession;
        $this->groupManager = $groupManager;
        $this->session = $session;
        $this->l = $l;
        $this->appData = $appData;
        $this->tokenMapper = $tokenMapper;
        $this->timeFactory = $timeFactory;
        $this->storagesService = $storagesService;
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     * @UseSession
     */
    public function oidc()
    {
        if ($redirectUrl = $this->request->getParam('login_redirect_url')) {
            $this->session->set('login_redirect_url', $redirectUrl);
        }

        $redirectUri = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.callback');
        $redirectUriPost = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.backend');
        $nonce = strval(random_int(1000000000,9999999999)) . strval(random_int(1000000000,9999999999));
        $this->session['nonce'] = $nonce;

        $schemaConfig = $this->config->getSystemValue('oidc_login_schema_config', array());
        $acHelper = new AnoncredHelper($schemaConfig);        
        $schemaAttr = $acHelper->getSchemaAttributes();
        $claims = array(
            'vp_token' => PresentationExchangeHelper::createPresentationDefinition(
                $schemaConfig, $schemaAttr
            ),
        );

        $registration = array(
            'subject_identifier_types_supported' => array('jkt'),
            'vp_formats' => array('ac_vp' => array()),
            'id_token_signing_alg_values_supported' => array('ES384', 'RS256'),
        );

        $arPost = array(
            'response_type' => 'id_token',
            'response_mode' => 'post',
            'client_id' => $redirectUriPost,
            'redirect_uri' => $redirectUriPost,
            'scope' => 'openid',
            'claims' => json_encode($claims),
            'nonce' => $nonce,
            'registration' => json_encode($registration)
        );

        $arUrlPost = "openid://?" . http_build_query($arPost);

        $result = Builder::create()
            ->writer(new SvgWriter())
            ->writerOptions([SvgWriter::WRITER_OPTION_EXCLUDE_XML_DECLARATION => true])
            ->data($arUrlPost)
            ->encoding(new Encoding('ISO-8859-1'))
            ->errorCorrectionLevel(new ErrorCorrectionLevelHigh())
            ->size(600)
            ->margin(0)
            ->roundBlockSizeMode(new RoundBlockSizeModeMargin())
            ->build();
        $dataUri = $result->getDataUri();

        $ar = array(
            'response_type' => 'id_token',
            'client_id' => $redirectUri,
            'redirect_uri' => $redirectUri,
            'scope' => 'openid',
            'claims' => json_encode($claims),
            'nonce' => $nonce,
            'registration' => json_encode($registration)
        );

        $arUrl = "openid://?" . http_build_query($ar);
        
        $params = array(
            'qr' => $dataUri,
            'arPost' => $arUrlPost,
            'ar' => $arUrl,
            'pollingUri' => $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.polling'),
            'callbackUri' => $redirectUri,
        );

        return new TemplateResponse('oidc_login', 'AuthorizationRequest', $params);
    }

    private function saveTokens(string $idTokenRaw, string $vpTokenRaw, bool $used) {
        // extract nonce from JWT payload
        $idTokenPayloadEncoded = explode(".", $idTokenRaw)[1];
        $idTokenPayload = json_decode(base64_decode($idTokenPayloadEncoded, true), true);
        $nonce = $idTokenPayload['nonce'];

        if (!empty($nonce)) {
            $token = new Token();
            $token->setNonce($nonce);
            $token->setIdToken($idTokenRaw);
            $token->setVpToken($vpTokenRaw);
            $token->setUsed($used);
            $token->setCreationTimestamp($this->timeFactory->getTime());
            $this->tokenMapper->insert($token);
            return $token;
        }
        return null;
    }

    private function getTokens($nonce) {
        try {
            return $this->tokenMapper->find($nonce);
        } catch (DoesNotExistException $e) {
            return null;
        }
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     */
    public function backend($id_token, $vp_token) {
        $this->saveTokens($id_token, $vp_token, false);
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     */
    public function polling() {
        $nonce = $this->session['nonce'];
        $tokens = $this->getTokens($nonce);
        if (empty($tokens)) {
            return new JSONResponse(array('finished' => FALSE));
        }
        return new JSONResponse(array('finished' => TRUE));
    }

    /**
     * @PublicPage
     * @NoCSRFRequired
     * @UseSession
     */
    public function callback($id_token='', $vp_token='') {
        $nonceFromSession = $this->session['nonce'];
             
        // check if we have tokens for this session in the database
        $tokens = $this->getTokens($nonceFromSession);
        if (!empty($tokens)) {
            // if the tokens where already used redirect to user to the main page
            if ($tokens->getUsed()) {
                return $this->redirectToMainPage();
            }

            $idTokenRaw = $tokens->getIdToken();
            $vpTokenRaw = $tokens->getVpToken();
            $redirectUri = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.backend');
        } elseif (strlen($id_token) != 0 && strlen($vp_token) != 0) {
            // if no tokens are in the database look for the ones in the GET parameter
            $idTokenRaw = $id_token;
            $vpTokenRaw = $vp_token;
            $redirectUri = $this->urlGenerator->linkToRouteAbsolute($this->appName.'.login.callback');
        } else {
            // if no tokens where found, cancel login with error page
            throw new LoginException("No id_token or vp_token passed to callback method");
        }
        
        // extract key from JWT payload
        $idTokenPayloadEncoded = explode(".", $idTokenRaw)[1];
        $idTokenPayload = json_decode(base64_decode($idTokenPayloadEncoded, true), true);
        $jwkJSON = $idTokenPayload['sub_jwk'];
        $jwk = JWK::createFromJson(json_encode($jwkJSON));

        // validate JWT signature
        $idToken = Load::jws($idTokenRaw)
            ->algs(['ES384', 'RS256'])
            ->aud($redirectUri)
            ->iss('https://self-issued.me/v2')
            ->sub($jwk->thumbprint('sha256'))
            ->exp()    
            ->iat()    
            ->nbf()
            ->key($jwk)
            ->run();

        $nonce = $idToken->claims->nonce();

        // check if the nonce from the id_token matches the session nonce
        if ($nonce != $nonceFromSession) {
            throw new LoginException('Nonce does not match ('.$nonce.' != '.$nonceFromSession.')');
        }

        $schemaConfig = $this->config->getSystemValue('oidc_login_schema_config', array());
        $acHelper = new AnoncredHelper($schemaConfig);
        $acHelper->parseProof($idToken->claims->get('_vp_token_'), $vpTokenRaw);
        
        $schemaAttr = $acHelper->getSchemaAttributes();
        $proofRequest = PresentationExchangeHelper::createProofRequest($nonce, $schemaConfig, $schemaAttr);
        
        $schemaResponse = $acHelper->getSchema();
        $schemas = json_encode(array(
            $schemaResponse->getId() => json_decode($schemaResponse->getJson())
        ));
        $credDefResponse = $acHelper->getCredDef();
        $credentials = json_encode(array(
            $credDefResponse->getId() => json_decode($credDefResponse->getJson())
        ));
        
        // TODO uncomment these lines if used with the Lissi App
        /*$valid = $libIndy->verifierVerifyProof($proofRequest, $proof, $schemas, $credentials, "{}", "{}")->get();
        
        if (!$valid->isValid()) {
            throw new LoginException("Credential verification failed");
        }*/

        // get attributes from proof
        $profile = $acHelper->getAttributesFromProof($vpTokenRaw);

        // after successful verification save the tokens in the database or update the entry
        if (empty($tokens)) {
            $tokens = $this->saveTokens($idTokenRaw, $vpTokenRaw, true);
        }
        $tokens->setUsed(true);
        $this->tokenMapper->update($tokens);
        
        return $this->login($profile);
    }

    private function authSuccess($profile)
    {
        if ($redirectUrl = $this->request->getParam('login_redirect_url')) {
            $this->session->set('login_redirect_url', $redirectUrl);
        }

        return $this->login($profile);
    }

    private function login($profile)
    {
        // Redirect if already logged in
        if ($this->userSession->isLoggedIn()) {
            return new RedirectResponse($this->urlGenerator->getAbsoluteURL('/'));
        }

        // Get attributes
        $confattr = $this->config->getSystemValue('oidc_login_attributes', array());
        $defattr = array(
            'id' => 'sub',
            'name' => 'name',
            'mail' => 'email',
            'quota' => 'ownCloudQuota',
            'home' => 'homeDirectory',
            'ldap_uid' => 'uid',
            'groups' => 'ownCloudGroups',
        );
        $attr = array_merge($defattr, $confattr);

        $joinAttr = $this->config->getSystemValue('oidc_login_join_attributes', array());
        foreach ($joinAttr as $key => $values) {
            $profile[$key] = '';
            foreach ($values as $v) {
                $profile[$key] = $profile[$key] . ' ' . $profile[$v];
            }
        }

        // Flatten the profile array
        $profile = $this->flatten($profile);

        // Get UID
        $uid = $profile[$attr['id']];

        // Ensure the LDAP user exists if we are proxying for LDAP
        if ($this->config->getSystemValue('oidc_login_proxy_ldap', false)) {
            // Get LDAP uid
            $ldapUid = $profile[$attr['ldap_uid']];
            if (empty($ldapUid)) {
                throw new LoginException($this->l->t('No LDAP UID found in OpenID response'));
            }

            // Get the LDAP user backend
            $ldap = NULL;
            foreach ($this->userManager->getBackends() as $backend) {
                if ($backend->getBackendName() == $this->config->getSystemValue('oidc_login_ldap_backend', "LDAP")) {
                    $ldap = $backend;
                }
            }

            // Check if backend found
            if ($ldap == NULL) {
                throw new LoginException($this->l->t('No LDAP user backend found!'));
            }

            // Get LDAP Access object
            $access = $ldap->getLDAPAccess($ldapUid);

            // Get the DN
            $dns = $access->fetchUsersByLoginName($ldapUid);
            if (empty($dns)) {
                throw new LoginException($this->l->t('Error getting DN for LDAP user'));
            }
            $dn = $dns[0];

            // Store the user
            $ldapUser = $access->userManager->get($dn);
            if ($ldapUser == NULL) {
                throw new LoginException($this->l->t('Error getting user from LDAP'));
            }

            // Method no longer exists on NC 20+
            if (method_exists($ldapUser, 'update')) {
                $ldapUser->update();
            }

            // Update the email address (#84)
            if (method_exists($ldapUser, 'updateEmail')) {
                $ldapUser->updateEmail();
            }

            // Force a UID for existing users with a different
            // user ID in nextcloud than in LDAP
            $uid = $ldap->dn2UserName($dn) ?: $uid;
        }

        // Check UID
        if (empty($uid)) {
            throw new LoginException($this->l->t('Can not get identifier from provider'));
        }

        // Check max length of uid
        if (strlen($uid) > 64) {
            $uid = md5($uid);
        }

        // Get user with fallback
        $user = $this->userManager->get($uid);
        $userPassword = '';

        // Create user if not existing
        if (null === $user) {
            if ($this->config->getSystemValue('oidc_login_disable_registration', true)) {
                throw new LoginException($this->l->t('Auto creating new users is disabled'));
            }

            $userPassword = substr(base64_encode(random_bytes(64)), 0, 30);
            $user = $this->userManager->createUser($uid, $userPassword);
        }

        // Get base data directory
        $datadir = $this->config->getSystemValue('datadirectory');

        // Set home directory unless proxying for LDAP
        if (!$this->config->getSystemValue('oidc_login_proxy_ldap', false) &&
             array_key_exists($attr['home'], $profile)) {

            // Get intended home directory
            $home = $profile[$attr['home']];

            if($this->config->getSystemValue('oidc_login_use_external_storage', false)) {
                // Check if the files external app is enabled and injected
                if ($this->storagesService === null) {
                    throw new LoginException($this->l->t('files_external app must be enabled to use oidc_login_use_external_storage'));
                }

                // Check if the user already has matching storage on their root
                $storages = array_filter($this->storagesService->getStorages(), function ($storage) use ($uid) {
                    return in_array($uid, $storage->getApplicableUsers()) && // User must own the storage
                        $storage->getMountPoint() == "/" && // It must be mounted as root
                        $storage->getBackend()->getIdentifier() == 'local' && // It must be type local
                        count($storage->getApplicableUsers() == 1); // It can't be shared with other users
                });

                if(!empty($storages)) {
                    // User had storage on their / so make sure it's the correct folder
                    $storage = array_values($storages)[0];
                    $options = $storage->getBackendOptions();

                    if($options['datadir'] != $home) {
                        $options['datadir'] = $home;
                        $storage->setBackendOptions($options);
                        $this->storagesService->updateStorage($storage);
                    }
                } else {
                    // User didnt have any matching storage on their root, so make one
                    $storage = $this->storagesService->createStorage('/', 'local', 'null::null', array(
                        'datadir' => $home
                    ), array(
                        'enable_sharing' => true
                    ));
                    $storage->setApplicableUsers([$uid]);
                    $this->storagesService->addStorage($storage);
                }
            } else {
                // Make home directory if does not exist
                mkdir($home, 0777, true);

                // Home directory (intended) of the user
                $nhome = "$datadir/$uid";

                // Check if correct link or home directory exists
                if (!file_exists($nhome) || is_link($nhome)) {
                    // Unlink if invalid link
                    if (is_link($nhome) && readlink($nhome) != $home) {
                        unlink($nhome);
                    }

                    // Create symlink to directory
                    if (!is_link($nhome) && !symlink($home, $nhome)) {
                        throw new LoginException("Failed to create symlink to home directory");
                    }
                }
            }
        }

        // Update user profile
        if (!$this->config->getSystemValue('oidc_login_proxy_ldap', false)) {
            if ($attr['name'] !== null) {
                $user->setDisplayName($profile[$attr['name']] ?: $profile[$attr['id']]);
            }

            if ($attr['mail'] !== null) {
                $user->setEMailAddress((string)$profile[$attr['mail']]);
            }

            // Set optional params
            if (array_key_exists($attr['quota'], $profile)) {
                $user->setQuota((string) $profile[$attr['quota']]);
            } else {
                if ($defaultQuota = $this->config->getSystemValue('oidc_login_default_quota')) {
                    $user->setQuota((string) $defaultQuota);
                };
            }

            // Groups to add user in
            $groupNames = [];

            // Add administrator group from attribute
            $manageAdmin = array_key_exists('is_admin', $attr) && $attr['is_admin'];
            if ($manageAdmin) {
                $adminAttr = $attr['is_admin'];
                if (array_key_exists($adminAttr, $profile) && $profile[$adminAttr]) {
                    array_push($groupNames, 'admin');
                }
            }

            // Add default group if present
            if ($defaultGroup = $this->config->getSystemValue('oidc_login_default_group')) {
                array_push($groupNames, $defaultGroup);
            }

            // Add user's groups from profile
            $hasProfileGroups = array_key_exists($attr['groups'], $profile);
            if ($hasProfileGroups) {
                // Get group names
                $profileGroups = $profile[$attr['groups']];

                // Explode by space if string
                if (is_string($profileGroups)) {
                    $profileGroups = array_filter(explode(' ', $profileGroups));
                }

                // Make sure group names is an array
                if (!is_array($profileGroups)) {
                    throw new LoginException($attr['groups'] . ' must be an array');
                }

                // Add to all groups
                $groupNames = array_merge($groupNames, $profileGroups);
            }

            // Remove duplicate groups
            $groupNames = array_unique($groupNames);

            // Remove user from groups not present
            $currentUserGroups = $this->groupManager->getUserGroups($user);
            foreach ($currentUserGroups as $currentUserGroup) {
                if (($key = array_search($currentUserGroup->getDisplayName(), $groupNames)) !== false) {
                    // User is already in group - don't process further
                    unset($groupNames[$key]);
                } else {
                    // User is not supposed to be in this group
                    // Remove the user ONLY if we're using profile groups
                    // or the group is the `admin` group and we manage admin role
                    if ($hasProfileGroups || ($manageAdmin && $currentUserGroup->getDisplayName() === 'admin')) {
                        $currentUserGroup->removeUser($user);
                    }
                }
            }

            // Add user to group
            foreach ($groupNames as $group) {
                // Get existing group
                $systemgroup = $this->groupManager->get($group);

                // Create group if does not exist
                if (!$systemgroup && $this->config->getSystemValue('oidc_create_groups', false)) {
                    $systemgroup = $this->groupManager->createGroup($group);
                }

                // Add user to group
                if ($systemgroup) {
                    $systemgroup->addUser($user);
                }
            }
        }

        // Complete login
        $this->userSession->getSession()->regenerateId();
        $tokenProvider = \OC::$server->query(DefaultTokenProvider::class);
        $this->userSession->setTokenProvider($tokenProvider);
        $this->userSession->createSessionToken($this->request, $user->getUID(), $user->getUID());
        $token = $tokenProvider->getToken($this->userSession->getSession()->getId());

        $this->userSession->completeLogin($user, [
            'loginName' => $user->getUID(),
            'password' => $userPassword,
            'token' => empty($userPassword) ? $token : null,
        ], false);
        
        //Workaround to create user files folder. Remove it later.
        \OC::$server->query(\OCP\Files\IRootFolder::class)->getUserFolder($user->getUID());

        // Prevent being asked to change password
        $this->session->set('last-password-confirm', \OC::$server->query(ITimeFactory::class)->getTime());

        return $this->redirectToMainPage();
    }

    private function redirectToMainPage() {
        // Go to redirection URI
        if ($redirectUrl = $this->session->get('login_redirect_url')) {
            return new RedirectResponse($redirectUrl);
        }

        // Fallback redirection URI
        $redir = '/';
        if ($login_redir = $this->session->get('oidc_redir')) {
            $redir = $login_redir;
        }

        return new RedirectResponse($this->urlGenerator->getAbsoluteURL($redir));
    }

    private function flatten($array, $prefix = '') {
        $result = array();
        foreach($array as $key => $value) {
            $result[$prefix . $key] = $value;
            if (is_array($value)) {
                $result = $result + $this->flatten($value, $prefix . $key . '_');
            }
            if (is_int($key) && is_string($value)) {
                $result[$prefix . $value] = $value;
            }
        }
        return $result;
    }
}

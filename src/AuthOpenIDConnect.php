<?php

require_once(__DIR__ . "/vendor/autoload.php");

use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;

/**
 * AuthOpenIDConnect
 */
class AuthOpenIDConnect extends AuthPluginBase
{
    /**
     * @var string
     */
    protected $storage = 'DbStorage';

    /**
     * @var array
     */
    protected $settings = [
        'info' => [
            'type' => 'info',
            'content' => '<h1>OpenID Connect</h1><p>Please provide the following settings.</br>If necessary settings are missing, the default authdb login will be shown.</p>'
        ],
        'providerURL' => [
            'type' => 'string',
            'label' => 'Provider URL',
            'help' => 'Required',
            'default' => ''
        ],
        'clientID' => [
            'type' => 'string',
            'label' => 'Client ID',
            'help' => 'Required',
            'default' => ''
        ],
        'clientSecret' => [
            'type' => 'string',
            'label' => 'Client Secret',
            'help' => 'Required',
            'default' => ''
        ],
        'scope' => [
            'type' => 'string',
            'label' => 'Scope',
            'help' => 'Required',
            'default' => ''
        ],
        'acrValues' => [
            'type' => 'string',
            'label' => 'Extra ACR Values to set',
            'default' => ''
        ],
        'attributeUsername' => [
            'type' => 'string',
            'label' => 'OIDC Attribute Username',
            'help' => 'Required',
            'default' => 'username'
        ],
        'attributeGivenName' => [
            'type' => 'string',
            'label' => 'OIDC Attribute GivenName',
            'help' => 'Required',
            'default' => 'givenName'
        ],
        'attributeFamilyName' => [
            'type' => 'string',
            'label' => 'OIDC Attribute FamilyName',
            'help' => 'Required',
            'default' => 'familyName'
        ],
        'attributeEmail' => [
            'type' => 'string',
            'label' => 'OIDC Attribute GivenName',
            'help' => 'Required',
            'default' => 'email'
        ],
        'redirectURL' => [
            'type' => 'string',
            'label' => 'Redirect URL',
            'help' => 'The Redirect URL.',
            'default' => '',
            'htmlOptions' => [
                'readOnly' => true,
            ]
        ]
    ];

    /**
     * @var string
     */
    static protected $description = 'OpenID Connect Authentication Plugin for LimeSurvey';

    /**
     * @var string
     */
    static protected $name = 'AuthOpenIDConnect';

    /**
     * @return void
     */
    public function init(): void
    {
        $this->subscribe('beforeActivate');
        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');

        // logout related
        $this->subscribe('beforeLogout');
        $this->subscribe('afterLogout');
    }

    /**
     * @return OpenIDConnectClient
     */
    private function getOIDCClient(): ?OpenIDConnectClient
    {
        $providerURL = $this->get('providerURL', null, null, false);
        $clientID = $this->get('clientID', null, null, false);
        $clientSecret = $this->get('clientSecret', null, null, false);

        if (!$providerURL || !$clientSecret || !$clientID) {
            return null;
        }

        $oidc = new OpenIDConnectClient(
            $providerURL,
            $clientID,
            $clientSecret
        );

        $oidc->addScope(explode(',', $this->get('scope', null, null, [])));

        $acrValues = $this->get('acrValues', null, null, false);

        // enable 2fa if requested
        if ($acrValues) {
            $oidc->addAuthParam(['acr_values' => $acrValues]);
        }

        $oidc->setRedirectURL($this->get('redirectURL', null, null, false));

        return $oidc;
    }

    /**
     * @return void
     */
    public function beforeActivate()
    {
        $baseURL = 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://' . "{$_SERVER['HTTP_HOST']}";
        $basePath = preg_split("/\/pluginmanager/", $_SERVER['REQUEST_URI']);

        $this->set('redirectURL', $baseURL . $basePath[0] . "/authentication/sa/login");
    }

    /**
     * @return void
     */
    public function beforeLogin(): void
    {
        $oidc = $this->getOIDCClient();

        if (is_null($oidc) || isset($_REQUEST['error'])) {
            return;
        }

        /* @var $authEvent LimeSurvey\PluginManager\PluginEvent */
        $authEvent = $this->getEvent();

        try {
            if ($oidc->authenticate()) {
                $username = $oidc->requestUserInfo($this->get('attributeUsername', null, null, false));
                $givenName = $oidc->requestUserInfo($this->get('attributeGivenName', null, null, false));
                $familyName = $oidc->requestUserInfo($this->get('attributeFamilyName', null, null, false));
                $email = $oidc->requestUserInfo($this->get('attributeEmail', null, null, false));

                $user = $this->api->getUserByName($username);

                if (empty($user)) {
                    $user = new User;
                    $user->users_name = $username;
                    $user->setPassword(createPassword());
                    $user->full_name = $givenName . ' ' . $familyName;
                    $user->parent_id = 1;
                    $user->lang = $this->api->getConfigKey('defaultlang', 'en');
                    $user->email = $email[0];

                    if (!$user->save()) {
                        $this->setAuthFailure(self::ERROR_USERNAME_INVALID, gT('Unable to create user'), $authEvent);
                        return;
                    }
                }

                $this->setUsername($user->users_name);
                $this->setAuthPlugin();

                return;
            }
        } catch (Throwable $error) {
            // Error occurred during authentication process, redirect to authdb login.
            $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, gT($error->getMessage()), $authEvent);
            return;
        }
    }

    /**
     * @return void
     */
    public function newUserSession(): void
    {
        $identity = $this->getEvent()->get('identity');

        if ($identity->plugin != 'AuthOpenIDConnect') {
            return;
        }

        $user = $this->api->getUserByName($this->getUsername());

        // Shouldn't happen, but just to be sure.
        if (empty($user)) {
            $this->setAuthFailure(self::ERROR_UNKNOWN_IDENTITY, gT('User not found.'));
        } else {
            $this->setAuthSuccess($user);
        }
    }

    /**
     * @return void
     * @throws OpenIDConnectClientException
     */
    public function beforeLogout(): void
    {
        $oidc = $this->getOIDCClient();
        $oidc->signOut(session('oidcIDToken'), route('auth.oidc.logout.callback'));
    }

    /**
     * @return void
     */
    public function afterLogout(): void
    {
        Yii::app()->getRequest()->redirect('/', true, 302);
    }

    /**
     * @inheritdoc
     */
    public static function getAuthMethodName(): string
    {
        // Using string literal here so it can be picked by translation bot
        return gT('OpenID Connect Authentication');
    }
}

?>

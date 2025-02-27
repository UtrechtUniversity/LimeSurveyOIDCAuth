<?php

require_once(__DIR__ . "/vendor/autoload.php");

use Jumbojett\OpenIDConnectClient;

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
        'attributeMapping' => [
            'type' => 'text',
            'label' => 'OIDC attribute mapping',
            'help' => 'Required, see documentation for more information',
            'default' => ''
        ],
        'acrValues' => [
            'type' => 'string',
            'label' => 'Extra ACR Values to set',
            'default' => ''
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
        $this->subscribe('afterLogout');
    }

    /**
     * @return void
     */
    public function beforeActivate(){
        $baseURL = 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://' . "{$_SERVER['HTTP_HOST']}";
        $basePath = preg_split("/\/pluginmanager/", $_SERVER['REQUEST_URI']);

        $this->set('redirectURL', $baseURL . $basePath[0] . "/authentication/sa/login");
    }

    /**
     * @return void
     */
    public function beforeLogin(): void
    {
        /* @var $authEvent LimeSurvey\PluginManager\PluginEvent */
        $authEvent = $this->getEvent();

        $providerURL = $this->get('providerURL', null, null, false);
        $clientID = $this->get('clientID', null, null, false);
        $clientSecret = $this->get('clientSecret', null, null, false);
        $redirectURL = $this->get('redirectURL', null, null, false);
        $scope = $this->get('scope', null, null, false);
        $attributeMapping = $this->get('attributeMapping', null, null, false);
        $acrValues = $this->get('acrValues', null, null, false);

        if (!$providerURL || !$clientSecret || !$clientID || !$redirectURL || !$scope || !$attributeMapping) {
            // Display authdb login if necessary plugin settings are missing.
            return;
        }

        $oidc = new OpenIDConnectClient($providerURL, $clientID, $clientSecret);
        $oidc->setRedirectURL($redirectURL);
        $oidc->addScope(explode(',', $scope));

        if ($acrValues) {
            $oidc->addAuthParam(['acr_values' => $acrValues]);
        }

        if (isset($_REQUEST['error'])) {
            return;
        }

        try {
            if ($oidc->authenticate()) {
                $attributeMapping = json_decode($attributeMapping, true);

                $username = $oidc->requestUserInfo($attributeMapping['username']);
                $email = $oidc->requestUserInfo($attributeMapping['email']);
                $givenName = $oidc->requestUserInfo($attributeMapping['givenName']);
                $familyName = $oidc->requestUserInfo($attributeMapping['familyName']);

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
                    // User successfully created.
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

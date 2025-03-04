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
        'forceOIDCLogin' => [
            'type' => 'boolean',
            'label' => 'Force OIDC Login',
            'help' => 'When true, all users have to login using OIDC, if false, they can still use the regular AuthDB method',
            'default' => true
        ],
        'loginFormOIDCIntroText' => [
            'type' => 'string',
            'label' => 'Login Form Intro Text',
            'help' => 'The text displayed in the intro text of the login form.',
            'default' => 'Use the button below to login into LimeSurvey using your OIDC account'
        ],
        'loginFormOIDCBtnText' => [
            'type' => 'string',
            'label' => 'Login Form Button Text',
            'help' => 'The text displayed in the button text of the login form.',
            'default' => 'Login using OIDC'
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
            'help' => 'Optional, can be used to force 2FA for example',
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
        ],
        'postLogoutCallBackURL' => [
            'type' => 'string',
            'label' => 'Post Logout CallBack URL',
            'help' => 'Post Logout CallBack.',
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
        $this->subscribe('getGlobalBasePermissions');
        $this->subscribe('beforeActivate');
        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');

        // logout related
        $this->subscribe('beforeLogout');
        $this->subscribe('afterLogout');

        if (!$this->get('forceOIDCLogin', null, null, false)) {
            $this->subscribe('newLoginForm');
        }
    }

    /**
     * getGlobalBasePermissions
     *
     * Add AuthLDAP Permission to global Permission
     */
    public function getGlobalBasePermissions()
    {
        $this->getEvent()->append('globalBasePermissions', array(
            'auth_oidc' => array(
                'create' => false,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
                'title' => gT("Use OIDC authentication"),
                'description' => gT("Use OIDC authentication"),
                'img' => 'usergroup'
            ),
        ));
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

        if ($acrValues) {
            $oidc->addAuthParam(['acr_values' => $acrValues]);
        }

        $oidc->setRedirectURL($this->get('redirectURL', null, null, false));

        return $oidc;
    }

    /**
     * @param $oidc
     * @param $name
     * @return false|mixed|null
     * @throws Exception
     */
    private function getAttribute($oidc, $name) {
        $attributeName = $this->get($name, null, null, false);

        if (!$attributeName) {
            throw new Exception('Missing attribute name: ' . $name);
        }

        $attribute = $oidc->requestUserInfo($attributeName);

        if (is_array($attribute)) {
            return current($attribute);
        }

        return $attribute;
    }

    /**
     * @return void
     */
    public function beforeActivate()
    {
        $baseURL = 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://' . "{$_SERVER['HTTP_HOST']}";
        $basePath = preg_split("/\/pluginmanager/", $_SERVER['REQUEST_URI']);

        $this->set('redirectURL', $baseURL . $basePath[0] . "/authentication/sa/login?oidc=true");
        $this->set('postLogoutCallBackURL', $baseURL . $basePath[0] . "/authentication/sa/logout");
    }

    /**
     * newLoginForm
     */
    public function newLoginForm()
    {
        $authTypeBase = $this->get('authtype_base', null, null, 'Authdb');

        $loginFormContent = '<div style="text-align:left; padding-bottom: 10px; margin-bottom: 10px; border-bottom: dashed 1px #000;">'.$this->get('loginFormOIDCIntroText').'<br /><br /><a class="btn btn-warning" href="?oidc=true" title="OIDC Login">'.$this->get('loginFormOIDCBtnText').'</a></><br></div>';

        $this
            ->getEvent()
            ->getContent($authTypeBase)
            ->addContent($loginFormContent, 'prepend');
    }

    /**
     * @return void
     */
    public function beforeLogin(): void
    {
        if(!$this->get('forceOIDCLogin', null, null, false)) {
            if(!($_GET['oidc'] === 'true')) {
                return;
            }
        }

        $oidc = $this->getOIDCClient();

        if (is_null($oidc) || isset($_REQUEST['error'])) {
            return;
        }

        /* @var $authEvent LimeSurvey\PluginManager\PluginEvent */
        $authEvent = $this->getEvent();

        try {
            if ($oidc->authenticate()) {
                $username = $this->getAttribute($oidc, 'attributeUsername');
                $givenName = $this->getAttribute($oidc, 'attributeGivenName');
                $familyName = $this->getAttribute($oidc, 'attributeFamilyName');
                $email = $this->getAttribute($oidc, 'attributeEmail');

                $user = $this->api->getUserByName($username);

                if (empty($user)) {
                    $user = new User;
                    $user->users_name = $username;
                    $user->setPassword(createPassword());
                    $user->full_name = $givenName . ' ' . $familyName;
                    $user->parent_id = 1;
                    $user->lang = $this->api->getConfigKey('defaultlang', 'en');
                    $user->email = $email;

                    if ($user->save()) {
                        // set default permissions
                        Permission::model()->setGlobalPermission($user->uid, 'auth_oidc');
                        Permission::model()->setGlobalPermission($user->uid, 'surveys', ['create_p']);
                    } else {
                        $this->setAuthFailure(self::ERROR_USERNAME_INVALID, gT('Unable to create user'), $authEvent);
                        return;
                    }
                }

                // store IdToken, used to sign out later on
                $_SESSION['oidcIDToken'] = $oidc->getIdToken();

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
        $oidcIDToken = $_SESSION['oidcIDToken'];

        if ($oidcIDToken) {
            unset($_SESSION["oidcIDToken"]);

            $oidc = $this->getOIDCClient();
            $oidc->signOut($oidcIDToken, $this->get('postLogoutCallBackURL', null, null, false));
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

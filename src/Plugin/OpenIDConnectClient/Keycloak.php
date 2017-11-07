<?php

namespace Drupal\keycloak\Plugin\OpenIDConnectClient;

use GuzzleHttp\ClientInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Language\LanguageInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Url;
use Drupal\openid_connect\Plugin\OpenIDConnectClientBase;
use Drupal\openid_connect\Plugin\OpenIDConnectClientInterface;
use Drupal\openid_connect\StateToken;
use Drupal\keycloak\KeycloakService;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * OpenID Connect client for Keycloak.
 *
 * Used to login to Drupal sites using Keycloak as authentication provider.
 *
 * @OpenIDConnectClient(
 *   id = "keycloak",
 *   label = @Translation("Keycloak")
 * )
 */
class Keycloak extends OpenIDConnectClientBase implements OpenIDConnectClientInterface, ContainerFactoryPluginInterface {

  /**
   * Keycloak service instance.
   *
   * @var \Drupal\keycloak\KeycloakService
   */
  protected $keycloak;

  /**
   * Constructs an instance of the Keycloak client plugin.
   *
   * @param array $configuration
   *   The plugin configuration.
   * @param string $plugin_id
   *   The plugin identifier.
   * @param mixed $plugin_definition
   *   The plugin definition.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request_stack
   *   The request stack.
   * @param \GuzzleHttp\ClientInterface $http_client
   *   The http client.
   * @param \Drupal\keycloak\KeycloakService $keycloak
   *   The Keycloak service.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   */
  public function __construct(
    array $configuration,
    $plugin_id,
    $plugin_definition,
    RequestStack $request_stack,
    ClientInterface $http_client,
    KeycloakService $keycloak,
    LoggerChannelFactoryInterface $logger_factory
  ) {
    parent::__construct(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $request_stack,
      $http_client,
      $logger_factory
    );

    $this->keycloak = $keycloak;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(
    ContainerInterface $container,
    array $configuration,
    $plugin_id,
    $plugin_definition
  ) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('request_stack'),
      $container->get('http_client'),
      $container->get('keycloak.keycloak'),
      $container->get('logger.factory')
    );
  }

  /**
   * Implements OpenIDConnectClientInterface::authorize().
   *
   * @param string $scope
   *   A string of scopes.
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse
   *   A trusted redirect response object.
   */
  public function authorize($scope = 'openid email') {
    $language_manager = \Drupal::languageManager();
    $language_none = $language_manager
      ->getLanguage(LanguageInterface::LANGCODE_NOT_APPLICABLE);
    $redirect_uri = Url::fromRoute(
      'openid_connect.redirect_controller_redirect',
      [
        'client_name' => $this->pluginId,
      ],
      [
        'absolute' => TRUE,
        'language' => $language_none,
      ]
    )->toString(TRUE);

    $url_options = [
      'query' => [
        'client_id' => $this->configuration['client_id'],
        'response_type' => 'code',
        'scope' => $scope,
        'redirect_uri' => $redirect_uri->getGeneratedUrl(),
        'state' => StateToken::create(),
      ],
    ];

    // Whether to add language parameter.
    if ($this->keycloak->isI18nEnabled()) {
      // Get current language.
      $langcode = $language_manager->getCurrentLanguage()->getId();
      // Map Drupal language code to Keycloak language identifier.
      // This is required for some languages, as Drupal uses IETF
      // script codes, while Keycloak may use IETF region codes.
      $languages = $this->keycloak->getI18nMapping();
      if (!empty($languages[$langcode])) {
        $langcode = $languages[$langcode]['locale'];
      }
      // Add parameter to request query, so the Keycloak login/register
      // pages will load using the right locale.
      $url_options['query']['kc_locale'] = $langcode;
    }

    $endpoints = $this->getEndpoints();
    // Clear _GET['destination'] because we need to override it.
    $this->requestStack->getCurrentRequest()->query->remove('destination');
    $authorization_endpoint = Url::fromUri($endpoints['authorization'], $url_options)->toString(TRUE);

    $response = new TrustedRedirectResponse($authorization_endpoint->getGeneratedUrl());
    // We can't cache the response, since this will prevent the state to be
    // added to the session. The kill switch will prevent the page getting
    // cached for anonymous users when page cache is active.
    \Drupal::service('page_cache_kill_switch')->trigger();

    return $response;
  }

  /**
   * Overrides OpenIDConnectClientBase::settingsForm().
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    $form = parent::buildConfigurationForm($form, $form_state);

    $form['keycloak_base'] = [
      '#title' => $this->t('Keycloak base URL'),
      '#description' => $this->t('The base URL of your Keycloak server. Typically <em>https://example.com[:PORT]/auth</em>.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['keycloak_base'],
    ];
    $form['keycloak_realm'] = [
      '#title' => $this->t('Keycloak realm'),
      '#description' => $this->t('The realm you connect to.'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['keycloak_realm'],
    ];

    // Keycloak realm endpoints.
    // Nice to have feature: Fetch these endpoints using an Ajax button from
    // the Keycloak OpenID configuration information endpoint at
    // https://example.com/auth/realms/realm/.well-known/openid-configuration
    // after the user entered the base URL and realm name.
    $form['authorization_endpoint_kc'] = [
      '#title' => $this->t('Authorization endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['authorization_endpoint_kc'],
    ];
    $form['authorization_endpoint_kc'] = [
      '#title' => $this->t('Authorization endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['authorization_endpoint_kc'],
    ];
    $form['token_endpoint_kc'] = [
      '#title' => $this->t('Token endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['token_endpoint_kc'],
    ];
    $form['userinfo_endpoint_kc'] = [
      '#title' => $this->t('UserInfo endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->configuration['userinfo_endpoint_kc'],
    ];

    // Synchronize email addresses with Keycloak. This is safe as long as
    // Keycloak is the only identity broker, because - as Drupal - it allows
    // unique email addresses only within a single realm.
    $form['userinfo_update_email'] = [
      '#title' => $this->t('Update email address in user profile'),
      '#type' => 'checkbox',
      '#default_value' => !empty($this->configuration['userinfo_update_email']) ? $this->configuration['userinfo_update_email'] : '',
      '#description' => $this->t('If email address has been changed for existing user, save the new value to the user profile.'),
    ];

    // Enable/disable i18n support and map language codes to Keycloak locales.
    $language_manager = \Drupal::languageManager();
    if ($language_manager->isMultilingual()) {
      $form['keycloak_i18n'] = [
        '#title' => $this->t('Enable multilanguage support'),
        '#type' => 'checkbox',
        '#default_value' => !empty($this->configuration['userinfo_update_email']) ? $this->configuration['userinfo_update_email'] : '',
        '#description' => $this->t('Adds language parameters to Keycloak authentication requests and maps OpenID connect language tags to Drupal languages.'),
      ];
      $form['keycloak_i18n_mapping'] = [
        '#title' => $this->t('Language mappings'),
        '#description' => $this->t('If your Keycloak is using different locale codes than Drupal (e.g. "zh-CN" in Keycloak vs. "zh-hans" in Drupal), define the Keycloak language codes here that match your Drupal setup.'),
        '#type' => 'details',
        '#collapsible' => TRUE,
        '#collapsed' => FALSE,
        '#tree' => TRUE,
        '#states' => [
          'visible' => [
            ':input[name="clients[keycloak][settings][keycloak_i18n]"]' => ['checked' => TRUE],
          ],
        ],
      ];
      $languages = $this->keycloak->getI18nMapping();
      foreach ($languages as $langcode => $language) {
        $form['keycloak_i18n_mapping'][$langcode] = [
          '#type' => 'container',
          'langcode' => [
            '#type' => 'hidden',
            '#value' => $langcode,
          ],
          'target' => [
            '#title' => sprintf('%s (%s)', $language['label'], $langcode),
            '#type' => 'textfield',
            '#size' => 30,
            '#default_value' => $language['locale'],
          ],
        ];
      }
    }
    else {
      $form['keycloak_i18n'] = [
        '#type' => 'hidden',
        '#value' => FALSE,
      ];
    }

    return $form;
  }

  /**
   * Overrides OpenIDConnectClientBase::getEndpoints().
   */
  public function getEndpoints() {
    return [
      'authorization' => $this->configuration['authorization_endpoint_kc'],
      'token' => $this->configuration['token_endpoint_kc'],
      'userinfo' => $this->configuration['userinfo_endpoint_kc'],
    ];
  }

  /**
   * Implements OpenIDConnectClientInterface::retrieveUserInfo().
   *
   * @param string $access_token
   *   An access token string.
   *
   * @return array|bool
   *   A result array or false.
   */
  public function retrieveUserInfo($access_token) {
    $userinfo = parent::retrieveUserInfo($access_token);

    // Synchronize email addresses with Keycloak. This is safe as long as
    // Keycloak is the only identity broker, because - as Drupal - it allows
    // unique email addresses only within a single realm.
    if (
      $this->configuration['userinfo_update_email'] == 1 &&
      is_array($userinfo) &&
      $sub = openid_connect_extract_sub([], $userinfo)
    ) {
      // Try finding a connected user profile.
      $authmap = \Drupal::service('openid_connect.authmap');
      $account = $authmap->userLoadBySub($sub, $this->getPluginId());
      if (
        $account !== FALSE &&
        ($account->getEmail() != $userinfo['email'])
      ) {
        $set_email = TRUE;

        // Check whether the e-mail address is valid.
        if (!\Drupal::service('email.validator')->isValid($userinfo['email'])) {
          drupal_set_message(
            t(
              'The e-mail address is not valid: @email',
              [
                '@email' => $userinfo['email'],
              ]
            ),
            'error'
          );
          $set_email = FALSE;
        }

        // Check whether there is an e-mail address conflict.
        if (
         $user = user_load_by_mail($userinfo['email']) &&
         $account->id() != $user->id()
        ) {
          drupal_set_message(
            t(
              'The e-mail address is already taken: @email',
              [
                '@email' => $userinfo['email'],
              ]
            ),
            'error'
          );
          return FALSE;
        }

        // Only change the email, if no validation error occurred.
        if ($set_email) {
          $account->setEmail($userinfo['email']);
          $account->save();
        }
      }
    }

    // Whether to 'translate' locale attribute.
    if (
      !empty($userinfo['locale']) &&
      $this->keycloak->isI18nEnabled()
    ) {
      // Map Keycloak locale identifier to Drupal language code.
      // This is required for some languages, as Drupal uses IETF
      // script codes, while Keycloak may use IETF region codes for
      // localization.
      $languages = $this->keycloak->getI18nMapping(TRUE);
      if (!empty($languages[$userinfo['locale']])) {
        $userinfo['locale'] = $languages[$userinfo['locale']]['language_id'];
      }
    }

    return $userinfo;
  }

}

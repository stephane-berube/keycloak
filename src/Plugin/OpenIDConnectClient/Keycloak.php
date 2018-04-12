<?php

namespace Drupal\keycloak\Plugin\OpenIDConnectClient;

use GuzzleHttp\ClientInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\DependencyInjection\DependencySerializationTrait;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Language\LanguageInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Url;
use Drupal\openid_connect\Plugin\OpenIDConnectClientBase;
use Drupal\openid_connect\Plugin\OpenIDConnectClientInterface;
use Drupal\openid_connect\OpenIDConnectStateToken;
use Drupal\keycloak\Service\KeycloakServiceInterface;
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
  use DependencySerializationTrait;

  /**
   * The Keycloak service.
   *
   * @var \Drupal\keycloak\Service\KeycloakServiceInterface
   */
  protected $keycloak;

  /**
   * The Keycloak role matcher service.
   *
   * @var \Drupal\keycloak\Service\KeycloakRoleMatcher
   */
  protected $roleMatcher;

  /**
   * The UUID service.
   *
   * @var \Drupal\Component\Uuid\UuidInterface
   */
  protected $uuid;

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
   * @param \Drupal\keycloak\Service\KeycloakServiceInterface $keycloak
   *   The Keycloak service.
   * @param \Drupal\keycloak\Service\KeycloakRoleMatcher $role_matcher
   *   The Keycloak role manager service.
   * @param \Drupal\Component\Uuid\UuidInterface $uuid
   *   The UUID service.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   */
  public function __construct(
    array $configuration,
    $plugin_id,
    $plugin_definition,
    RequestStack $request_stack,
    ClientInterface $http_client,
    KeycloakServiceInterface $keycloak,
    KeycloakRoleMatcher $role_matcher,
    UuidInterface $uuid,
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
    $this->roleMatcher = $role_matcher;
    $this->uuid = $uuid;
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
      $container->get('keycloak.role_matcher'),
      $container->get('uuid'),
      $container->get('logger.factory')
    );
  }

  /**
   * {@inheritdoc}
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
        'state' => OpenIDConnectStateToken::create(),
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
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    $form = parent::buildConfigurationForm($form, $form_state);
    $form_state->setCached(FALSE);

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
      $form['keycloak_i18n_enabled'] = [
        '#title' => $this->t('Enable multi-language support'),
        '#type' => 'checkbox',
        '#default_value' => !empty($this->configuration['keycloak_i18n']['enabled']) ? $this->configuration['keycloak_i18n']['enabled'] : '',
        '#description' => $this->t('Adds language parameters to Keycloak authentication requests and maps OpenID connect language tags to Drupal languages.'),
      ];
      $form['keycloak_i18n'] = [
        '#title' => $this->t('Multi-language settings'),
        '#type' => 'fieldset',
        '#collapsible' => FALSE,
        '#states' => [
          'visible' => [
            ':input[name="clients[keycloak][settings][keycloak_i18n_enabled]"]' => ['checked' => TRUE],
          ],
        ],
      ];
      $form['keycloak_i18n']['mapping'] = [
        '#title' => $this->t('Language mappings'),
        '#description' => $this->t('If your Keycloak is using different locale codes than Drupal (e.g. "zh-CN" in Keycloak vs. "zh-hans" in Drupal), define the Keycloak language codes here that match your Drupal setup.'),
        '#type' => 'details',
        '#collapsible' => FALSE,
      ];
      $languages = $this->keycloak->getI18nMapping();
      foreach ($languages as $langcode => $language) {
        $form['keycloak_i18n']['mapping'][$langcode] = [
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
      $form['keycloak_i18n_enabled'] = [
        '#type' => 'hidden',
        '#value' => FALSE,
      ];
    }

    $form['keycloak_sso'] = [
      '#title' => $this->t('Replace Drupal login with Keycloak single sign-on (SSO)'),
      '#type' => 'checkbox',
      '#default_value' => !empty($this->configuration['keycloak_sso']) ? $this->configuration['keycloak_sso'] : '',
      '#description' => $this->t("Changes Drupal's authentication back-end to use Keycloak by default. Drupal's user login and registration pages will redirect to Keycloak. Existing users will be able to login using their Drupal credentials at <em>/keycloak/login</em>."),
    ];

    $form['keycloak_sign_out'] = [
      '#title' => $this->t('Enable Drupal-initiated single sign-out'),
      '#type' => 'checkbox',
      '#default_value' => !empty($this->configuration['keycloak_sign_out']) ? $this->configuration['keycloak_sign_out'] : 0,
      '#description' => $this->t("Whether to sign out of Keycloak, when the user logs out of Drupal."),
    ];
    $form['check_session_enabled'] = [
      '#title' => $this->t('Enable Keycloak-initiated single sign-out'),
      '#type' => 'checkbox',
      '#default_value' => !empty($this->configuration['check_session']['enabled']) ? $this->configuration['check_session']['enabled'] : 0,
      '#description' => $this->t('Whether to log out of Drupal, when the user ends its Keycloak session.'),
    ];
    $form['check_session'] = [
      '#title' => $this->t('Check session settings'),
      '#type' => 'fieldset',
      '#states' => [
        'visible' => [
          ':input[name="clients[keycloak][settings][check_session_enabled]"]' => ['checked' => TRUE],
        ],
      ],
    ];
    $form['check_session']['interval'] = [
      '#title' => $this->t('Check session interval'),
      '#type' => 'number',
      '#min' => 1,
      '#max' => 99999,
      '#step' => 1,
      '#size' => 5,
      '#field_suffix' => $this->t('seconds'),
      '#default_value' => !isset($this->configuration['check_session']['interval']) ? $this->configuration['check_session']['interval'] : 2,
    ];

    $form['keycloak_groups_enabled'] = [
      '#title' => $this->t('Enable user role mapping'),
      '#type' => 'checkbox',
      '#default_value' => !empty($this->configuration['keycloak_groups']['enabled']) ? $this->configuration['keycloak_groups']['enabled'] : '',
      '#description' => $this->t('Enables assigning Drupal user roles based on Keycloak group name patterns.'),
    ];

    $form['keycloak_groups'] = [
      '#title' => $this->t('User role assignment settings'),
      '#type' => 'fieldset',
      '#collapsible' => FALSE,
      '#states' => [
        'visible' => [
          ':input[name="clients[keycloak][settings][keycloak_groups_enabled]"]' => ['checked' => TRUE],
        ],
      ],
    ];
    $form['keycloak_groups']['description'] = [
      '#markup' => $this->t("<p>You can assign and remove Drupal user roles based on the user groups given to the user in Keycloak. The Keycloak user's groups will be retrieved using the UserInfo endpoint of your realm.<br />Before using this feature, you need to map group memberships to the userinfo within the mappers section of your Keycloak client settings.</p>"),
    ];
    $form['keycloak_groups']['claim_name'] = [
      '#title' => $this->t('User groups claim name'),
      '#type' => 'textfield',
      '#default_value' => !empty($this->configuration['keycloak_groups']['claim_name']) ? $this->configuration['keycloak_groups']['claim_name'] : 'groups',
      '#description' => $this->t('Name of the user groups claim. This can be a fully qualified name like "additional.groups". In this case, the user groups will be taken from the nested "groups" attribute of the "additional" claim.'),
    ];
    $form['keycloak_groups']['split_groups'] = [
      '#title' => $this->t('Split group paths'),
      '#type' => 'checkbox',
      '#default_value' => !empty($this->configuration['keycloak_groups']['split_groups']) ? $this->configuration['keycloak_groups']['split_groups'] : '',
      '#description' => $this->t('Allows splitting group paths into single group names. If enabled, Keycloak group paths will be splitted using the "/" character and every path segment will be treated as single user group name. E.g. the group path "/Internal/Public Relations" will be split into the groups "Internal" and "Public Relations", and the mapping rules will be applied to both groups. Please note: If this option is enabled, using "/" within any group name may have unintended side effects.'),
    ];
    $form['keycloak_groups']['split_groups_limit'] = [
      '#title' => $this->t('Group path nesting limit'),
      '#type' => 'number',
      '#min' => 0,
      '#max' => 99,
      '#step' => 1,
      '#size' => 2,
      '#default_value' => !empty($this->configuration['keycloak_groups']['split_groups_limit']) ? $this->configuration['keycloak_groups']['split_groups_limit'] : 0,
      '#description' => $this->t('Allows limiting the nesting level of split group paths. E.g. the group path "/Internal/Public Relations/Social Media" with a group path nesting limit of "1" will split the group path into "Internal" only, a group path nesting limit of "2" will return "Internal" and "Public Relations", and so on. A value of "0" will not limit nesting and return all groups.'),
      '#states' => [
        'visible' => [
          ':input[name="clients[keycloak][settings][keycloak_groups][split_groups]"]' => ['checked' => TRUE],
        ],
      ],
    ];
    $form['keycloak_groups']['rules_description'] = [
      '#markup' => sprintf('<strong>%s</strong>', $this->t('Mapping rules')),
    ];

    $form = array_merge_recursive($form, $this->getGroupRuleTable($form_state));

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function getEndpoints() {
    return $this->keycloak->getEndpoints();
  }

  /**
   * {@inheritdoc}
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
        $user = user_load_by_mail($userinfo['email']);
        if ($user && $account->id() != $user->id()) {
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

  /**
   * Ajax callback for a user group mapping rules table refresh.
   *
   * @param array $form
   *   An associative array containing the structure of the form.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The current state of the form.
   *
   * @return array
   *   Form builder array fragment for the user group mapping rules table.
   */
  public function rulesAjaxCallback(array &$form, FormStateInterface $form_state) {
    return $form['clients']['keycloak']['settings']['keycloak_groups']['rules'];
  }

  /**
   * Submit function for the 'Add rule' ajax callback.
   *
   * Adds an empty rule row to the user group mapping rules table.
   *
   * @param array $form
   *   An associative array containing the structure of the form.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The current state of the form.
   */
  public function addRuleSubmit(array &$form, FormStateInterface $form_state) {
    $uuid = $this->uuid->generate();
    $rules = $form_state->get('rules');
    array_push($rules, $uuid);
    $form_state->set('rules', $rules);
    $form_state->setRebuild();
  }

  /**
   * Submit function for the 'Delete rule' ajax callback.
   *
   * Removes a rule from the user group mapping rules table.
   *
   * @param array $form
   *   An associative array containing the structure of the form.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The current state of the form.
   */
  public function deleteRuleSubmit(array &$form, FormStateInterface $form_state) {
    $target_id = $form_state->getTriggeringElement()['#attributes']['data-delete-target'];
    // Remove the row from form.
    $rules = $form_state->get('rules');
    $rules = array_diff($rules, [$target_id]);
    $form_state->set('rules', $rules);
    // Rebuild the form.
    $form_state->setRebuild();
  }

  /**
   * Helper method returning user group mapping rules form array table.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The current state of the form.
   *
   * @return array
   *   Form array definition for a draggable table of user group mapping
   *   rules.
   */
  protected function getGroupRuleTable(FormStateInterface &$form_state) {
    $form = [];

    $form['keycloak_groups']['rules'] = [
      '#type' => 'table',
      '#title' => $this->t('Group mapping rules'),
      '#prefix' => '<div id="keycloak-group-roles-replace">',
      '#suffix' => '</div>',
      '#header' => [
        '',
        $this->t('Weight'),
        $this->t('User role'),
        $this->t('Action'),
        $this->t('Evaluation type'),
        $this->t('Pattern'),
        $this->t('Case sensitive'),
        $this->t('Enabled'),
        '',
      ],
      '#empty' => $this->t('There are no rules yet.'),
      '#tableselect' => FALSE,
      '#tabledrag' => [
        [
          'action' => 'order',
          'relationship' => 'sibling',
          'group' => 'keycloak-groups-rules-weight',
        ],
      ],
    ];

    $roles = ['NONE' => ''] + $this->roleMatcher->getRoleOptions();
    $operations = $this->roleMatcher->getEvalOperationOptions();

    // Get saved rules from configuration.
    $config_rules = $this->configuration['keycloak_groups']['rules'];
    // Create associative array of rules with rule id as keys.
    $rules = [];
    foreach ($config_rules as $rule) {
      $rules[$rule['id']] = $rule;
    }
    // Cross-check whether the rules are stored in the form state.
    $fs_rules = $form_state->get('rules');
    if (empty($fs_rules)) {
      // Get the rule keys.
      $fs_rules = array_keys($rules);
      // Add a new item at the bottom.
      array_push($fs_rules, $this->uuid->generate());
      // Remember these rows by IDs.
      $form_state->set('rules', $fs_rules);
    }

    // For every rule add a row to our form.
    foreach ($fs_rules as $key) {
      $row = $this->getGroupRuleRow($roles, $operations, isset($rules[$key]) ? $rules[$key] : ['id' => $key]);
      $form['keycloak_groups']['rules'][$key] = $row;
    }

    $form['keycloak_groups']['add'] = [
      '#type' => 'submit',
      '#name' => 'add',
      '#value' => $this->t('Add rule'),
      '#submit' => [[$this, 'addRuleSubmit']],
      '#ajax' => [
        'callback' => [$this, 'rulesAjaxCallback'],
        'wrapper' => 'keycloak-group-roles-replace',
        'effect' => 'none',
      ],
    ];

    return $form;
  }

  /**
   * Helper method to construct a setting form user group role mapping row.
   *
   * @param array $roles
   *   Options array holding the available user roles and an empty
   *   placeholder keyed by 'NONE'.
   * @param array $operations
   *   Options array holding the available evaluation methods.
   * @param array $defaults
   *   Default values for the rule row.
   *
   * @return array
   *   Array of form element definitions for a user group role mapping rule.
   */
  protected function getGroupRuleRow(array $roles, array $operations, array $defaults = []) {
    $uuid = empty($defaults['id']) ? $this->uuid->generate() : $defaults['id'];

    $row['#attributes']['class'][] = 'draggable';
    $row['#weight'] = !empty($defaults['weight']) ? $defaults['weight'] : 0;
    $row['id'] = [
      '#type' => 'hidden',
      '#value' => $uuid,
    ];
    $row['weight'] = [
      '#type' => 'weight',
      '#title' => t('Weight'),
      '#title_display' => 'invisible',
      '#default_value' => !empty($defaults['weight']) ? $defaults['weight'] : 0,
      '#attributes' => ['class' => ['keycloak-groups-rules-weight']],
    ];
    $row['role'] = [
      '#title' => $this->t('User role'),
      '#title_display' => 'invisible',
      '#type' => 'select',
      '#options' => $roles,
      '#default_value' => !empty($defaults['role']) ? $defaults['role'] : NULL,
    ];
    $row['action'] = [
      '#title' => $this->t('Action'),
      '#title_display' => 'invisible',
      '#type' => 'select',
      '#options' => [
        'add' => $this->t('add'),
        'remove' => $this->t('remove'),
      ],
      '#default_value' => !empty($defaults['action']) ? $defaults['action'] : NULL,
    ];
    $row['operation'] = [
      '#title' => $this->t('Evaluation type'),
      '#title_display' => 'invisible',
      '#type' => 'select',
      '#options' => $operations,
      '#default_value' => !empty($defaults['operation']) ? $defaults['operation'] : NULL,
    ];
    $row['pattern'] = [
      '#title' => $this->t('Pattern'),
      '#title_display' => 'invisible',
      '#type' => 'textfield',
      '#size' => 50,
      '#default_value' => !empty($defaults['pattern']) ? $defaults['pattern'] : NULL,
    ];
    $row['case_sensitive'] = [
      '#title' => $this->t('Case sensitive'),
      '#title_display' => 'invisible',
      '#type' => 'checkbox',
      '#default_value' => !empty($defaults['case_sensitive']) ? $defaults['case_sensitive'] : FALSE,
    ];
    $row['enabled'] = [
      '#title' => $this->t('Case sensitive'),
      '#title_display' => 'invisible',
      '#type' => 'checkbox',
      '#default_value' => !empty($defaults['enabled']) ? $defaults['enabled'] : FALSE,
    ];
    $row['delete'] = [
      '#type' => 'submit',
      '#name' => 'delete[row-' . $uuid . ']',
      '#value' => $this->t('Delete'),
      '#submit' => [[$this, 'deleteRuleSubmit']],
      '#attributes' => [
        'data-delete-target' => $uuid,
      ],
      '#ajax' => [
        'callback' => [$this, 'rulesAjaxCallback'],
        'wrapper' => 'keycloak-group-roles-replace',
        'effect' => 'none',
      ],
    ];

    return $row;
  }

}

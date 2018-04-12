<?php

namespace Drupal\keycloak\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\StringTranslation\TranslationInterface;
use Drupal\user\RoleInterface;
use Drupal\user\UserInterface;

/**
 * Role matcher service.
 *
 * Provides methods for matching Keycloak user group rules to
 * Drupal user roles.
 *
 * Notice: Method names, parameters and comments will use the term
 * 'group' to refer to Keycloak user groups and the term 'role' when
 * referring to Drupal user roles.
 */
class KeycloakRoleMatcher {
  use StringTranslationTrait;

  /**
   * A configuration object containing Keycloak client settings.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

  /**
   * The User entity storage.
   *
   * @var \Drupal\Core\Entity\EntityStorageInterface
   */
  protected $userRoleStorage;

  /**
   * The logger factory.
   *
   * @var Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * Constructs a RoleManager service object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity manager.
   * @param \Drupal\Core\StringTranslation\TranslationInterface $string_translation
   *   The string translation service.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   */
  public function __construct(
    ConfigFactoryInterface $config_factory,
    EntityTypeManagerInterface $entity_type_manager,
    TranslationInterface $string_translation,
    LoggerChannelFactoryInterface $logger_factory
  ) {
    $this->config = $config_factory->get('openid_connect.settings.keycloak');
    $this->userRoleStorage = $entity_type_manager->getStorage('user_role');
    $this->stringTranslation = $string_translation;
    $this->loggerFactory = $logger_factory;
  }

  /**
   * Whether Keycloak groups to Drupal roles synchronization is enabled.
   *
   * @return bool
   *   TRUE, if the synchronization is enabled, FALSE otherwise.
   */
  public function isEnabled() {
    return $this->config->get('enabled') &&
      $this->config->get('settings.keycloak_groups.enabled');
  }

  /**
   * Whether there are defined Keycloak role rules.
   *
   * @return bool
   *   TRUE, if rules were defined, FALSE otherwise.
   */
  public function hasRoleRules() {
    return !empty($this->config->get('settings.keycloak_groups.rules'));
  }

  /**
   * Return the Keycloak role rules.
   *
   * @param bool $enabled_only
   *   (Optional) Whether to return enabled rules only.
   *   Defaults to FALSE.
   *
   * @return array
   *   Array of role rules. Each rule is an associative array with
   *   the following keys:
   *   - id:               (Internal) ID of the rule.
   *   - weight:           The weight of the rule.
   *   - role:             Drupal role ID this rule applies to.
   *   - action:           Action to take, if the rule matches.
   *   - operation:        Rule matching operation.
   *   - pattern:          Value to evaluate.
   *   - case_sensitive:   Whether the pattern must match case-sensitive.
   *   - enabled:          Whether the rule is enabled.
   */
  public function getRoleRules($enabled_only = FALSE) {
    $rules = $this->config->get('settings.keycloak_groups.rules');

    // Make sure we return an array.
    if (empty($rules)) {
      $rules = [];
    }
    // Filter disabled rules.
    elseif ($enabled_only) {
      $rules = array_filter($rules, function ($rule) {
        return $rule['enabled'];
      });
    }

    return $rules;
  }

  /**
   * Retrieve Keycloak groups from user information.
   *
   * @param string $attribute
   *   Keycloak groups claim identifier.
   * @param array $userinfo
   *   User info array as returned by
   *   \Drupal\keycloak\Plugin\OpenIDConnectClient\Keycloak::retrieveUserInfo().
   *
   * @return array
   *   Extracted user groups.
   */
  public function getGroups($attribute, array $userinfo) {
    // Whether the user information is empty.
    if (empty($userinfo)) {
      // No group attribute. Return empty array.
      return [];
    }

    // Walk the attribute path to retrieve the user groups.
    $attribute_path = explode('.', $attribute);
    while (!empty($attribute_path)) {
      $segment = array_shift($attribute_path);

      if (isset($userinfo[$segment])) {
        $userinfo = $userinfo[$segment];
      }
      else {
        $userinfo = [];
        break;
      }
    }

    return $userinfo;
  }

  /**
   * Return the user groups claim name.
   *
   * @return string
   *   The configured (fully qualified) user groups claim name.
   */
  public function getUserGroupsClaimName() {
    return $this->config->get('settings.keycloak_groups.claim_name');
  }

  /**
   * Whether splitting group paths is enabled.
   *
   * @return bool
   *   TRUE, if splitting group paths is enabled, FALSE otherwise.
   */
  public function isSplitGroupsEnabled() {
    return $this->config->get('settings.keycloak_groups.split_groups');
  }

  /**
   * Return the maximum allowed nesting level for group path splitting.
   *
   * @return int
   *   The maximum allowed nesting limit of split group paths.
   */
  public function getSplitGroupsLimit() {
    return $this->config->get('settings.keycloak_groups.split_groups_limit');
  }

  /**
   * Applies user role rules to the given user account.
   *
   * @param \Drupal\user\UserInterface $account
   *   User account.
   * @param array $userinfo
   *   Associative array with user information.
   * @param bool $save_changes
   *   (Optional) Whether to save the account after the rules have
   *   been applied.
   *   Defaults to FALSE.
   *
   * @return bool
   *   TRUE, if the rules were applied, FALSE otherwise.
   */
  public function applyRoleRules(UserInterface &$account, array $userinfo, $save_changes = FALSE) {
    $rules = $this->getRoleRules(TRUE);
    if (empty($rules)) {
      return TRUE;
    }

    // Extract groups from userinfo.
    $groups = $this->getGroups($this->getUserGroupsClaimName(), $userinfo);

    // Split group paths, if enabled.
    if (!empty($groups) && $this->isSplitGroupsEnabled()) {
      $groups = $this->getSplitGroups($groups, $this->getSplitGroupsLimit());
    }

    $roles = $this->getRoleOptions();
    $operations = $this->getEvalOperationOptions();

    // Walk the rules and apply them.
    foreach ($rules as $rule) {
      $result = $this->evalRoleRule($groups, $rule);
      if ($result) {
        switch ($rule['action']) {
          case 'add':
            if ($this->isDebugMode()) {
              $this->getLogger()->debug('Add user role @role to @user, as evaluation "@operation @pattern" matches @groups.', [
                '@role' => $roles[$rule['role']],
                '@user' => $account->getAccountName(),
                '@operation' => $operations[$rule['operation']],
                '@pattern' => $rule['pattern'],
                '@groups' => print_r($groups, TRUE),
              ]);
            }
            $account->addRole($rule['role']);
            break;

          case 'remove':
            if ($this->isDebugMode()) {
              $this->getLogger()->debug('Remove user role @role from @user, as evaluation "@operation @pattern" matches @groups.', [
                '@role' => $roles[$rule['role']],
                '@user' => $account->getAccountName(),
                '@operation' => $operations[$rule['operation']],
                '@pattern' => $rule['pattern'],
                '@groups' => print_r($groups, TRUE),
              ]);
            }
            $account->removeRole($rule['role']);
            break;

          default:
            break;

        }
      }
    }

    // Whether to save the user account.
    if ($save_changes) {
      $account->save();
    }

    return TRUE;
  }

  /**
   * Return an options array of available role evaluation operations.
   *
   * @return array
   *   Array of available role evaluation operations that can be used
   *   as select / radio / checkbox options.
   */
  public function getEvalOperationOptions() {
    $operations = [
      'equal' => $this->t('exact match'),
      'not_equal' => $this->t('no match'),
      'starts_with' => $this->t('starts with'),
      'starts_not_with' => $this->t('starts not with'),
      'ends_with' => $this->t('ends with'),
      'ends_not_with' => $this->t('ends not with'),
      'contains' => $this->t('contains'),
      'contains_not' => $this->t('contains not'),
      'empty' => $this->t('no groups given'),
      'not_empty' => $this->t('any group given'),
      'regex' => $this->t('regex match'),
      'not_regex' => $this->t('no regex match'),
    ];
    return $operations;
  }

  /**
   * Return all available user roles as options array.
   *
   * @param bool $exclude_locked
   *   (Optional) Whether to exclude the system locked roles 'Anonymous' and
   *   'Authenticated'.
   *   Defaults to TRUE.
   *
   * @return array
   *   Array of user roles that can be used as select / radio / checkbox
   *   options.
   */
  public function getRoleOptions($exclude_locked = TRUE) {
    $role_options = [];
    $roles = $this->userRoleStorage->loadMultiple();
    foreach ($roles as $role) {
      $role_id = $role->id();
      if ($exclude_locked && ($role_id == RoleInterface::ANONYMOUS_ID || $role_id == RoleInterface::AUTHENTICATED_ID)) {
        continue;
      }
      $role_options[$role_id] = $role->label();
    }
    return $role_options;
  }

  /**
   * Return a regex evaluation pattern for user group role rules.
   *
   * @param string $pattern
   *   User entered search pattern.
   * @param string $operation
   *   Evaluation operation to conduct.
   * @param bool $case_sensitive
   *   Whether the resulting pattern shall be case-sensitive.
   *
   * @return string
   *   PCRE pattern for role rule evaluation.
   */
  protected function getEvalPattern($pattern, $operation = 'equal', $case_sensitive = TRUE) {
    // Quote regular expression characters in regular pattern string.
    if ($operation != 'regex' && $operation != 'not_regex') {
      $pattern = preg_quote($pattern, '/');
    }

    // Construct a PCRE pattern for the given operation.
    switch ($operation) {
      case 'starts_with':
      case 'starts_not_with':
        $pattern = '/^' . $pattern . '/';
        break;

      case 'ends_with':
      case 'ends_not_with':
        $pattern = '/' . $pattern . '$/';
        break;

      case 'contains':
      case 'contains_not':
      case 'regex':
      case 'not_regex':
        $pattern = '/' . $pattern . '/';
        break;

      case 'not_equal':
      default:
        $pattern = '/^' . $pattern . '$/';
        break;

    }

    // Whether the pattern shall not be case sensitive.
    if (!$case_sensitive) {
      $pattern = $pattern . 'i';
    }

    return $pattern;
  }

  /**
   * Return split user groups.
   *
   * Keycloak user groups can be nested. This helper method flattens
   * nested group paths to an one-level array of group path segments.
   *
   * @param array $groups
   *   Array of user group paths as returned by Keycloak.
   * @param int $max_level
   *   (Optional) Maximum level to split into the result. If a level
   *   greater than 0 is given, the splitting will ignore user groups
   *   with a higher nesting level. Level counting starts at 1. If a
   *   maximum of 0 is given, ALL levels will be included.
   *   Defaults to 0.
   *
   * @return array
   *   Transformed user groups array.
   */
  protected function getSplitGroups(array $groups, $max_level = 0) {
    $target = [];

    foreach ($groups as $group) {
      $segments = explode('/', trim($group, '/'));
      if ($max_level > 0) {
        $segments = array_slice($segments, 0, $max_level);
      }
      $target = array_merge($target, $segments);
    }

    return array_unique($target);
  }

  /**
   * Check, if the given rule matches the user groups.
   *
   * This method applies the given user group rule to the user groups
   * and evaluates, whether the rule action should be executed or not.
   *
   * @param array $groups
   *   User groups to evaluate.
   * @param array $rule
   *   User group rule to evaluate.
   *
   * @return bool
   *   TRUE, if the rule matches the groups, FALSE otherwise.
   */
  protected function evalRoleRule(array $groups, array $rule) {
    // Whether teh rule is disabled.
    if (!$rule['enabled']) {
      return FALSE;
    }

    $operation = $rule['operation'];

    // Check the 'empty' operation.
    if ($operation == 'empty') {
      return empty($groups);
    }

    // Check the 'not_empty' operation.
    if ($operation == 'not_empty') {
      return !empty($groups);
    }

    $pattern = $this->getEvalPattern(
      $rule['pattern'],
      $operation,
      $rule['case_sensitive']
    );

    // Apply the pattern to the user groups.
    $result = preg_grep($pattern, $groups);

    // Evaluate the result.
    // 'not' operations are TRUE, if the result array is empty.
    if (
      $operation == 'not_equal' ||
      $operation == 'starts_not_with' ||
      $operation == 'ends_not_with' ||
      $operation == 'contains_not' ||
      $operation == 'not_regex'
    ) {
      return empty($result);
    }

    // All other operations are TRUE, if the result array is not empty.
    return !empty($result);
  }

  /**
   * Return Keycloak logger.
   *
   * @return \Psr\Log\LoggerInterface
   *   Logger instance for the Keycloak module.
   */
  public function getLogger() {
    return $this->loggerFactory->get('openid_connect_keycloak');
  }

  /**
   * Whether the Keycloak client is in verbose debug mode.
   *
   * @return bool
   *   TRUE, if debug mode is enabled, FALSE otherwise.
   */
  public function isDebugMode() {
    return $this->config->get('settings.debug');
  }

}

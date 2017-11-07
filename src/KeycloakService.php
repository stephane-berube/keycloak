<?php

namespace Drupal\keycloak;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;

/**
 * Keycloak service.
 */
class KeycloakService {

  /**
   * A configuration object containing Keycloak client settings.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

  /**
   * A language manager instance.
   *
   * @var \Drupal\Core\Language\LanguageManagerInterface
   */
  protected $languageManager;

  /**
   * A logger instance.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $logger;

  /**
   * Constructor for Drupal\keycloak\KeycloakService.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Language\LanguageManagerInterface $language_manager
   *   A language manager instance.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger
   *   A logger channel factory instance.
   */
  public function __construct(
    ConfigFactoryInterface $config_factory,
    LanguageManagerInterface $language_manager,
    LoggerChannelFactoryInterface $logger
  ) {
    $this->config = $config_factory->get('openid_connect.settings.keycloak');
    $this->languageManager = $language_manager;
    $this->logger = $logger;
  }

  /**
   * Whether the Keycloak client is enabled.
   *
   * @return bool
   *   TRUE, if the Keycloak client is enabled, FALSE otherwise.
   */
  public function isEnabled() {
    return $this->config->get('enabled');
  }

  /**
   * Whether the Keycloak clients' i18n mapping is enabled.
   *
   * @return bool
   *   TRUE, if i18n mapping is enabled, FALSE otherwise.
   */
  public function isI18nEnabled() {
    return $this->languageManager->isMultilingual() &&
      $this->config->get('settings.keycloak_i18n');
  }

  /**
   * Return the Keycloak i18n locale code mapping.
   *
   * This mapping is required for some languages, as Drupal uses IETF
   * script codes, while Keycloak may use IETF region codes for its
   * localization.
   *
   * @param bool $reverse
   *   (optional) Whether to use Drupal language IDs as keys (FALSE), or
   *   Keycloak locales (TRUE).
   *   Defaults to FALSE.
   * @param bool $include_enabled
   *   (optional) Whether to include non-mapped, but in Drupal enabled
   *   languages. If no mapping is set for an enabled language, the Drupal
   *   language ID will be used as Keycloak locale. (Which most often
   *   matches the Keycloak locales by default.)
   *   Defaults to TRUE.
   *
   * @return array
   *   Associative array with i18n locale mappings with keys as specified
   *   with the $reverse parameter and an associative locale map array as
   *   value, having the following keys:
   *   - language_id:           Drupal language ID.
   *   - locale:                Keycloak locale.
   *   - label:                 Localized human-readable language label.
   */
  public function getI18nMapping($reverse = FALSE, $include_enabled = TRUE) {
    $mappings = [];

    $languages = $this->languageManager->getLanguages();
    if (empty($languages)) {
      return $mappings;
    }

    $configured = $this->config->get('settings.keycloak_i18n_mapping');
    // The stored mapping is an unkeyed list of associative arrays
    // with 'langcode' and 'target' as keys. Transform it to an assoc
    // array of 'langcode' => 'target'.
    $kc_mappings = [];
    if (!empty($configured)) {
      foreach ($configured as $mapping) {
        $kc_mappings[$mapping['langcode']] = $mapping['target'];
      }
    }

    // Create the i18n locale mapping information.
    foreach ($languages as $langcode => $language) {
      if (empty($kc_mappings[$langcode]) && !$include_enabled) {
        continue;
      }

      $mapping = [
        'language_id' => $langcode,
        'locale' => !empty($kc_mappings[$langcode]) ? $kc_mappings[$langcode] : $langcode,
        'label' => $language->getName(),
      ];

      $mappings[$reverse ? $mapping['locale'] : $langcode] = $mapping;
    }

    return $mappings;
  }

}

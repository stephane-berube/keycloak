<?php

namespace Drupal\keycloak\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;

/**
 * Keycloak service.
 */
class KeycloakService implements KeycloakServiceInterface {

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
   * The logger factory.
   *
   * @var Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * {@inheritdoc}
   */
  public function __construct(
    ConfigFactoryInterface $config_factory,
    LanguageManagerInterface $language_manager,
    LoggerChannelFactoryInterface $logger
  ) {
    $this->config = $config_factory->get('openid_connect.settings.keycloak');
    $this->languageManager = $language_manager;
    $this->loggerFactory = $logger;
  }

  /**
   * {@inheritdoc}
   */
  public function isEnabled() {
    return $this->config->get('enabled');
  }

  /**
   * {@inheritdoc}
   */
  public function getBaseUrl() {
    return $this->config->get('settings.keycloak_base');
  }

  /**
   * {@inheritdoc}
   */
  public function getRealm() {
    return $this->config->get('settings.keycloak_realm');
  }

  /**
   * {@inheritdoc}
   */
  public function getEndpoints() {
    $base = $this->getBaseUrl() . '/realms/' . $this->getRealm();
    return [
      'authorization' => $base . self::KEYCLOAK_AUTH_ENDPOINT_URI,
      'token' => $base . self::KEYCLOAK_TOKEN_ENDPOINT_URI,
      'userinfo' => $base . self::KEYCLOAK_USERINFO_ENDPOINT_URI,
      'end_session' => $base . self::KEYCLOAK_END_SESSION_ENDPOINT_URI,
      'session_iframe' => $base . self::KEYCLOAK_CHECK_SESSION_IFRAME_URI,
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function isI18nEnabled() {
    return $this->languageManager->isMultilingual() &&
      $this->config->get('settings.keycloak_i18n.enabled');
  }

  /**
   * {@inheritdoc}
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

  /**
   * {@inheritdoc}
   */
  public function getLogger() {
    return $this->loggerFactory->get('openid_connect_keycloak');
  }

  /**
   * {@inheritdoc}
   */
  public function isDebugMode() {
    return $this->config->get('settings.debug');
  }

}

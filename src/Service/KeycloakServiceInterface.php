<?php

namespace Drupal\keycloak\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;

/**
 * Keycloak service interface.
 */
interface KeycloakServiceInterface {

  /**
   * Default Keycloak OpenID configuration endpoint URI.
   */
  const KEYCLOAK_CONFIG_ENDPOINT_URI = '/.well-known/openid-configuration';

  /**
   * Default Keycloak authorization endpoint URI.
   */
  const KEYCLOAK_AUTH_ENDPOINT_URI = '/protocol/openid-connect/auth';

  /**
   * Default Keycloak token endpoint URI.
   */
  const KEYCLOAK_TOKEN_ENDPOINT_URI = '/protocol/openid-connect/token';

  /**
   * Default Keycloak userinfo endpoint URI.
   */
  const KEYCLOAK_USERINFO_ENDPOINT_URI = '/protocol/openid-connect/userinfo';

  /**
   * Default Keycloak end session endpoint URI for single sign-out propagation.
   */
  const KEYCLOAK_END_SESSION_ENDPOINT_URI = '/protocol/openid-connect/logout';

  /**
   * Default Keycloak check session iframe URI.
   */
  const KEYCLOAK_CHECK_SESSION_IFRAME_URI = '/protocol/openid-connect/login-status-iframe.html';

  /**
   * Constructor for Drupal\keycloak\Service\KeycloakService.
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
  );

  /**
   * Whether the Keycloak client is enabled.
   *
   * @return bool
   *   TRUE, if the Keycloak client is enabled, FALSE otherwise.
   */
  public function isEnabled();

  /**
   * Return the Keycloak base URL.
   *
   * @return string
   *   Keycloak base URL.
   */
  public function getBaseUrl();

  /**
   * Return the Keycloak realm.
   *
   * @return string
   *   Keycloak realm.
   */
  public function getRealm();

  /**
   * Return the available Keycloak endpoints.
   *
   * @return array
   *   Associative array with Keycloak endpoints:
   *   - authorization:         Authorization endpoint.
   *   - token:                 Token endpoint.
   *   - userinfo:              User info endpoint.
   *   - end_session:           End session endpoint.
   *   - session_iframe:        Session iframe URL.
   */
  public function getEndpoints();

  /**
   * Whether Keycloak multi-language support is enabled.
   *
   * @return bool
   *   TRUE, if multi-language support is enabled, FALSE otherwise.
   */
  public function isI18nEnabled();

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
  public function getI18nMapping($reverse = FALSE, $include_enabled = TRUE);

  /**
   * Whether Keycloak single sign-on (SSO) is enabled.
   *
   * @return bool
   *   TRUE, if single sign-on is enabled, FALSE otherwise.
   */
  public function isSsoEnabled();

  /**
   * Return Keycloak logger.
   *
   * @return \Psr\Log\LoggerInterface
   *   Logger instance for the Keycloak module.
   */
  public function getLogger();

  /**
   * Whether the Keycloak client is in verbose debug mode.
   *
   * @return bool
   *   TRUE, if debug mode is enabled, FALSE otherwise.
   */
  public function isDebugMode();

}

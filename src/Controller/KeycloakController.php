<?php

namespace Drupal\keycloak\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\keycloak\Service\KeycloakServiceInterface;
use Drupal\openid_connect\Claims;
use Drupal\openid_connect\Plugin\OpenIDConnectClientManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Keycloak controller.
 *
 * Provides controller actions for custom user login and logout.
 *
 * @see \Drupal\keycloak\Routing\RouteSubscriber
 */
class KeycloakController extends ControllerBase {

  /**
   * The Keycloak service.
   *
   * @var \Drupal\keycloak\Service\KeycloakServiceInterface
   */
  protected $keycloak;

  /**
   * The OpenID Connect plug-in manager.
   *
   * @var \Drupal\openid_connect\Plugin\OpenIDConnectClientManager
   */
  protected $pluginManager;

  /**
   * The OpenID Connect claims.
   *
   * @var \Drupal\openid_connect\Claims
   */
  protected $claims;

  /**
   * The request stack used to access request globals.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  protected $requestStack;

  /**
   * Constructs a KeycloakController object.
   *
   * @param \Drupal\keycloak\Service\KeycloakServiceInterface $keycloak
   *   A Keycloak service instance.
   * @param \Drupal\openid_connect\Plugin\OpenIDConnectClientManager $plugin_manager
   *   The OpenID Connect plug-in manager.
   * @param \Drupal\openid_connect\Claims $claims
   *   The OpenID Connect claims.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request_stack
   *   The request stack.
   */
  public function __construct(
    KeycloakServiceInterface $keycloak,
    OpenIDConnectClientManager $plugin_manager,
    Claims $claims,
    RequestStack $request_stack
  ) {
    $this->keycloak = $keycloak;
    $this->pluginManager = $plugin_manager;
    $this->claims = $claims;
    $this->requestStack = $request_stack;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('keycloak.keycloak'),
      $container->get('plugin.manager.openid_connect_client.processor'),
      $container->get('openid_connect.claims'),
      $container->get('request_stack')
    );
  }

  /**
   * Login the user using the Keycloak openid_connect client.
   */
  public function login() {
    openid_connect_save_destination();
    $client_name = 'keycloak';

    $configuration = $this->config('openid_connect.settings.keycloak')
      ->get('settings');
    $client = $this->pluginManager->createInstance(
      $client_name,
      $configuration
    );
    $scopes = $this->claims->getScopes();
    $_SESSION['openid_connect_op'] = 'login';
    $response = $client->authorize($scopes);

    return $response;
  }

}

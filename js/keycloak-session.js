(function ($, Drupal, drupalSettings) {
  'use strict';

  Drupal.behaviors.keycloak = {
    attach: function (context, settings) {

      var sessionIframe = {
        initialized: false,
        enable: drupalSettings.keycloak.enableSessionCheck,
        iframeUrl: drupalSettings.keycloak.sessionCheckIframeUrl,
        interval: isNaN(drupalSettings.keycloak.sessionCheckInterval) ? 2 : Number(drupalSettings.keycloak.sessionCheckInterval),
        logoutUrl: drupalSettings.keycloak.logoutUrl,
        logout: drupalSettings.keycloak.logout,
        clientId: drupalSettings.keycloak.clientId,
        sessionId: drupalSettings.keycloak.sessionId,
        callbackList: []
      };

      function createPromise() {
        var p = {
          setSuccess: function (result) {
            p.success = true;
            p.result = result;
            if (p.successCallback) {
              p.successCallback(result);
            }
          },

          setError: function (result) {
            p.error = true;
            p.result = result;
            if (p.errorCallback) {
              p.errorCallback(result);
            }
          },

          promise: {
            success: function (callback) {
              if (p.success) {
                callback(p.result);
              }
              else if (!p.error) {
                p.successCallback = callback;
              }
              return p.promise;
            },
            error: function (callback) {
              if (p.error) {
                callback(p.result);
              }
              else if (!p.success) {
                p.errorCallback = callback;
              }
              return p.promise;
            }
          }
        };
        return p;
      }

      /**
       * Return window location origin.
       *
       * @return {String} Location origin.
       */
      function getOrigin() {
        if (!window.location.origin) {
          return window.location.protocol + '//' + window.location.hostname + (window.location.port ? ':' + window.location.port : '');
        }
        else {
          return window.location.origin;
        }
      }

      /**
       * Initialize session check iframe.
       *
       *@return {promise} Promise.
       */
      function setupSessionCheckIframe() {
        var promise = createPromise();

        if (!sessionIframe.enable) {
          promise.setSuccess();
          return promise.promise;
        }

        if (sessionIframe.iframe) {
          promise.setSuccess();
          return promise.promise;
        }

        var iframe = document.createElement('iframe');
        sessionIframe.iframe = iframe;

        iframe.onload = function () {
          var iframeUrl = sessionIframe.iframeUrl;
          if (iframeUrl.charAt(0) === '/') {
            sessionIframe.iframeOrigin = getOrigin();
          }
          else {
            sessionIframe.iframeOrigin = iframeUrl.substring(0, iframeUrl.indexOf('/', 8));
          }
          promise.setSuccess();

          setTimeout(check, sessionIframe.interval * 1000);
        };

        iframe.setAttribute('src', sessionIframe.iframeUrl);
        iframe.setAttribute('title', 'keycloak-session-iframe');
        iframe.style.display = 'none';
        document.body.appendChild(iframe);

        var messageCallback = function (event) {
          if ((event.origin !== sessionIframe.iframeOrigin) || (sessionIframe.iframe.contentWindow !== event.source)) {
            return;
          }

          if (!(event.data === 'unchanged' || event.data === 'changed' || event.data === 'error')) {
            return;
          }

          if (event.data !== 'unchanged') {
            sessionIframe.logout = true;
          }

          var callbacks = sessionIframe.callbackList.splice(0, sessionIframe.callbackList.length);

          for (var i = callbacks.length - 1; i >= 0; --i) {
            var promise = callbacks[i];
            if (event.data === 'unchanged') {
              promise.setSuccess();
            }
            else {
              promise.setError();
            }
          }
        };

        window.addEventListener('message', messageCallback, false);

        var sessionExpiredCallback = function () {
          // For now, we simply redirect to the logout page.
          // To meeting OpenID Connect specifications, we should first
          // try to refresh the session by triggering a sign on request
          // without prompt.
          window.location.href = sessionIframe.logoutUrl;
        };

        var check = function () {
          checkSessionIframe().error(sessionExpiredCallback);
          if (!sessionIframe.logout) {
            setTimeout(check, sessionIframe.interval * 1000);
          }
        };

        return promise.promise;
      }

      function checkSessionIframe() {
        var promise = createPromise();

        if (sessionIframe.iframe && sessionIframe.iframeOrigin) {
          var msg = sessionIframe.clientId + ' ' + sessionIframe.sessionId;
          sessionIframe.callbackList.push(promise);
          var origin = sessionIframe.iframeOrigin;
          if (sessionIframe.callbackList.length === 1) {
            sessionIframe.iframe.contentWindow.postMessage(msg, origin);
          }
        }
        else {
          promise.setSuccess();
        }

        return promise.promise;
      }

      $(document).once('keycloak').each(function () {
        if (sessionIframe.enable && !sessionIframe.initialized) {
          setupSessionCheckIframe()
            .success(function () {
              sessionIframe.initialized = true;
            })
            .error(function () {
              // console.log('[KEYCLOAK SSO] Error initializing session check iframe.');
            });
        }
      });

    }
  };
})(jQuery, Drupal, drupalSettings);

/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

async function setAppUp(window, givenScope, i18n, lang) {
  // Start the Angular machine.
  var app = window.angular.module('demo', []);

  await i18n.setupAngularService(app, lang);

  // Make the errors appear.
  app.factory('$exceptionHandler', function() {
    return function myExceptionHandler(exception, cause) {
      throw new Error(exception);
    };
  });

  // Remove debug info, nobody cares.
  app.config(function($compileProvider, $sceDelegateProvider) {
    $compileProvider.debugInfoEnabled(false);
  });

  // App functionnality
  app.controller('paramsController', function($window, $scope, i18n) {
    $scope.window = $window;
    $scope.i18n = i18n;
    for (const k of Object.keys(givenScope)) {
      $scope[k] = givenScope[k];
    }
  });

  // A directive to load internationalized templates.
  app.directive('myInclude', ($compile, $sce, i18n) => {
    var recursionCount = 0;

    return {
      restrict: 'A',
      link: (scope, element, attrs) => {
        if (!attrs['myInclude'].match(/\.html$|\.js$|\.json$/)) {
          throw new Error(`Include should only include html, json or js files ಠ_ಠ`);
        }
        recursionCount++;
        if (recursionCount >= 20) {
          // ng-include a template that ng-include a template that...
          throw Error(`That's too recursive ಠ_ಠ`);
        }
        element.html(i18n.template(attrs['myInclude']));
        $compile(element.contents())(scope);
      }
    };
  });

  // And we're ready to bootstrap and render.
  window.angular.bootstrap(window.document, ['demo']);
}

module.exports = setAppUp;

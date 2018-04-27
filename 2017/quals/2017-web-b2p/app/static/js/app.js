// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.




angular.module("b2tp", ['vcRecaptcha'])
.controller("DeloreanCtrl", ['$scope', '$location', '$window', '$http', '$httpParamSerializer', 'vcRecaptchaService', function($scope, $location, $window, $http, $httpParamSerializer, vcRecaptchaService) {
    function getWaybackUrl() {
        return 'https://web.archive.org/web/' + $scope.date_y + $scope.date_m + $scope.date_d + '/' + $scope.website;
    };

    function report() {
        var recaptcha = vcRecaptchaService.getResponse();
        if (!recaptcha) {
            alert('Wrong captcha.')
            return;
        }
        $location.search('reported', 1);
        $http({
            method: 'POST',
            url: '/report',
            data: {
                'reported': $httpParamSerializer($location.search()),
                'recaptcha': recaptcha
            },
        });
        $scope.reported = true;
    }

    function month_name(m) {
        var months = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
        return months[parseInt(m)-1] || 'ERR';
    }

    $scope.reported = false;
    $scope.headless = $window.navigator.userAgent.indexOf('Headless') !== -1;
    $scope.website = 'http://www.google.com/';
    $scope.date_d = '01';
    $scope.date_m = '01';
    $scope.date_y = '2000';

    $scope.getWaybackUrl = getWaybackUrl;
    $scope.report = report;
    $scope.month_name = month_name;


    var q = $location.search();

    if (q['url']) $scope.website = q['url'];
    if (q['d']) $scope.date_d = q['d'];
    if (q['m']) $scope.date_m = q['m'];
    if (q['y']) $scope.date_y = q['y'];
    if (q['reported']) {
        $location.search('reported', null);
        $window.location = getWaybackUrl();
    }

    $scope.date = [$scope.date_d, $scope.date_m, $scope.date_y].join('/');
    $scope.setDate = () => $scope.date = prompt("When do you want to go?", $scope.date) || $scope.date;

    $scope.$watch('date', function(newval, oldval) {
        // NEW
        if (newval == oldval)
            return;
        //

        var parts = newval.split('/');
        if (parts.length == 3) {
            // CHANGED
            if (parts[0].length < 2)
                parts[0] = ('00' + parts[0]).slice(-2);

            if (parts[1].length < 2)
                parts[1] = ('00' + parts[1]).slice(-2);

            if (parts[2].length < 2)
                parts[2] = ('0000' + parts[2]).slice(-4);

            $scope.date_d = parts[0];
            $scope.date_m = parts[1];
            $scope.date_y = parts[2];
        }
        $location.search('d', $scope.date_d);
        $location.search('m', $scope.date_m);
        $location.search('y', $scope.date_y);
    });

    $scope.$watch('website', function(newval, oldval) {
        if (newval) $location.search('url', newval);
    });

}])
.directive('wayback', function() {
    return {
        template: '<iframe class="wayback-iframe" ng-src="{{getWaybackUrl()}}"></iframe>',
    };
})
.config(['$sceDelegateProvider', '$locationProvider', function($sceDelegateProvider, $locationProvider) {
    $sceDelegateProvider.resourceUrlWhitelist(['self', 'https://web.archive.org/**']);
    $locationProvider.html5Mode(true);
}])


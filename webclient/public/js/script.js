'use strict';

    // create the module and name it scotchApp
    	// also include ngRoute for all our routing needs
    var scotchApp = angular.module('scotchApp', ['ngResource', 'ngRoute'])

  .config(function($routeProvider, $locationProvider, $httpProvider) {
    //================================================
    // Check if the user is connected
    //================================================
    var checkLoggedin = function($q, $timeout, $http, $location, $rootScope){
      // Initialize a new promise
      var deferred = $q.defer();

      // Make an AJAX call to check if the user is logged in
      $http.get('/loggedin').success(function(user){
        // Authenticated
        if (user !== '0'){
          console.log("LOGIN");
          /*$timeout(deferred.resolve, 0);*/
          if($location.path() != '/')
            deferred.resolve();
          else{
            deferred.reject();
            $location.url('/info');
          }
        }
        // Not Authenticated
        else if($location.path() != '/'){
          console.log("NO LOGIN");
          //$timeout(function(){deferred.reject();}, 0);
          deferred.reject();
          $location.url('/');
        }
        else 
          deferred.resolve();

      });

      return deferred.promise;
    };
    //================================================
    
    //================================================
    // Add an interceptor for AJAX errors
    //================================================
    $httpProvider.interceptors.push(function($q, $location) {
      return {
        response: function(response) {
          // do something on success
          return response;
        },
        responseError: function(response) {
          if (response.status === 401)
            $location.url('/');
          return $q.reject(response);
        }
      };
    });
    //================================================

    //================================================
    // Define all the routes
    //================================================
    $routeProvider
      .when('/ab', {
        templateUrl: '/views/main.html'
      })
      .when('/info', {
        templateUrl : 'info.html',
        controller: 'infoController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/error',{
        templateUrl : 'error.html',
        controller  : 'errorController'
      })

      .when('/', {
        templateUrl: 'login.html',
        controller: 'loginController',
        resolve: {
          loggedin: checkLoggedin
        }
      })
      .otherwise({
        redirectTo: '/error'

      });
    //================================================

    $locationProvider.html5Mode(true);

  }) // end of config()
  .run(function($rootScope, $http){
    $rootScope.message = '';

    // Logout function is available in any pages
    $rootScope.logout = function(){
      $rootScope.message = 'Logged out.';
      $http.post('/logout');
    };
  });

    // configure our routes
    /*scotchApp.config(function($routeProvider, $locationProvider){
    		$routeProvider

    		.when('/info',{
    			templateUrl : 'info.html',
    			controller  : 'infoController'
    		})

    		.when('/about',{
    			templateUrl : 'about.html',
    			controller  : 'aboutController'
    		})

    		.when('/contact',{
    			templateUrl : 'contact.html',
    			controller  : 'contactController'
    		})

            .when('/error',{
                templateUrl : 'error.html',
                controller  : 'errorController'
            })

    		.when('/',{
                templateUrl : 'login.html',
                controller  : 'loginController'
            })

            .otherwise({
                redirectTo: '/error'
            })

            $locationProvider.html5Mode(true);
    });
*/
    // create the controller and inject Angular's $scope
    scotchApp.controller('infoController', function($scope, $http, $location) {
        $scope.info = {};

        $http.get('/userinfo')
        .success(function(res){
            $scope.info  = res;
            console.log("INFO " + $scope.info.result_table);
        })
    });

    scotchApp.controller('aboutController', function($scope, $http, $location) {
        $scope.bool = "";
        $http.get('/checklogin')
        .success(function(res){
            $scope.bool = res;
            if($scope.bool == true){
                 $scope.message = 'Look! I am an about page';
            }
            else if($scope.bool == false)
                $location.path('/')
        })
    });

    scotchApp.controller('contactController', function($scope, $http, $location) {
        $scope.bool = "";
        $http.get('/checklogin')
        .success(function(res){
            $scope.bool = res;
            if($scope.bool == true){
                $scope.message = 'Contact us! JK. This is just a demo';
            }
            else if($scope.bool == false)
                $location.path('/')
        })
    });

    scotchApp.controller('loginController', function($scope,$http,$location){
        $scope.user = {};
        $scope.login = function(){
        $http.post('/login', {
          username: $scope.user.username,
          password: $scope.user.password,
          type    : $scope.user.type
        })
        .success(function(user){
          // No error: authentication OK
          console.log("SUCCESS");
          $location.path('/info');
        })
        .error(function(){
          // Error: authentication failed
          console.log("ERROR");
          $location.path('/');
        });
      };
/*        $scope.user = {};
        $scope.bool = "";
        
        $http.get('/checklogin')
        .success(function(res){
            $scope.bool = res;
            if($scope.bool == true){
                 $location.path('/info')
            }
            else if($scope.bool == false){
                $scope.login = function(){
                $http.post('/login', {
                  username: $scope.user.username,
                  password: $scope.user.password,
                  type    : $scope.user.type
                })
                .success(function(res){
                  //$location.path('/info')
                })
              };
            }
        })*/
    });

    scotchApp.controller('errorController', function($scope) {
        $scope.message = "Error Don't have this page";
    });

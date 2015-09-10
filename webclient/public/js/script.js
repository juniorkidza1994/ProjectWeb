// script.js

    // create the module and name it scotchApp
    	// also include ngRoute for all our routing needs
    var scotchApp = angular.module('scotchApp', ['ngRoute']);

    // configure our routes
    scotchApp.config(function($routeProvider, $locationProvider){
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

    // create the controller and inject Angular's $scope
    scotchApp.controller('infoController', function($scope, $http, $location) {
        $scope.bool = "";
        $scope.info = {};

        $http.get('/checklogin')
        .success(function(res){
            $scope.bool = res;
            if($scope.bool == true){
                 $http.get('/userinfo')
                 .success(function(res){
                    $scope.info  = res;
                    console.log("INFO " + $scope.info.result_table);
                 })
            }
            else if($scope.bool == false)
                $location.path('/')
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
        })
    });

    scotchApp.controller('errorController', function($scope) {
        $scope.message = "Error Don't have this page";
    });

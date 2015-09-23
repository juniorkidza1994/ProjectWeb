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

      .when('/downloadSelfPHR', {
        templateUrl : 'downloadSelfPHR.html',
        controller: 'downloadController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/accessPermissionManagement', {
        templateUrl : 'accessPermisManage.html',
        controller: 'accessPermisController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/deleteSelfPHR', {
        templateUrl : 'deleteSelfPHR.html',
        controller: 'deleteController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/changepwd', {
        templateUrl : 'changepassword.html',
        controller: 'changePwdController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/assignPermission', {
        templateUrl : 'assignAccessPermission.html',
        controller: 'assignAccessPermissionController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/changeEmail', {
        templateUrl : 'changeEmail.html',
        controller: 'changeEmailController',
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

    // create the controller and inject Angular's $scope
    scotchApp.controller('infoController', function($scope, $http, $location) {
        $scope.info = {};

        $http.get('/userinfo')
        .success(function(res){
            $scope.info  = res;
            console.log("INFO " + $scope.info.attribute_list);
        })
    });

    scotchApp.controller('changePwdController', function($scope, $http, $location) {
        $scope.password = {};
        $scope.password.flag = false;

        $scope.submit = function(){
            $http.post('/changepwd', {
              current_passwd        : $scope.password.curr_passwd,
              new_passwd            : $scope.password.new_passwd,
              confirm_new_passwd    : $scope.password.confirm_passwd,
              send_new_passwd_flag  : $scope.password.flag
            })
            .success(function(user){
              // No error: authentication OK
              console.log("SUCCESS");
              $location.path('/info');
            })
        };

        $scope.cancle = function(){
          $location.path('/info');
        }
    });

    scotchApp.controller('changeEmailController', function($scope, $http, $location) {
        $scope.data = {};
        $scope.info = {};

        $http.get('/userinfo')
        .success(function(res){
            $scope.info  = res;
            $scope.data.email = $scope.info.email_address;
        })

        $scope.submit = function(){
            $http.post('/change_email', {
              email                  : $scope.data.email,
              confirm_new_passwd     : $scope.data.password,
            })
            .success(function(user){
              // No error: authentication OK
              console.log("SUCCESS");
              $location.path('/info');
            })
        };

        $scope.cancle = function(){
          $location.path('/info');
        }
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


    scotchApp.controller('accessPermisController', function($scope, $http, $location) {
        $scope.access_permission_list = {};
        $scope.selectedRow = null;
        $scope.checked = {};

        $http.post('/access_permission_management_list')
        .success(function(res){
            $scope.access_permission_list = res;
            console.log(res);
        })     

        $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
        }

        $scope.assign = function(){
          $location.path('/assignPermission');
        }

        $scope.edit = function(){
          console.log($scope.selectedRow);
          if($scope.selectedRow != null ){
            console.log("EDIT " + $scope.access_permission_list[$scope.selectedRow]);
            $http.post('/edit_access_permission', {
              row             : $scope.selectedRow,
              uploadflag      : $scope.access_permission_list[$scope.selectedRow][1],
              downloadflag    : $scope.access_permission_list[$scope.selectedRow][2],
              deleteflag      : $scope.access_permission_list[$scope.selectedRow][3]
            })
            .success(function(res){
              if(res == true){
                console.log("EDIT SUCCESS");
                $location.path('/accessPermissionManagement');
              }
            })
          }
        }

        $scope.delete = function(){
          console.log($scope.selectedRow);
          if($scope.selectedRow != null ){
            console.log("Delete " + $scope.access_permission_list[$scope.selectedRow]);
            $http.post('/delete_access_permission', {
              delete_user      : $scope.access_permission_list[$scope.selectedRow][0],
            })
            .success(function(res){
              if(res == true){
                console.log("Delete SUCCESS");
                 $http.post('/access_permission_management_list')
                 .success(function(res){
                     $scope.access_permission_list = res;
                     console.log(res);
                 })   
                $location.path('/accessPermissionManagement');
              }
            })
          }
        }
    });

    scotchApp.controller('assignAccessPermissionController', function($scope, $http, $location) {
        $scope.authorityList = {};
        $scope.assign = {};
        $scope.assign.uploadflag = false;
        $scope.assign.downloadflag = false;
        $scope.assign.deleteflag = false;

        $http.post('/authority_name_list')
        .success(function(res){
            $scope.authorityList = res;
        })

      //  $scope.selectedAuthority = $scope.authorityList[0];

        $scope.submit = function(index){
          if($scope.assign.uploadflag || $scope.assign.downloadflag || $scope.assign.deleteflag){
            console.log("SUCCESS");
            $http.post('/assign_access_permission', {
                authority : $scope.selectedAuthority,
                username : $scope.assign.username,
                uploadflag : $scope.assign.uploadflag,
                downloadflag : $scope.assign.downloadflag,
                deleteflag : $scope.assign.deleteflag,
            })
            .success(function(res){
              if(res == true){
                console.log("Assign SUCCESS");
                $location.path('/accessPermissionManagement');
              }
            })
          }
          else
            console.log("FAIL");
        }

         $scope.check = function(){
           return ($scope.assign.uploadflag || $scope.assign.downloadflag || $scope.assign.deleteflag);
         }
    });

    scotchApp.controller('downloadController', function($scope, $http, $location) {
        $scope.phr_list = {};
        $scope.selectedRow = null;

        $http.post('/download_self_phr_list')
        .success(function(res){
            $scope.phr_list = res;
            console.log(res);
        })

        $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
        }

        $scope.download = function(){
          $http.post('/downloadPHR', {
            index: $scope.selectedRow
         })
        }
    });

    scotchApp.controller('deleteController', function($scope, $http, $location) {
        $scope.phr_list = {};
        $scope.selectedRow = null;

        $http.post('/delete_self_phr_list')
        .success(function(res){
            $scope.phr_list = res;
            console.log("DELETE LIST : " + res);
        })

        $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
        }

        $scope.download = function(){
          $http.post('/deletePHR', {
            index: $scope.selectedRow
         })
        }
    });

    scotchApp.controller('loginController', function($scope,$http,$location){
        $scope.user = {};
        $scope.check = 0;

        $scope.login = function(){
          if($scope.check == 0){
            console.log("GO LOGIN");
            $scope.check = 1;
            $http.post('/login', {
              username: $scope.user.username,
              password: $scope.user.password,
              type    : $scope.user.type
            })
            .success(function(user){
              // No error: authentication OK
              console.log("SUCCESS");
              console.log(user);
              $location.path('/info');
            })
            .error(function(){
              // Error: authentication failed
              console.log("ERROR");
              $location.path('/');
            });
          }
          else{
            console.log("WAIT LOGIN");
          }
      };
    });

    scotchApp.controller('errorController', function($scope) {
        $scope.message = "Error Don't have this page";
    });

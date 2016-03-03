'use strict';

    // create the module and name it phrApp
      // also include ngRoute for all our routing needs

    var myClass;

    var isLoggin;

    var userType;

    var phrApp = angular.module('phrApp', ['ngResource', 'ngRoute', 'ngFileUpload', 'ui.tree', 'ngAnimate', 'ui.bootstrap', 'treeGrid'])

  .config(function($routeProvider, $locationProvider, $httpProvider) {
    //================================================
    // Check if the user is connected
    //================================================

    var interceptor = ['$rootScope', '$q', "Base64", function (scope, $q, Base64) {
        function success(response) {
            return response;
        }
        function error(response) {
            var status = response.status;
            if (status == 401) {
                //AuthFactory.clearUser();
                //window.location = "/account/login?redirectUrl=" + Base64.encode(document.URL);
                console.log("EIEI");

                return;
            }
            // otherwise
            return $q.reject(response);
        }
        return function (promise) {
            return promise.then(success, error);
        }
    }];

    var checkLoggedin = function($q, $timeout, $http, $location, $rootScope){
      // Initialize a new promise
      var deferred = $q.defer();

      // Make an AJAX call to check if the user is logged in
      $http.get('/api/loggedin').success(function(user){
        // Authenticated
        if (user !== '0'){
          /*$timeout(deferred.resolve, 0);*/
          if($location.path() != '/'){
            deferred.resolve();
            if(user.type == "User" && ($location.path().indexOf("/admin") > -1 ))
              $location.url('/user/info');
            else if(user.type == "Admin" && ($location.path().indexOf("/user/") > -1 ))
              $location.url('/admin/info');      
          }
          else if($location.path() == '/' && $location.path() == '/forgetpwd'){
            deferred.reject();
            if(user.type == "User")
              $location.url('/user/info');
            else if(user.type == "Admin")
              $location.url('/admin/info')
          }
          else {
            deferred.reject();
            if(user.type == "User")
              $location.url('/user/info');
            else if(user.type == "Admin")
              $location.url('/admin/info')
          }
        }
        // Not Authenticated
        else if($location.path() == '/' || $location.path() == '/forgetpwd'){
          console.log("NO LOGIN");
        //  $timeout(function(){deferred.reject();}, 0);
          deferred.resolve();
        }
        else {
          deferred.reject();
          $location.url('/');
        }
          

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
          if (response.status === 401){
            //console.log("ERRRRRRRR");
            $location.path('/');
          }
          return $q.reject(response);
        }
      };
    });
    //================================================

    //================================================
    // Define all the routes
    //================================================
    $routeProvider

      .when('/admin/info', {
        templateUrl : 'adminInfo.html',
        controller: 'admininfoController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/admin/changeconfig', {
        templateUrl : 'changeConfig.html',
        controller: 'changeConfigController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/admin/changemailserver', {
        templateUrl : 'changeMailServer.html',
        controller: 'changeMailServerController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/admin/attribute', {
        templateUrl : 'attributeManagement.html',
        controller: 'attributeController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/admin/registerattribute', {
        templateUrl : 'registerAttribute.html',
        controller: 'registerAttributeController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/admin/transaction', {
        templateUrl: 'adminTransaction.html',
        controller: 'admintransactionController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/admin/adminmanagement', {
        templateUrl : 'adminManagement.html',
        controller: 'adminManagementController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/admin/registeradmin', {
        templateUrl : 'registerAdmin.html',
        controller: 'registerAdminController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/admin/editadmin', {
        templateUrl : 'editAdmin.html',
        controller: 'editAdminController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/admin/authoritymanagement', {
        templateUrl : 'authorityManagement.html',
        controller: 'authorityManagementController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/admin/registerauthority', {
        templateUrl : 'registerAuthority.html',
        controller: 'registerAuthorityController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/admin/editauthority', {
        templateUrl : 'editAuthority.html',
        controller: 'editAuthorityController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/admin/usermanagement', {
        templateUrl : 'userManagement.html',
        controller: 'userManagementController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/admin/registeruser', {
        templateUrl : 'registerUser.html',
        controller: 'registerUserController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

     .when('/admin/edituser', {
        templateUrl : 'editUser.html',
        controller: 'editUserController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

     .when('/admin/editattribute', {
        templateUrl : 'editAttribute.html',
        controller: 'editAttributeController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

    //-------------------------- USER -----------------------------------------
      .when('/user/info', {
        templateUrl : 'info.html',
        controller: 'userinfoController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/user/downloadPHR', {
        templateUrl : 'downloadPHR.html',
        controller: 'downloadController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/user/accessPermissionManagement', {
        templateUrl : 'accessPermisManage.html',
        controller: 'accessPermisController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/user/deletePHR', {
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

      .when('/user/assignPermission', {
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

      .when('/user/uploadPHR', {
        templateUrl : 'uploadPHR.html',
        controller: 'uploadPHRController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/user/trustedUsers', {
        templateUrl : 'yourTrustedUsers.html',
        controller: 'trustedUsersController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/user/delegate', {
        templateUrl : 'delegate.html',
        controller: 'delegateController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/user/restricted', {
        templateUrl: 'restricted.html',
        controller: 'restrictedController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/user/transaction', {
        templateUrl: 'transaction.html',
        controller: 'transactionController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      // ---------------- LOGIN --------------------
      .when('/', {
        templateUrl: 'login.html',
        controller: 'loginController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/forgetpwd', {
        templateUrl: 'forgetpwd.html',
        controller: 'forgetPasswordController',
        resolve: {
          loggedin: checkLoggedin
        }
      })

      .when('/error',{
        templateUrl : 'error.html',
        controller  : 'errorController'
      })


      .otherwise({
        redirectTo: '/error'
      });
    //================================================

 //   $locationProvider.html5Mode(true);

  }) // end of config()
  .run(function($rootScope, $http){
    $rootScope.message = '';

    // Logout function is available in any pages
    $rootScope.logout = function(){
      $rootScope.message = 'Logged out.';
      // $http.get('/api/logout');
    };
  });

    // create the controller and inject Angular's $scope
    phrApp.controller('indexController', function($scope, $http, $location) {
      $scope.isLoggin = false;

      console.log("ISLOGGIN : " + $scope.isLoggin);

      $http.get('/api/loggedin').success(function(user){
        console.log(user.type);
        // Authenticated
        if (user !== '0'){
          $scope.isLoggin = true;
          $scope.usertype = user.type;
          console.log($scope.usertype);
        }
        // Not Authenticated
        else
          $scope.isLoggin = false;
      });

      $scope.logout = function(){
        $http.get('/api/logout').success(function(user){
          console.log(user.type);
          // Authenticated
          if (user !== '0'){
            $scope.isLoggin = true;
            $scope.usertype = user.type;
            console.log($scope.usertype);
          }
          // Not Authenticated
          else
            $scope.isLoggin = false;
        });
      }
    });

    // create the controller and inject Angular's $scope
    phrApp.controller('userinfoController', function($scope, $http, $location) {
        $scope.info = {};

        // get userinfo
        $http.get('/api/userinfo')
        .success(function(res){
            $scope.info  = res;
            //console.log("INFO " + $scope.info.attribute_list);
        })
    });

    phrApp.controller('delegateController', function($scope, $http, $location) {
        $scope.delegate = {};

        // get userinfo
        $http.post('/api/delegate_table')
        .success(function(res){
            $scope.delegate = res;
            //console.log($scope.attribute_all);
        })

        // click row
        $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
        }

        $scope.clickedSomewhereElse = function(){
        //  console.log("HIT !!")
          $scope.selectedRow = null;
        };
    });

    phrApp.controller('restrictedController', function($scope, $http, $location) {
        $scope.restricted = {};
        $scope.info = {};
        $scope.isShowCancel = false;
        $scope.isShowApprove = false;
        $scope.selectedRow = -1;

        // get table
        $http.post('/api/restricted_table')
        .success(function(res){
            $scope.restricted = res;
            //console.log($scope.attribute_all);
        })

        $http.get('/api/userinfo')
        .success(function(res){
            $scope.info  = res;
            //console.log("INFO " + $scope.info.attribute_list);
        })

        // click row
        $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
            var full_name = $scope.info.authorityName +'.' + $scope.info.username ;
            //console.log(full_name);
            if(full_name == $scope.restricted[index][1]){
              console.log("Equal");
              $scope.isShowCancel = true;
            }
            else {
              $scope.isShowApprove = true;
            }
        }

        var isClickApprove = false;

        $scope.approve = function(){
          if($scope.selectedRow == -1){
            alert("No any row selected");
          }
          else {
            if(!isClickApprove){
              console.log("APPROVE");
              isClickApprove = true;
              var full_emergency_staff_name = $scope.restricted[$scope.selectedRow][0];
              var full_phr_ownername = $scope.restricted[$scope.selectedRow][1];
              $http.post('/api/approve_restricted', {
                  full_emergency_staff_name : $scope.restricted[$scope.selectedRow][0],
                  full_phr_ownername        : $scope.restricted[$scope.selectedRow][1],
                  phr_description           : $scope.restricted[$scope.selectedRow][2],
                  phr_id                    : parseInt($scope.restricted[$scope.selectedRow][5],10),
                  emergency_unit_name       : full_emergency_staff_name.substring(0, full_emergency_staff_name.indexOf(".")),
                  emergency_staff_name      : full_emergency_staff_name.substring(full_emergency_staff_name.indexOf(".") + 1),

                  phr_owner_authority_name  : full_phr_ownername.substring(0, full_phr_ownername.indexOf(".")),
                  phr_ownername             : full_phr_ownername.substring(full_phr_ownername.indexOf(".") + 1)
              })
              .success(function(res){
                // No error: authentication OK
                //console.log("SUCCESS");
                isClickApprove = false;
                $scope.isShowCancel = false;
                $scope.isShowApprove = false;
                alert(res[1]);
                if(res[0]){
                  $http.post('/api/restricted_table')
                  .success(function(res){
                      $scope.restricted = res;
                      $location.path('user/restricted');
                  })
                }
              })
            }
          }
        }

        $scope.clickedSomewhereElse = function(){
        //  console.log("HIT !!")
          $scope.selectedRow = null;
          $scope.isShowCancel = false;
          $scope.isShowApprove = false;
        };
    });

    phrApp.controller('transactionController', function($scope, $http, $location, $filter) {
      $scope.Date = [];
      $scope.Date.startDate = new Date();
      $scope.Date.startTime = new Date(1970, 0, 1, 0, 0, 0);
      $scope.Date.endDate = new Date();
      $scope.Date.endTime = new Date(1970, 0, 1, 0, 0, 0);  
      $scope.transaction_log_type = "";
      $scope.allFlag = false;
      $scope.logs = {};
      $scope.bigTotalItems = 1;
      $scope.bigCurrentPage = 1;
      $scope.limit = $scope.bigCurrentPage * 10;
      $scope.begin = ($scope.bigCurrentPage - 1) * 10;
      $scope.maxSize= 5;

      var monthNames = ["January", "February", "March", "April", "May", "June",
      "July", "August", "September", "October", "November", "December"];

      var isClick = false;

      $scope.search = function(){
        console.log("CLICK SEARCH");
        if(!isClick){

          isClick = true;
          
          if(!$scope.allFlag){
            // $scope.sDate.d =  $filter('date')($scope.startDate, 'd');
            // $scope.sDate.m =  $scope.startDate.getMonth();
            // $scope.sDate.y =  $filter('date')($scope.startDate, 'yyyy');

            // if($scope.Date.startDate == null || $scope.Date.startTime == null ||
            //    $scope.Date.endDate == null || $scope.Date.endTime == null ){
            //     alert("Invalid input !!");
            //     isClick =false;
            // }
            // else {
              $http.post('/api/transaction_auditing', {
                transaction_log_type  : $scope.transaction_log_type, 
                start_year_index      : $scope.Date.startDate.getFullYear(), 
                start_month_index     : $scope.Date.startDate.getMonth(), 
                start_day_index       : $scope.Date.startDate.getDate()-1, 
                start_hour_index      : $scope.Date.startTime.getHours(), 
                start_minute_index    : $scope.Date.startTime.getMinutes(), 
                end_year_index        : $scope.Date.endDate.getFullYear(), 
                end_month_index       : $scope.Date.endDate.getMonth(), 
                end_day_index         : $scope.Date.endDate.getDate()-1, 
                end_hour_index        : $scope.Date.endTime.getHours(), 
                end_minute_index      : $scope.Date.endTime.getMinutes() 
              })
              .success(function(res){
                // No error: authentication OK
                //console.log("SUCCESS");
                isClick = false;

                if(angular.isArray(res)){
                  $scope.logs = res;
                  $scope.bigTotalItems = $scope.logs.length;
                  console.log($scope.bigTotalItems);
                  $scope.chooseTable = $scope.transaction_log_type;
                  $location.path('/user/transaction');
                }
                else {
                  alert(res);
                  $scope.logs = {};
                }
              })
            }
          else {

            console.log("SSSSSS");
            $http.post('/api/transaction_auditing', {
              allFlag               : $scope.allFlag,
              transaction_log_type  : $scope.transaction_log_type
            })
            .success(function(res){
              // No error: authentication OK
              //console.log("SUCCESS");
              // $scope.logs = res;
              // $scope.bigTotalItems = $scope.logs.length;
              // console.log($scope.bigTotalItems);
              // isClick = false;
              // $location.path('/user/transaction');

              isClick = false;

              if(angular.isArray(res)){
                $scope.logs = res;
                $scope.bigTotalItems = $scope.logs.length;
                console.log($scope.bigTotalItems);
                $scope.chooseTable = $scope.transaction_log_type;
                $location.path('/user/transaction');
              }
              else {
                alert(res);
                $scope.logs = {};
              }
            })
          }
          // console.log("Start date: " + $scope.startDate);
          // console.log("Start date filter: " );
          // console.log($scope.sDate);
          // console.log("Start Time: " + $scope.startTime);
          // console.log("End date: " + $scope.endDate);
          // console.log("End Time: " + $scope.endTime);
          // console.log("Choice: " + $scope.transaction_type);
        }
      };
      //}

    });

    phrApp.controller('trustedUsersController', function($scope, $http, $location) {
        $scope.trustedUsers = {};
        $scope.authorityList = {};
        $scope.username = "";
        $scope.selectedAuthority = -1;
        $scope.selectedRow = -1;

        // get userinfo
        $http.post('/api/trusted_users_table')
        .success(function(res){
            $scope.trustedUsers = res;
            //console.log($scope.attribute_all);
        })

        // click row
        $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
        }

        $scope.clickedSomewhereElse = function(){
        //  console.log("HIT !!")
          $scope.selectedRow = -1;
        };

        $http.post('/api/authority_name_list')
        .success(function(res){
            $scope.authorityList = res;
        })


        var isClick = false;

        $scope.addUser = function(){
          console.log("ADD USER");
          if(!isClick){
            isClick = true;
            $http.post('/api/add_trusted_user', {
              username        : $scope.username,
              index           : parseInt($scope.selectedAuthority),
            })
            .success(function(res){
              // No error: authentication OK
              //console.log("SUCCESS");
              isClick = false;
              alert(res[1]);
              if(res[0]){
                $http.post('/api/trusted_users_table')
                .success(function(res){
                    $scope.trustedUsers = res;
                    $location.path('/user/trustedUsers');
                    //console.log($scope.attribute_all);
                })
              }
            })
          }
        };

        $scope.remove = function(){
          alert("No function");
        }
    });

    phrApp.controller('changePwdController', function($scope, $http, $location) {
        $scope.password = {};
        $scope.password.flag = false;
        var isClick = false;
        $scope.password.curr_passwd = "";
        $scope.password.new_passwd = "";
        $scope.password.confirm_passwd = "";

        $scope.submit = function(){
          if(!isClick){
            isClick = true;

            if($scope.password.curr_passwd == null){
              $scope.password.curr_passwd = "";
            }
            if($scope.password.new_passwd == null){
              $scope.password.new_passwd = "";
            }
            if($scope.password.confirm_passwd == null){
              $scope.password.confirm_passwd = "";
            }

            $http.post('/api/changepwd', {
              current_passwd        : $scope.password.curr_passwd,
              new_passwd            : $scope.password.new_passwd,
              confirm_new_passwd    : $scope.password.confirm_passwd,
              send_new_passwd_flag  : $scope.password.flag
            })
            .success(function(res){
              // No error: authentication OK
              //console.log("SUCCESS");
              isClick = false;
              console.log(res);

              if(res[0]){
                alert(res[1]);
                $location.path('/');
              }
              else {
                $scope.password.curr_passwd = "";
                $scope.password.new_passwd = "";
                $scope.password.confirm_passwd = "";
                alert(res[1]);
              }
            })
          }
        };

        $scope.back = function(){
          $location.path('/info');
        }
    });

    phrApp.controller('uploadPHRController', ['$scope', 'Upload' , '$http' , '$location' , '$uibModal' ,function ($scope, Upload, $http, $location, $uibModal) {
        $scope.authorityList = {};
        $scope.attribute_all = {};
        $scope.id_node = 1;
        $scope.userinfo = {} ;
        $scope.description = "";
        $scope.con_level = "";
        $scope.threshold = 0;
        $scope.trusted_users = 0;
        $scope.tree_string = "";
        $scope.parent = ""; 
        $scope.canUpload = false;
        $scope.search_selectedAuthority = "";
        $scope.search_username  = "";
        $scope.trustedUsersTable = {};
        $scope.isSearch = false;
        $scope.tree = [];

        // Cancle upload
        $http.post('/api/cancelUploadPHR')

        // get authority_name_list
        $http.post('/api/authority_name_list')
        .success(function(res){
            $scope.authorityList = res;
        })

        // get table
        $http.post('/api/trusted_users_table')
        .success(function(res){
            $scope.trustedUsersTable = res;
        })

        // get userinfo
        $http.get('/api/userinfo')
        .success(function(res){
            $scope.userinfo = res;
        })

        // get attribute list
        $http.post('/api/attribute_table')
        .success(function(res){
            $scope.attribute_all = res;
            //console.log($scope.attribute_all);
        })

        $scope.isClick = false;

        // upload later on form submit or something similar
        $scope.submit = function() {
          if(!$scope.isClick){

            $scope.isClick = true;

          // call dfs function
            $scope.dfs($scope.tree);

           // console.log("TREE STRING" + $scope.tree_string);

           //console.log($scope.file);
           //console.log($scope.form.file);

           console.log($scope.tree.length);

          if(!$scope.file){
            alert("Choose 1 file");
            $scope.isClick =  false;
          }
          else if($scope.description == "" || $scope.description == null){
            alert("Please input description");
            $scope.isClick =  false;
          }
          else if($scope.con_level == ""){
            alert("Please select confidentiality level");
            $scope.isClick =  false;
          }
          else if($scope.con_level == "Restricted level" && ($scope.threshold <= 0 || $scope.threshold > $scope.trusted_users)){
            alert("The threshold value must be between 1 and " + $scope.trusted_users + "(No. of trusted users)" );
            $scope.isClick =  false;
          }
          else if($scope.tree.length == 0){
            alert("Please specify access policy");
            $scope.isClick =  false;
          }
          else {
            $scope.upload($scope.file);
            $scope.tree_string = "";
          }
          // if(!$scope.form.file.$valid || $scope.file  !$scope.file.$error){
          //   alert("Choose 1 files");
          // }
          // if(!($scope.tree.length != 0 &&  $scope.description != "" && $scope.con_level != "") && 
          //     !($scope.con_level == "Restricted level" && $scope.threshold > 0 && $scope.trusted_users > 0)){
          //       console.log("WRONG TREE");
          //       $scope.isClick = false;
          // }

            // vaildation file & form
            // else if ($scope.form.file.$valid && $scope.file && !$scope.file.$error) {

            //   // add owner user to tree
            //   $scope.tree_string += " or (UsernameNode__SUB__" + $scope.userinfo.authorityName + "__SUB__" + $scope.userinfo.username + ')';
            //   console.log("UPLOAD");
            //   console.log($scope.file);
            //   $scope.upload($scope.file);
            //   $scope.tree_string = "";
            // }
            // else {
               //console.log($scope.form.file.$valid);
            // }
          }
        };

      // covert tree to string
      $scope.dfs = function (node) {
        if(node){
          angular.forEach(node, function(value,key){
      //      console.log("KEY : " + key );
      //     console.log("Value : " + value['name'] );
            if($scope.parent == ""){
                $scope.parent = "(";
       //         console.log($scope.parent);
            }

            var temp_name = value['name'];

      //      console.log("TEMP NAME BEFORE : " + temp_name);

            var temp_type = "";

            if(value['type'] == "Username"){
                  temp_type = "UsernameNode__SUB__";
            }      
            else if(value['type'] == "Attribute"){
                  temp_type = "AttributeNode__SUB__";
            }

            temp_name = temp_type  + temp_name.replace(".","__SUB__");

      //      console.log("TEMP NAME AFTER : " + temp_name);

            // REPLACE STRING 
            if(value['nodes'].length != 0){

          //    console.log(value['nodes']);     
              $scope.parent += temp_name + " and "; 
         //     console.log($scope.parent);
              $scope.dfs(value['nodes']);
              var lastIndex = $scope.parent.lastIndexOf(temp_name);
              $scope.parent = $scope.parent.substring(0,lastIndex);
            }
            else {
              // REPLACE STRING

              if($scope.tree_string != "")
                $scope.tree_string += " or ";
              $scope.tree_string +=  $scope.parent + temp_name + ")";
            //  console.log($scope.tree_string);
            }
            
          });        
        }
      };

      var isClickSearch = false;

      

      // verify user permission
      $scope.search = function(){
          if(!isClickSearch){
            $scope.trusted_users = $scope.trustedUsersTable.length;
            console.log("No trusted Users : " + $scope.trusted_users)

            console.log("SEARCH UPLOAD");
            console.log("SEARCH USERNAME : " + $scope.search_username);
            console.log("SEARCH Authority : " + $scope.search_selectedAuthority);
            isClickSearch =true;

            $http.post('/api/verify_upload_permission_main',{
                authorityName :  $scope.search_selectedAuthority,
                username      :  $scope.search_username
            })
            .success(function(res){
                isClickSearch = false;
                // show form upload
                $scope.canUpload = res[0];
                if(!res[0]){
                  $scope.search_selectedAuthority = "";
                  $scope.search_username  = "";
                  alert(res[1]);
                }
               // $location.path('/uploadPHR');
            })
            .error(function(err){
              isClickSearch = false;
              $scope.search_selectedAuthority = "";
              $scope.search_username  = "";
            })
          }
      }
  
      $scope.progressBar = 0;
      var m_upload;
      // Can't change page
      $scope.$on('$locationChangeStart', function(event) {
        console.log("IS CLICK : "  + $scope.isClick);

          // check when upload isn't complete
          if ($scope.isClick) {
             var r = confirm("Are you sure to leave this page ?");
             if(r == true) {
                // Cancle upload
                $scope.file.upload.abort();
                $http.post('/api/cancelUploadPHR')
             }
          }
      });

      var re_value = function(){
                        // RE VALUE
                $scope.max = 0;
                $scope.dynamic = 0;
                $scope.authorityList = {};
                $scope.attribute_all = {};
                $scope.id_node = 1;
                $scope.userinfo = {} ;
                $scope.description = "";
                $scope.con_level = "";
                $scope.threshold = 0;
                $scope.trusted_users = 0;
                $scope.tree_string = "";
                $scope.parent = ""; 
                $scope.canUpload = false;
                $scope.search_selectedAuthority = "";
                $scope.search_username  = "";
                 $scope.progressBar = 0;
                 $scope.tree = [];

                 // get authority_name_list
        $http.post('/api/authority_name_list')
        .success(function(res){
            $scope.authorityList = res;
        })

        // get table
        $http.post('/api/trusted_users_table')
        .success(function(res){
            $scope.trustedUsersTable = res;
        })

        // get userinfo
        $http.get('/api/userinfo')
        .success(function(res){
            $scope.userinfo = res;
        })

        // get attribute list
        $http.post('/api/attribute_table')
        .success(function(res){
            $scope.attribute_all = res;
            //console.log($scope.attribute_all);
        })
      }

      $scope.cancel = function(){
        var r = confirm("Are you sure to cancel Upload Files ?");
             if(r == true) {
                // Cancle upload
                $scope.isClick = false;
                re_value();
                $scope.file.upload.abort();
                $http.post('/api/cancelUploadPHR')
            }
      };

      // upload on file select or drop
      $scope.upload = function (file) {
        var isSuccess = false;
        var msg = "";
        file.upload =  Upload.upload({
                url: 'api/uploadPHR',
                data: {'phr_owner_name': $scope.search_username, file: file, 'phr_owner_authority_name': $scope.search_selectedAuthority, 
                'data_description': $scope.description,
                'confidentiality_level': $scope.con_level, 'access_policy': $scope.tree_string,
                'threshold' : $scope.threshold, 'truted_users': $scope.trusted_users
              }

            })
        file.upload.then(function (resp) {
                console.log('Success ' + resp.config.data.file.name + 'uploaded. Response: ' + resp.data);
                console.log(resp);
                isSuccess = resp.data[0];
                msg       = resp.data[1];
            }, function (resp) {
                console.log('Error status: ' + resp.status);
                $scope.file.upload.abort();
                isSuccess = false;
                msg = "Cancle upload";
                re_value();
            }, function (evt) {
                var progressPercentage = parseInt(100.0 * evt.loaded / evt.total);
                $scope.progressBar = progressPercentage;
                console.log('progress: ' + progressPercentage + '% ' + evt.config.data.file.name);
            })
            .finally(function(){
              alert(msg);
              re_value();
              $scope.file = null;
              $location.path('/user/uploadPHR')
              // if(isSuccess){
              //   alert("UPLOAD SUCCESS !!");

              //   // $scope.canUpload = false;
              //   // $scope.search_username = "";
              //   // $scope.search_selectedAuthority = "";

              //   // RE VALUE
              //   re_value();

              //   $location.path('/user/info');
              // }
              // else {
              //   alert("UPLOAD FAILED !!");
              //   $location.path('/user/info');
              // }
              $scope.isClick = false;
            });
            
            console.log(file);
            
        };

        // CLICK ROW
        $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
            //console.log($scope.selectedRow);
        }

        // CLICK NODE
        $scope.setClickedNode = function(node){
            $scope.selectedNode = node;
            $scope.selectedNode_ID = node.$modelValue.id;
            //console.log($scope.selectedNode);
        }

        // Click somewhere
        $scope.clickedSomewhereElse = function(){
        //  console.log("HIT !!")
          $scope.selectedNode = null;
          $scope.selectedRow = null;
          $scope.selectedNode_ID = null;
        };

        // TEST ui tree
      $scope.remove = function (scope) {
        scope.remove();
      };

      $scope.toggle = function (scope) {
        scope.toggle();
      };

      $scope.moveLastToTheBeginning = function () {
        var a = $scope.data.pop();
        $scope.data.splice(0, 0, a);
      };

      
      $scope.selectedAuthority = null;
      $scope.username = null;

      // ADD USERNAME TO TREE
      $scope.addUserToTree = function(){
        if($scope.selectedAuthority != null && $scope.username != null){
          $http.post('/api/check_user_exist', {
            authority_name      : $scope.selectedAuthority,
            username            : $scope.username
          })
          .success(function(result){
            if(result){
              $scope.addToNode("Username", $scope.selectedAuthority +  "." + $scope.username);
            }
            else {
              //console.log("NOT HAVE USER");
            }
          })
        }
      }

      // ADD ATTRIBUTE TO TREE
      $scope.addAttribToTree = function(){
        if($scope.selectedRow != null ){
          var selectedRow = $scope.selectedRow;
          console.log($scope.attribute_all[$scope.selectedRow][1]);
          if($scope.attribute_all[$scope.selectedRow][1] == "true"){
            console.log("Numeric");
            var modalInstance = $uibModal.open({
              animation: $scope.animationsEnabled,
              templateUrl: 'numericAttrib.html',
              controller: 'numericController'
            });

            modalInstance.result.then(function (selectedItem) {
              $scope.value_numeric = selectedItem;
              $scope.addToNode("Attribute", $scope.attribute_all[selectedRow][0] + " " + $scope.value_numeric.operation + " " + 
                $scope.value_numeric.value);
            }
            );

          }
          else {
            $scope.addToNode("Attribute", $scope.attribute_all[$scope.selectedRow][0]);
          }
        }
        else {
          alert("Choose 1 attribute");
        }
      }

      // ADD TO TREE
      $scope.addToNode = function (type, scope) {
        console.log($scope.tree);
          var title = "";

          if(type == "Username"){
              title = "User";
          }
          else if(type = "Attribute"){
              title = "Attribute";
          }

          if($scope.selectedNode != null){

            //console.log("ADD SUB NODE");
            var nodeData = $scope.selectedNode.$modelValue;
            // if(type == "Username"){
            //   title = "User";
            // }
            // else if(type = "Attribute"){
            //   title = "Attribute";
            // }
            // else

            nodeData.nodes.push({
              id : nodeData.id * 10 + nodeData.nodes.length,
              title: title,
              type: type,
              name: scope,
              full: title + ": " + scope,
              nodes: []
            });
          }
          else {
            //console.log("ADD NODE");
            $scope.tree.push({
              id: $scope.id_node,
              title: title,
              type: type,
              name: scope,
              full: title + ": " + scope,
              nodes: []
            });
            //console.log($scope.tree);
            $scope.id_node ++;
          }
      };

      $scope.collapseAll = function () {
        $scope.$broadcast('collapseAll');
      };

      $scope.expandAll = function () {
        $scope.$broadcast('expandAll');
      };
      
      $scope.tree = [];

    }]);

    phrApp.controller('numericController', function($scope, $uibModalInstance) {
      $scope.value_numeric = {};



        $scope.ok = function () {
          if($scope.value_numeric.operation == null )
            alert("Choose 1 operation");
          else if($scope.value_numeric.value == null || $scope.value_numeric.value == "")
            alert("Please input correct format for the attribute value");
          else 
            $uibModalInstance.close($scope.value_numeric);
        };

        $scope.cancel = function () {
          $uibModalInstance.dismiss('cancel');
        };
    });
  
    phrApp.controller('changeEmailController', function($scope, $http, $location, $window) {
        $scope.data = {};
        $scope.info = {};

        $scope.data.password = "";

        var type;

        $http.get('/api/loggedin')
        .success(function(user){
          type = user.type;
          if(type == "Admin"){
            // get userinfo
            $http.get('/api/admininfo')
            .success(function(res){
                $scope.info  = res;
                $scope.data.email = $scope.info.email_address;
            })
          }
          else if(type == "User"){
            $http.get('/api/userinfo')
            .success(function(res){
                $scope.info  = res;
                $scope.data.email = $scope.info.email_address;
            })
          }

        })

        var isClick = false;

        $scope.submit = function(){
          if(!isClick){
            isClick = true;

            if($scope.data.email == null){
              $scope.data.email = "";
            }
            if($scope.data.password == null){
              $scope.data.password = "";
            }


            $http.post('/api/change_email', {
              email                  : $scope.data.email,
              confirm_new_passwd     : $scope.data.password
            })
            .success(function(res){
              // No error: authentication OK
              //console.log("SUCCESS");
              isClick = false;
              $window.alert(res[1])
              $scope.data.password = "";
              if(res[0])
                $location.path('/');
            })
          }
        };

        $scope.back = function(){
          $location.path('/');
        }
    });

    phrApp.controller('accessPermisController', function($scope, $http, $location, $window) {
        $scope.access_permission_list = {};
        $scope.selectedRow = -1;
        $scope.checked = {};

        var indexEdit = -1;
        var beforeEdit = [];

        // get access permission list
        $http.post('/api/access_permission_management_list')
        .success(function(res){
            $scope.access_permission_list = res;
            // beforeEdit = res;
            for(var x in res){
              beforeEdit.push([]);
              beforeEdit[x].push(res[x][1]);
              beforeEdit[x].push(res[x][2]);
              beforeEdit[x].push(res[x][3]);
            }
            //console.log(beforeEdit);
        })     

        // set click row
        $scope.setClickedRow = function(index){

          //console.log(index);

          //console.log(beforeEdit);

          $scope.selectedRow = index;

          if(indexEdit == -1){
            indexEdit = index;
          }
          else if(index != indexEdit){

            //console.log(beforeEdit[indexEdit][0]);

            $scope.access_permission_list[indexEdit][1] = beforeEdit[indexEdit][0];
            $scope.access_permission_list[indexEdit][2] = beforeEdit[indexEdit][1];
            $scope.access_permission_list[indexEdit][3] = beforeEdit[indexEdit][2];
            indexEdit = index;
          }

          // if(index != indexEdit){
          //   $scope.selectedRow = index;
          //   console.log("Row " + $scope.selectedRow);
          //   console.log(beforeEdit);
          //   console.log(indexEdit);
          //   console.log($scope.access_permission_list)

          //   if(indexEdit != -1){
          //     $scope.access_permission_list[indexEdit][1] = beforeEdit[indexEdit][0];
          //     $scope.access_permission_list[indexEdit][2] = beforeEdit[indexEdit][1];
          //   }

          //   indexEdit= $scope.selectedRow;
          // }
        }

        // change location to assign
        $scope.assign = function(){
          $location.path('/user/assignPermission');
        }

        var isClickEdit = false;

        // edit permission
        $scope.edit = function(){
          //console.log($scope.selectedRow);
          if(!isClickEdit){
            isClickEdit = true;
            if($scope.selectedRow == null || $scope.selectedRow == -1 ){
              alert("Choose 1 row");
              isClickEdit = false;
            }
            else {
              //console.log("EDIT " + $scope.access_permission_list[$scope.selectedRow]);
              $http.post('/api/edit_access_permission', {
                row             : $scope.selectedRow,
                uploadflag      : $scope.access_permission_list[$scope.selectedRow][1],
                downloadflag    : $scope.access_permission_list[$scope.selectedRow][2],
                deleteflag      : $scope.access_permission_list[$scope.selectedRow][3]
              })
              .success(function(res){
                alert(res[1]);
                isClickEdit = false;
                if(res[0]){
                  //console.log("EDIT SUCCESS");
                  $http.post('/api/access_permission_management_list')
                  .success(function(res){
                      $scope.access_permission_list = res;

                      for(var x in res){
                        beforeEdit[x][0] = res[x][1];
                        beforeEdit[x][1] = res[x][2];
                        beforeEdit[x][2] = res[x][3];
                      }

                      console.log(beforeEdit);
                  })    
                }
              })
            }
          }
        }

        var isClickDelete = false;

        // delete access permission
        $scope.delete = function(){
          console.log($scope.selectedRow)
          console.log("DELETE");
          if(!isClickDelete){
            isClickDelete = true;
            if($scope.selectedRow == null || $scope.selectedRow == -1){
              alert("Choose 1 row");
              isClickDelete = false;
            }
            else {

                var r = confirm("Are you sure to delete this row ?");
                
                if(r == true) {

                  //console.log("Delete " + $scope.access_permission_list[$scope.selectedRow]);
                  $http.post('/api/delete_access_permission', {
                    delete_user      : $scope.access_permission_list[$scope.selectedRow][0],
                  })
                  .success(function(res){
                    if(res == true){
                      //console.log("Delete SUCCESS");
                       $http.post('/api/access_permission_management_list')
                       .success(function(res){
                           $scope.access_permission_list = res;
                          // console.log(res);
                       })   
                       isClickDelete = false;
                       $scope.selectedRow = -1;
                       $window.alert("DELETE SUCCESS !!")
                      $location.path('/user/accessPermissionManagement');
                    }
                  })
                }
                else{
                  isClickDelete = false;
                  $scope.access_permission_list[$scope.selectedRow][1] = beforeEdit[$scope.selectedRow][0];
                  $scope.access_permission_list[$scope.selectedRow][2] = beforeEdit[$scope.selectedRow][1];
                  $scope.access_permission_list[$scope.selectedRow][3] = beforeEdit[$scope.selectedRow][2];
                  $scope.selectedRow = -1;
                  indexEdit = -1;
                }
              
            }
          }
        }
    });

    phrApp.controller('assignAccessPermissionController', function($scope, $http, $location, $window) {
        $scope.authorityList = [];
        $scope.assign = {};
        $scope.assign.uploadflag = false;
        $scope.assign.downloadflag = false;
        $scope.assign.deleteflag = false;

        // get authority list
        $http.post('/api/authority_name_list')
        .success(function(res){
            $scope.authorityList = res;
            // console.log($scope.authorityList);
        })

        

        $scope.selectedAuthority = -1;
        $scope.assign.username = null;

        var isClick = false;

        $scope.submit = function(){

          if(!isClick){
            //console.log("SUCCESS");
            isClick = true;

            console.log($scope.selectedAuthority);

            if($scope.assign.username == null)
              $scope.assign.username = "";

            $http.post('/api/assign_access_permission', {
                index : $scope.selectedAuthority,
                username : $scope.assign.username,
                uploadflag : $scope.assign.uploadflag,
                downloadflag : $scope.assign.downloadflag,
                deleteflag : $scope.assign.deleteflag,
            })
            .success(function(res){

              alert(res[1]);

              if(res[0]){
                $location.path('/user/accessPermissionManagement');
              }

              isClick = false;
            })
          }
        }

         $scope.check = function(){
           return ($scope.assign.uploadflag || $scope.assign.downloadflag);
         }

         $scope.back =  function(){
            $location.path('/user/accessPermissionManagement');
         }
    });

    phrApp.controller('downloadController', function($scope, $http, $location, $window) {
        $scope.phr_list = {};
        $scope.selectedRow = null;
        $scope.selectedAuthority = "";
        $scope.username = "";
        $scope.authorityList = "";

        console.log("PHR LIST : " + $scope.phr_list);

        $http.post('/api/cancelDownloadPHR')

        var re_value = function(){
              $scope.isClick = false;
              $scope.canDownload = false;
              $scope.phr_list = {};
              $scope.selectedRow = null;
              $scope.selectedRow = null;
              $scope.selectedAuthority = "";
              $scope.username = "";
              isClickSearch = false;
        };

        var isCancle = false;

        $scope.cancel = function(){
          var r = confirm("Are you sure to cancel download ?");
          if(r == true) {
            console.log("CANCEL");
            isCancle  = true;
            $http.post('/api/cancelDownloadPHR')
            .success(function(res){
              re_value();
              if(res){
                alert("Cancel download");
              }
              $location.path('/user/downloadPHR'); 
            })
          }
        }

        // get authority_name_list
        $http.post('/api/authority_name_list')
        .success(function(res){
            $scope.authorityList = res;
        })

        // click row
        $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
        }

        $scope.isClick = false;

        var isClickSearch = false;

        $scope.canDownload = false;
        // search
        $scope.search = function(){
          if(!isClickSearch){
            isClickSearch = true;

              console.log("SEARCH DOWNLOAD");
              $http.post('/api/download_phr_list',{
                  authorityName :  $scope.selectedAuthority,
                  username      :  $scope.username
              })
              .success(function(res){
                  // isClickSearch = false;
                  
                  if(res[0] == false){
                    alert(res[1]);
                    re_value();
                    isClickSearch = false;
                  }
                  else{
                    $scope.canDownload = true;
                    $scope.phr_list = res;
                  }

                  // console.log($scope.phr_list);
                  //$location.path('/downloadSelfPHR');
              })
          }
        }

        // open download window
        $scope.download = function(){
          if(!$scope.isClick){

            $scope.isClick = true;

            if($scope.selectedRow == null){
              alert("Choose 1 row for download");
              $scope.isClick = false;
            }
            else {
              $scope.isClick = true;
              $scope.canDownload = false;
              $http.post('/api/downloadPHR', {
                authorityName :  $scope.selectedAuthority,
                username      :  $scope.username,
                index         :  $scope.selectedRow,
              })
              .success(function(res){
                re_value();
                
                console.log(res);

                    if(res){
                      $window.open('/api/downloadPHR');
                      
                    }
                    else if(!isCancle){
                      alert("DOWNLAOD FAILED (Decryption fail or can't verify user)");
                    }
              })
            }
          }
        }

        // Can't change page
        $scope.$on('$locationChangeStart', function(event) {
          console.log("IS CLICK : "  + $scope.isClick);

            // check when upload isn't complete
            if ($scope.isClick) {
               var r = confirm("Are you sure to leave this page ?");
               if(r == true) {
                  $scope.phr_list = {};
                  $scope.selectedRow = null;
                  $scope.selectedRow = null;
                  $scope.selectedAuthority = "";
                  $http.post('/api/cancelDownloadPHR')
               }
            }
        });
    });

    phrApp.controller('deleteController', function($scope, $http, $location) {
        $scope.phr_list = {};
        $scope.selectedRow = null;
        $scope.canDelete = false;
        $scope.authorityList = "";

                // get authority_name_list
        $http.post('/api/authority_name_list')
        .success(function(res){
            $scope.authorityList = res;
        })

        // $http.post('/api/delete_self_phr_list')
        // .success(function(res){
        //     $scope.phr_list = res;
        //   //   console.log("DELETE LIST : " + res);
        // })

        // click row
        $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
        }

        var isClickDelete = false;
        var isClickSearch = false;

        // Search
        $scope.search = function(){
          if(!isClickSearch){
            if($scope.username == null)
              $scope.username = "";
            if($scope.selectedAuthority == null)
              $scope.selectedAuthority = "";

            console.log("SEARCH Delete");
            isClickSearch =true;
            $http.post('/api/delete_phr_list',{
                authorityName :  $scope.selectedAuthority,
                username      :  $scope.username
            })
            .success(function(res){
                // isClickSearch = false;
                if(res[0] == false){
                  alert(res[1]);
                  $scope.username = "";
                  $scope.selectedAuthority = "";
                  isClickSearch = false;
                }
                else{
                  $scope.phr_list = res;
                  $scope.canDelete = true;
                }
                console.log($scope.canDelete);
                // console.log($scope.phr_list);
                //$location.path('/downloadSelfPHR');
            })
          }
        }

        // delete phr
        $scope.delete = function(){


          if(!isClickDelete){
            isClickDelete = true;
            if($scope.selectedRow == -1 || $scope.selectedRow == null){
              alert("Choose row !!");
              isClickDelete = false;
            }
            else {

                var r = confirm("Do you want to delete this file ?");
               
                if(r == true) {
                    $http.post('/api/deletePHR', {
                      authorityName :  $scope.selectedAuthority,
                      username      :  $scope.username,
                      index         :  $scope.selectedRow
                    })
                    .success(function(res){
                      alert(res[1]);
                      isClickDelete = false;
                      if(res[0]){
                        $scope.phr_list = {};
                        $scope.selectedRow = -1;
                        $scope.canDelete = false;
                        $scope.selectedAuthority = "";
                        $scope.username = "";
                        isClickSearch = false;
                        isClickDelete = false;
                        $location.path('user/deletePHR')
                      }
                    })
                }
                else {
                  $scope.selectedRow = -1;
                  isClickDelete = false;
                }
            }
          } 

        }
    });

    phrApp.controller('loginController', function($scope,$http,$location, $window, $route){
        $scope.user = {};
       var isClick = false;

        $scope.login = function(){
          if(!isClick){

            isClick = true;

            if($scope.user.username == null || $scope.user.username.length > 20 || $scope.user.username.length == 0){
              alert("Please input username's length between 1 - 20 charecters");
              isClick = false;
              $scope.user = {};
            } 
            else if($scope.user.type == null){
              alert("Please choose 1 account type");
              isClick = false;
              $scope.user = {};
            }
            else if($scope.user.password == null || $scope.user.password.length < 8 || $scope.user.password.length > 50){
              alert("Please input password's length between 8 - 50 charecters");
              isClick = false;
              $scope.user = {};
            }
            else {
           //   console.log("GO LOGIN");
              $http.post('/api/login', {
                username: $scope.user.username,
                password: $scope.user.password,
                type    : $scope.user.type
              })
              .success(function(user){
                // No error: authentication OK
            //    console.log("SUCCESS");
            //    console.log(user);
                $window.alert("LOGIN SUCCESS !!")
                $window.location.reload();
              })
              .error(function(err){
                console.log(err);
                $window.alert("Wrong username or password");
                $window.location.reload();
                isClick = false;
                $scope.user = {};
              })
            }
          }
        };

        $scope.forget_pwd = function(){
          $location.path('/forgetpwd');
        }
    });

    phrApp.controller('forgetPasswordController', function($scope,$http,$location, $window, $route){
        $scope.user = {};
        $scope.isClickButton = false;
        $scope.isReset = false;
        $scope.header = "";
        var isClickRequest = false;
        var isClickReset = false;

        $scope.setReset = function(){
          $scope.isClickButton = true;
          $scope.isReset = true;
          $scope.header = "Password Resetting";
        }

        $scope.setRequest = function(){
          $scope.isClickButton = true;
          $scope.isReset = false;
          $scope.header = "Password Resetting Code Requesting";
        }


        $scope.requestCode = function(){
          
          if(!isClickRequest){
         //   console.log("GO LOGIN");
            isClickRequest = true;
            if($scope.user.username == null || $scope.user.username == ""){
              alert("Please input username's length between 1 - 20 charecters");
              isClickRequest = false;
            }
            else if($scope.user.type == null){
              alert("CHOOSE TYPE USER");
              isClickRequest = false;
            }
            else {
              $http.post('/api/requestCode', {
                username: $scope.user.username,
                type    : $scope.user.type
              })
              .success(function(res){
                // No error: authentication OK
            //    console.log("SUCCESS");
            //    console.log(user);
                isClickRequest = false;
                alert(res[1]);

                if(res[0]){
                  $location.path('/');
                }
                else {
                  $scope.user = {};
                }
              })
            }
          }
        };

        $scope.resetPwd = function(){
          
          if(!isClickReset){
         //   console.log("GO LOGIN");
            isClickReset = true;
            if($scope.user.username == null || $scope.user.username == ""){
              alert("Please input username's length between 1 - 20 charecters");
              isClickReset = false;
            }
            else if($scope.user.type == null){
              alert("CHOOSE TYPE USER");
              isClickReset = false;
            }
            else if($scope.user.resettingCode == "" || $scope.user.resettingCode == null){
              alert("the restting code 's length is 8 charecters.");
              isClickReset = false;
            }
            else {
              $http.post('/api/resetPwd', {
                username      : $scope.user.username,
                resettingCode : $scope.user.resettingCode,
                type          : $scope.user.type
              })
              .success(function(res){
                // No error: authentication OK
            //    console.log("SUCCESS");
            //    console.log(user);
                isClickReset = false;
                alert(res[1]);

                if(res[0]){
                  $location.path('/');
                }
                else {
                  $scope.user = {};
                }
              })
            }
          }
        }
    });

    //----------------------- ADMIN ------------------------------
    
    // create the controller and inject Angular's $scope
    phrApp.controller('admininfoController', function($scope, $http, $location) {
        $scope.info = {};

        // get userinfo
        $http.get('/api/admininfo')
        .success(function(res){
            $scope.info  = res;
            //console.log("INFO " + $scope.info.attribute_list);
        })
    });

    // create the controller and inject Angular's $scope
    phrApp.controller('changeConfigController', function($scope, $http, $location) {
        $scope.info = {};
        $scope.password = "";

        var isClick = false;

        // get userinfo
        $http.get('/api/admininfo')
        .success(function(res){
            $scope.info  = res;
            //console.log("INFO " + $scope.info.attribute_list);
        })

        $scope.submit = function(){
          if(!isClick){
            isClick = true;

            if($scope.info.audit_server_ip_addr == null){
              $scope.info.audit_server_ip_addr = "";
            }
            if($scope.info.phr_server_ip_addr == null){
              $scope.info.phr_server_ip_addr = "";
            }
            if($scope.info.emergency_server_ip_addr == null){
              $scope.info.emergency_server_ip_addr = "";
            }
            if($scope.info.password == null){
              $scope.info.password = "";
            }

            $http.post('/api/changeConfig',{
              audit     : $scope.info.audit_server_ip_addr,
              phr       : $scope.info.phr_server_ip_addr,
              emergency : $scope.info.emergency_server_ip_addr,
              passwd    : $scope.password
            })
            .success(function(res){
              alert(res[1]);
              isClick = false;
              $scope.password = "";
              if(res[0]){
                $location.path("/admin/info");
              }
            })
          }
        }

    });

        // create the controller and inject Angular's $scope
    phrApp.controller('changeMailServerController', function($scope, $http, $location) {
        $scope.info = {};
        $scope.password = "";
        $scope.new_passwd = "";
        $scope.confirm_passwd = "";
        $scope.changepwd = false;

        var isClick = false;

        // get userinfo
        $http.get('/api/admininfo')
        .success(function(res){
            $scope.info  = res;
            //console.log("INFO " + $scope.info.attribute_list);
        })

        $scope.submit = function(){
          if(!isClick){      
            isClick = true;    

            if($scope.info.mail_server_url == null){
              $scope.info.mail_server_url = "";
            }
            if($scope.info.authority_email_address == null){
              $scope.info.authority_email_address = "";
            }
            if($scope.new_passwd == null){
              $scope.new_passwd = "";
            }
            if($scope.confirm_passwd == null){
              $scope.confirm_passwd = "";
            }
            if($scope.password == null){
              $scope.password = "";
            }

            console.log("New Password : " + $scope.new_passwd);
            console.log("Confirm New Password : " + $scope.confirm_passwd);
            console.log("Password : " + $scope.password);

            $http.post('/api/changemailserver',{
                  mailserver      : $scope.info.mail_server_url,
                  authorityemail  : $scope.info.authority_email_address,
                  newpasswd       : $scope.new_passwd,
                  confirmpasswd   : $scope.confirm_passwd,
                  changepwd       : $scope.changepwd,
                  password        : $scope.password 
              })
              .success(function(res){
                isClick = false;

                alert(res[1]);

                $scope.password = "";
                $scope.new_passwd = "";
                $scope.confirm_passwd = "";

                if(res[0]){
                  $location.path("/admin/info");
                }
              })
          }
        }
    });

    phrApp.controller('attributeController', function($scope, $http, $location) {
        $scope.attribute_table = {};
        $scope.selectedRow = -1;

        $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
        }

        // get userinfo
          $http.post('/api/adminattribute')
          .success(function(res){
              $scope.attribute_table  = res;
              console.log($scope.attribute_table);
          })

          var isClickDelete = false;

          $scope.delete = function(){
            if(!isClickDelete){
              isClickDelete = true;

              if($scope.selectedRow == -1){
                alert("Choose row !!");
                isClickDelete = false;
              }
              else {
                  var r = confirm("Removing the attribute may affect to an attribute list of some users!!!\n" + 
                  "Are you sure to remove this attribute?");

                  if(r == true) {

                        $http.post('/api/deleteattribute',{
                          attributename : $scope.attribute_table[$scope.selectedRow][0]
                        })
                        .success(function(res){
                            if(res){
                              alert("Delete Success !!");
                              $http.post('/api/adminattribute')
                              .success(function(res){
                                  $scope.attribute_table  = res;
                                  console.log($scope.attribute_table);
                              })
                              $scope.selectedRow = -1;
                            }
                            else {
                              alert("Delete Faill !!");
                            }
                            isClickDelete = false;
                            $location.path('/admin/attribute');
                        })
                  } 
                  else {
                    isClickDelete = false;
                  }
              }
            }
        }
    });

    phrApp.controller('registerAttributeController', function($scope, $http, $location) {
        $scope.attributename = "";
        $scope.isnumerical = false;

        var isClick = false;

        // get userinfo
        $scope.submit = function(){

          if(!isClick){
            isClick = true;
            $http.post('/api/registerattribute',{
              attributename : $scope.attributename,
              isnumerical   : $scope.isnumerical
            })
            .success(function(res){
              isClick = false;
              alert(res[1]);
              if(res[0]){
                $location.path('/admin/attribute');
              }
            })
          }
        }
    });

    phrApp.controller('admintransactionController', function($scope, $http, $location, $filter) {
      $scope.chooseTable = "";
      $scope.Date = [];
      $scope.Date.startDate = new Date();
      $scope.Date.startTime = new Date(1970, 0, 1, 0, 0, 0);
      $scope.Date.endDate = new Date();
      $scope.Date.endTime = new Date(1970, 0, 1, 0, 0, 0);    
      $scope.transaction_log_type = "";
      $scope.allFlag = false;
      $scope.logs = {};
      $scope.bigTotalItems = 1;
      $scope.bigCurrentPage = 1;
      $scope.limit = $scope.bigCurrentPage * 10;
      $scope.begin = ($scope.bigCurrentPage - 1) * 10;
      $scope.maxSize= 5;



      var monthNames = ["January", "February", "March", "April", "May", "June",
      "July", "August", "September", "October", "November", "December"];

      var isClick = false;

      $scope.search = function(){
        if(!isClick){

          isClick = true;
          
          // console.log($scope.Date.startDate);
          // console.log($scope.Date.startTime);
          // console.log($scope.Date.endDate);
          // console.log($scope.Date.endTime);

           if(!$scope.allFlag){
        //     // $scope.sDate.d =  $filter('date')($scope.startDate, 'd');
        //     // $scope.sDate.m =  $scope.startDate.getMonth();
        //     // $scope.sDate.y =  $filter('date')($scope.startDate, 'yyyy');



             // if($scope.Date.startDate == null || $scope.Date.startTime == null ||
             //    $scope.Date.endDate == null || $scope.Date.endTime == null ){
             //     alert("Invalid input !!");
             //     isClick =false;
             // }
             // else {
               $http.post('/api/admin_transaction_auditing', {
                 transaction_log_type  : $scope.transaction_log_type, 
                 start_year_index      : $scope.Date.startDate.getFullYear(), 
                 start_month_index     : $scope.Date.startDate.getMonth(), 
                 start_day_index       : $scope.Date.startDate.getDate()-1, 
                 start_hour_index      : $scope.Date.startTime.getHours(), 
                 start_minute_index    : $scope.Date.startTime.getMinutes(), 
                 end_year_index        : $scope.Date.endDate.getFullYear(), 
                 end_month_index       : $scope.Date.endDate.getMonth(), 
                 end_day_index         : $scope.Date.endDate.getDate()-1, 
                 end_hour_index        : $scope.Date.endTime.getHours(), 
                 end_minute_index      : $scope.Date.endTime.getMinutes() 
               })
               .success(function(res){
                isClick = false;
                //console.log(res);
                //console.log(angular.isArray(res));
                 // No error: authentication OK
                 //console.log("SUCCESS");
                  if(angular.isArray(res)){
                     $scope.logs = res;
                     $scope.bigTotalItems = $scope.logs.length;
                     console.log($scope.bigTotalItems);
                     $scope.chooseTable = $scope.transaction_log_type;
                     $location.path('/admin/transaction');
                  }
                  else {
                    alert(res);
                    $scope.logs = {};
                  }
               })
             //}
           }
           else {
             $http.post('/api/admin_transaction_auditing', {
               allFlag               : $scope.allFlag,
               transaction_log_type  : $scope.transaction_log_type
             })
             .success(function(res){
              isClick = false;
               // No error: authentication OK
               //console.log("SUCCESS");
               if(angular.isArray(res)){
                     $scope.logs = res;
                     $scope.bigTotalItems = $scope.logs.length;
                     console.log($scope.bigTotalItems);
                     $scope.chooseTable = $scope.transaction_log_type;
                     $location.path('/admin/transaction');
                  }
                  else {
                    alert(res);
                    $scope.logs = {};
                  }
             })
           }
         }
      }

    });

    phrApp.controller('adminManagementController', function($scope, $http, $location) {
        $scope.admin_list = {};
        $scope.selectedRow = -1;

        var isClick = false;

        $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
        }

        // get userinfo
          $http.post('/api/adminlist')
          .success(function(res){
              $scope.admin_list  = res;
              //console.log($scope.admin_list);
          })

          $scope.edit = function(){
            if(!isClick){
              isClick = true;
              if($scope.selectedRow == -1){
                alert("Choose row !!");
                isClick = false;
              }
              else {
                $http.post('/api/initeditadmin',{
                  username : $scope.admin_list[$scope.selectedRow][0],
                  email    : $scope.admin_list[$scope.selectedRow][1]
                })
                .success(function(res){
                  isClick = false;
                  if(res){
                    $location.path('/admin/editadmin');
                  }
                  else {
                    alert("Error Can't not edit admin");
                    $location.path('/admin/adminmanagement');
                  }
                })
              }
            }
          }

          $scope.delete = function(){
            if(!isClick){
              isClick = true;
              if($scope.selectedRow == -1){
                    alert("Choose row !!");
                    isClick = false;
              }
              else {
                var r = confirm("Are you sure to remove this admin?\n");
               
                if(r == true) {
                      $http.post('/api/deleteadmin',{
                        username : $scope.admin_list[$scope.selectedRow][0]
                      })
                      .success(function(res){
                        isClick = false;
                          if(res){
                            $scope.selectedRow = -1;
                            alert("Delete Success !!");
                            $http.post('/api/adminlist')
                            .success(function(res){
                                $scope.admin_list  = res;
                                //console.log($scope.admin_list);
                            })
                          }
                          else {
                            alert("Delete Faill !!");
                          }
                          $location.path('/admin/adminmanagement');
                      })
                }
                else{
                  isClick = false;
                }
              } 
            }
          }

          $scope.reset = function(){
            if(!isClick){
              if($scope.selectedRow == -1){
                alert("Choose row !!");
                isClick = false;
              }
              else {
                var r = confirm("Are you sure to reset password ?");

                if(r == true) {
                      $http.post('/api/resetpasswordadmin',{
                        username : $scope.admin_list[$scope.selectedRow][0]
                      })
                      .success(function(res){
                        $scope.selectedRow = -1;
                        isClick = false;
                        alert(res[1]);
                        $location.path('/admin/adminmanagement')
                      })
                }
                else {
                  isClick = false;
                }
              } 
            }
          }
    });

    phrApp.controller('registerAdminController', function($scope, $http, $location) {
        $scope.username = "";
        $scope.email = "";
        var isClick = false;

        // get userinfo
        $scope.submit = function(){
          if(!isClick){
            isClick = true;
            $http.post('/api/registeradmin',{
              username : $scope.username,
              email    : $scope.email
            })
            .success(function(res){
              isClick = false;
              alert(res[1]);
              if(res[0]){
                $location.path('/admin/adminmanagement');
              }
            })
          }
        }
    });

    phrApp.controller('editAdminController', function($scope, $http, $location) {
        $scope.username = "";
        $scope.email = "";

        var isClick = false;

        $http.post('/api/info_editadmin')
        .success(function(res){
          $scope.username = res.username;
          $scope.email = res.email;
        })

        // get userinfo
        $scope.submit = function(){
          if(!isClick){
            isClick = true;
            if($scope.username == null){
              $scope.username = "";
            }
            if($scope.email == null){
              $scope.email = "";
            }
            $http.post('/api/editadmin',{
              username : $scope.username,
              email    : $scope.email
            })
            .success(function(res){
              isClick = false;
              alert(res[1]);
              if(res[0]){
                $location.path('/admin/adminmanagement');
              }
            })
          }
        }
    });

    phrApp.controller('authorityManagementController', function($scope, $http, $location) {
      $scope.authority_table = [];

      $scope.selectedRow = -1;

      var isClick = false;

      $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
      }

      $http.post('/api/admin_authority_list')
      .success(function(res){
              $scope.authority_table  = res;
              //console.log($scope.admin_list);
      })

      $scope.edit = function(){
            if($scope.selectedRow == -1){
              alert("Choose row !!");
            }
            else {

              console.log($scope.authority_table[$scope.selectedRow]);

              $http.post('/api/initeditauthority',{
                authorityname : $scope.authority_table[$scope.selectedRow][0],
                ipaddress : $scope.authority_table[$scope.selectedRow][1]
              })
              .success(function(res){
                if(res){
                  $location.path('/admin/editauthority');
                }
                else {
                  alert("Error Can't edit authority");
                  $location.path('/admin/authoritymanagement')
                }
              })
            }
      }

      var isClickDelete = false;

      $scope.delete = function(){

        if(!isClickDelete){
          isClickDelete = true;
          if($scope.selectedRow == -1){
            alert("Choose row !!");
            isClickDelete = false;
          }
          else {
              var r = confirm("Are you sure to remove this authority?\n");
             
              if(r == true) {

                    $http.post('/api/deleteauthority',{
                      authorityname : $scope.authority_table[$scope.selectedRow][0]
                    })
                    .success(function(res){
                        if(res){
                          $http.post('/api/admin_authority_list')
                          .success(function(res){
                                  $scope.authority_table  = res;
                                  //console.log($scope.admin_list);
                          })
                          $scope.selectedRow = -1;
                          alert("Delete Success !!");
                          $location.path('/admin/authoritymanagement');
                        }
                        else {
                          alert("Delete Faill !!");
                          $scope.selectedRow = -1;
                          $location.path('/admin/authoritymanagement');
                        }
                        isClickDelete  = false;
                    })
              } 
              else {
                isClickDelete = false;
                $scope.selectedRow = -1;
              }
          }
        }
      }
    });

    phrApp.controller('registerAuthorityController', function($scope, $http, $location) {
        $scope.authority_name = "";
        $scope.ip_address = "";

        var isClick = false;

        // get userinfo
        $scope.submit = function(){

          if(!isClick){
            isClick = true;

            $http.post('/api/registerauthority',{
              authorityname : $scope.authority_name,
              ipaddress   : $scope.ip_address
            })
            .success(function(res){
              isClick = false;
              alert(res[1]);
              
              if(res[0]){          
                $location.path('/admin/authoritymanagement');
              }
            })
          }
        }
    });

    phrApp.controller('editAuthorityController', function($scope, $http, $location) {
        $scope.authority_name = "";
        $scope.ip_address = "";

        var isClick = false;

        console.log("EDIT !!");

        $http.post('/api/info_editauthority')
        .success(function(res){
          console.log("GET INFO ");
          $scope.authority_name = res.authority;
          $scope.ip_address = res.ipaddress;
        })

        // get userinfo
        $scope.submit = function(){

          if(!isClick){
            isClick = true;
            console.log($scope.ip_address+"");

            $http.post('/api/editauthority',{
              authority   : $scope.authority_name,
              ipaddress   : $scope.ip_address
            })
            .success(function(res){
              isClick = false;
              alert(res[1]);
                if(res[0]){
                  $location.path('/admin/authoritymanagement');
                }
            })
          }
        }
    });

    phrApp.controller('userManagementController', function ($scope, $http, $location) {

        var arr = [];
        $scope.selectedRow = null ;

        

        $scope.tree_data = [{Name: " " ,Type: " ", Email: " ", children: []}];

        var getlist = function(){

          arr = [];
          $scope.selectedRow = null ;

          var index = 0;

          $http.post('/api/user_list')
          .success(function(res){
            console.log("GET INFO ");
            
            angular.forEach(res, function(value,key){

              var str = value.split("+");
              if(str[0] == "M"){
                arr.push({
                  ID: index, Name: str[1], Type: str[2], Email: str[3], children: [] 
                });
              }
               else if(str[0] == "C"){
                  arr[arr.length - 1].children.push({
                    ID: index, Name:str[1], Type: str[2], Email: str[3],
                       children: [] 
                  });
               }
              
              index ++ ;
              console.log(str);
            });

            console.log(arr);

            $scope.tree_data = arr.slice();

            console.log($scope.tree_data);
           
          })
        };

        getlist();

        $scope.col_defs = [

          {
            field: "Type",
            displayName: "Type",
            // cellTemplate: '<span ng-click="cellTemplateScope.click(row.branch.ID)">{{ row.branch[col.field] }}</span>',
            // cellTemplateScope: {
            //     click: function(data) {         // this works too: $scope.someMethod;
            //         console.log(data);
            //         $scope.index = data;
            //     }
            // }
          },

          {
            field: "Email",
            displayName: "Email Address",
            // cellTemplate: '<span ng-click="cellTemplateScope.click(row.branch)">{{ row.branch[col.field] }}</span>',
            // cellTemplateScope: {
            //     click: function(data) {         // this works too: $scope.someMethod;
            //         console.log(data);
            //         $scope.selectedRow = data;
            //     }
            // }
          }

        ];

        $scope.my_tree_handler = function(branch){
          console.log('you clicked on', branch)
          $scope.selectedRow = branch;
        }

        $scope.register =  function(){
          $http.post('/api/set_register_user')
          .success(function(res){
          })

         $location.path('/admin/registeruser');
        }

        var isClickEdit = false;

        $scope.edit =  function(){

          console.log($scope.selectedRow);
          if(!isClickEdit){
            isClickEdit = true;
            if($scope.selectedRow != null){
              if($scope.selectedRow['Type'] == "User"){
                console.log("Edit User");
                $http.post('/api/setedituser',{
                  ID   : $scope.selectedRow['ID']
                })
                .success(function(res){
                  isClickEdit = false;
                  console.log("EDIT USER");
                  if(res)
                    $location.path('/admin/edituser');
                  else
                    alert("Edit failed");
                })
                 
              }
              else if($scope.selectedRow['Name'].indexOf(" = ") != -1 && $scope.selectedRow['Type'] == "Attribute"){
                console.log("Edit Attribute");
                $http.post('/api/seteditattribute',{
                  ID   : $scope.selectedRow['ID']
                })
                .success(function(res){
                  console.log("EDIT ATTRIBUTE");
                  $location.path('/admin/editattribute');
                })
              }
            }
          }
        }

        $scope.isResetPwd =     function(){
        //  console.log($scope.selectedRow);
          if($scope.selectedRow != null){
            if($scope.selectedRow['Type'] == "User")
              return true;
            else
              return false;
          }
        }

        $scope.isEdit = function(){
        //  console.log($scope.selectedRow);
          if($scope.selectedRow != null){
            if($scope.selectedRow['Type'] == "User" || ($scope.selectedRow['Name'].indexOf(" = ") != -1 && $scope.selectedRow['Type'] == "Attribute"))
              return true;
            else
              return false;
          }
        }

         var isClicked_resetPwd = false;

        $scope.resetPwd =     function(){

          if(!isClicked_resetPwd){

            isClicked_resetPwd = true;

            var r = confirm("Are you sure to reset password " + $scope.selectedRow['Name'] + "?\n");
             
              if(r == true) {
                    $http.post('/api/resetpassworduser',{
                      username   : $scope.selectedRow['Name']
                    })
                    .success(function(res){

                      isClicked_resetPwd = false;

                       alert(res[1]);
                    })
              } 
              else {
                 isClicked_resetPwd = false;
              }
          }

        }

        var isClicked_remove = false;

        $scope.remove = function(){

          if(!isClicked_remove){

            isClicked_remove = true;

            var r = confirm("Are you sure to remove this " + $scope.selectedRow['Type'] + "?\n");
             
              if(r == true) {

                    $http.post('/api/removeuser',{
                      ID : $scope.selectedRow['ID']
                    })
                    .success(function(res){

                      isClicked_remove = false;

                        if(res){
                          alert("Remove Success !!");
                          getlist();
                          $location.path('/admin/usermanagement');
                        }
                        else {
                          alert("Remove Faill !!");
                          $location.path('/admin/usermanagement');
                        }
                    })
              } 
              else
                 isClicked_remove = false;
            }
          }
    });

    phrApp.controller('registerUserController', function($scope, $http, $location) {
        $scope.attributename = "";

        $scope.isnumerical = false;

        $scope.username = "";
        $scope.email = "";

        $scope.attribute_table = [];

        $http.post('/api/table_attribute_for_user_management')
        .success(function(res){
          console.log("SSSSS");
          console.log(res);
          $scope.attribute_table = res;

          for(var i = 0 ; i < $scope.attribute_table.length;i++){

                $scope.attribute_table[i][0] = false;
                if($scope.attribute_table[i][2] != "(none)")
                  $scope.attribute_table[i][2] = "(value)";
              }
        })

        var isClicked = false;

        $scope.submit = function(){
          if(!isClicked){

            isClicked = true;

            if($scope.email == null)
              $scope.email = "";
            if($scope.username == null)
              $scope.username = null;

            $http.post('/api/registeruser',{
              username   : $scope.username,
              email   : $scope.email,
              attributeTable : $scope.attribute_table
            })
            .success(function(res){
                $scope.username = "";
                $scope.email = "";

                isClicked = false;

                for(var i = 0 ; i < $scope.attribute_table.length;i++){
                  $scope.attribute_table[i][0] = false;
                  if($scope.attribute_table[i][2] != "(none)")
                    $scope.attribute_table[i][2] = "(value)";
                }

                console.log(res);

                alert(res[1]);

                if(res[0]){
                  $location.path('/admin/usermanagement');
                }
                
            })
          }
        }
    });

    phrApp.controller('editUserController', function($scope, $http, $location) {
        
      $scope.username = "";
      $scope.email = "";
      $scope.attribute_table = [];

      $http.post('/api/table_attribute_for_user_management')
      .success(function(res){
        $scope.attribute_table = res;
          console.log("TABLE");
          console.log(res);
       })

      $http.post('/api/info_for_edit_user')
      .success(function(res){
        $scope.username = res[0];
        $scope.email    = res[1];
          console.log("USERNAME Enail");
          console.log(res);
      })

      var isClicked  = false;

      $scope.submit = function(){
        if(!isClicked){
          isClicked = true;
          if($scope.email == null)
            $scope.email = "";
          if($scope.username == null)
            $scope.username = null;

          $http.post('/api/edituser',{
            username: $scope.username,
            email   : $scope.email,
            attributeTable : $scope.attribute_table
          })
          .success(function(res){

            isClicked = false;
            alert(res[1]);
            
            if(res[0])
              $location.path('/admin/usermanagement');
          })
        }
      }

    });

    phrApp.controller('editAttributeController', function($scope, $http, $location) {
        
      $scope.username = "";
      $scope.attributename = "";
      $scope.attributevalue = "";

      $http.post('/api/info_for_edit_attribute')
      .success(function(res){
        $scope.username         = res[0];
        $scope.attributename    = res[1];
        $scope.attributevalue   = res[2];
          console.log("USERNAME Attribute");
          console.log(res);
          console.log($scope.username);
          console.log($scope.attributename);
          console.log($scope.attributevalue);
      })

      var isClicked = false;

      $scope.submit = function(){

        if(!isClicked){

          isClicked = true;
          $http.post('/api/editattribute',{
            username: $scope.username,
            attributename   : $scope.attributename,
            attributevalue : $scope.attributevalue
          })
          .success(function(res){
              isClicked = true;
              alert(res[1]);
              $location.path('/admin/usermanagement');
          })
        }
      }

    });


    //--------------------------------------------------------------------

    phrApp.controller('errorController', function($scope) {
        $scope.message = "Error Don't have this page";
        console.log("TESTTTT ");
    });

    // CLICK ANYWHERE
    phrApp.directive('clickOff', function($parse, $document) {
    var dir = {
        compile: function($element, attr) {
          // Parse the expression to be executed
          // whenever someone clicks _off_ this element.
          var fn = $parse(attr["clickOff"]);
          return function(scope, element, attr) {
            // add a click handler to the element that
            // stops the event propagation.
            element.bind("click", function(event) {
              event.stopPropagation();
            });
            angular.element($document[0].body).bind("click",                                                                 function(event) {
                scope.$apply(function() {
                    fn(scope, {$event:event});
                });
            });
          };
        }
      };
    return dir;
});
'use strict';

    // create the module and name it phrApp
    	// also include ngRoute for all our routing needs

    var myClass;

    var isLoggin;

    var userType;

    var phrApp = angular.module('phrApp', ['ngResource', 'ngRoute', 'ngFileUpload', 'ui.tree', 'ngAnimate', 'ui.bootstrap'])

  .config(function($routeProvider, $locationProvider, $httpProvider) {
    //================================================
    // Check if the user is connected
    //================================================
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
            else if(user.type == "Admin" && ($location.path().indexOf("/user") > -1 ))
              $location.url('/admin/info');      
          }
          else{
            deferred.reject();
            if(user.type == "User")
              $location.url('/user/info');
            else if(user.type == "Admin")
              $location.url('/admin/info')
          }
        }
        // Not Authenticated
        else if($location.path() != '/'){
          //console.log("NO LOGIN");
        //  $timeout(function(){deferred.reject();}, 0);

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
      .when('/ab', {
        templateUrl: '/views/main.html'
      })

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
        controller: 'registerattributeController',
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

      .when('/user/deleteSelfPHR', {
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

      .when('/', {
        templateUrl: 'login.html',
        controller: 'loginController',
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
      $http.post('/api/logout');
    };
  });

    // create the controller and inject Angular's $scope
    phrApp.controller('indexController', function($scope, $http, $location) {
      $scope.isLoggin = false;

      console.log("ISLOGGIN : " + $scope.isLoggin);

      $http.get('/api/loggedin').success(function(user){
        // Authenticated
        if (user !== '0'){
          $scope.isLoggin = true;
          $scope.usertype = user.type;
        }
        // Not Authenticated
        else
          $scope.isLoggin = false;
      });
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
            var full_name = info.authorityName +'.' + info.username ;
            if(full_name == restricted[index][1]){
              $scope.isShowCancel = true;
            }
        }

        var isClickApprove = false;

        $scope.approve = function(){
          if($scope.selectedRow == -1){
            alert("No any row selected");
          }
          else {
            if(!isClickApprove){
              isClickApprove = true;
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
                if(res){
                  $http.post('/api/restricted_table')
                  .success(function(res){
                      $scope.restricted = res;
                      alert("Approve SUCCESS !!");
                      $location.path('/restricted');
                  })
                }
                else
                  // ERROR
                  alert(" .... ");
                //$location.path('/info');
              })
            }
          }
        }

        $scope.clickedSomewhereElse = function(){
        //  console.log("HIT !!")
          $scope.selectedRow = null;
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
                start_day_index       : $scope.Date.startDate.getDate(), 
                start_hour_index      : $scope.Date.startTime.getHours(), 
                start_minute_index    : $scope.Date.startTime.getMinutes(), 
                end_year_index        : $scope.Date.endDate.getFullYear(), 
                end_month_index       : $scope.Date.endDate.getMonth(), 
                end_day_index         : $scope.Date.endDate.getDate(), 
                end_hour_index        : $scope.Date.endTime.getHours(), 
                end_minute_index      : $scope.Date.endTime.getMinutes() 
              })
              .success(function(res){
                // No error: authentication OK
                //console.log("SUCCESS");
                $scope.logs = res;
                $scope.bigTotalItems = $scope.logs.length;
                console.log($scope.bigTotalItems);
                isClick = false;
                $location.path('/user/transaction');
              })
            }
          }
          else {
            $http.post('/api/transaction_auditing', {
              allFlag               : $scope.allFlag,
              transaction_log_type  : $scope.transaction_log_type
            })
            .success(function(res){
              // No error: authentication OK
              //console.log("SUCCESS");
              $scope.logs = res;
              $scope.bigTotalItems = $scope.logs.length;
              console.log($scope.bigTotalItems);
              isClick = false;
              $location.path('/user/transaction');
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
      //}

    });

    phrApp.controller('trustedUsersController', function($scope, $http, $location) {
        $scope.trustedUsers = {};
        $scope.authorityList = {};
        $scope.username = "";
        $scope.selectedAuthority ="";

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
          $scope.selectedRow = null;
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
              authorityName   : $scope.selectedAuthority,
            })
            .success(function(res){
              // No error: authentication OK
              //console.log("SUCCESS");
              isClick = false;
              if(res){
                $http.post('/api/trusted_users_table')
                .success(function(res){
                    $scope.trustedUsers = res;
                    alert("Add User SUCCESS !!");
                    $location.path('/trustedUsers');
                    //console.log($scope.attribute_all);
                })
              }
              else
                alert("Trusted user must be another user or Please input correct format for the username!!");
              //$location.path('/info');
            })
          }
        };
    });

    phrApp.controller('changePwdController', function($scope, $http, $location) {
        $scope.password = {};
        $scope.password.flag = false;
        var isClick = false;

        $scope.submit = function(){
          if(!isClick){
            isClick = true;
            $http.post('/api/changepwd', {
              current_passwd        : $scope.password.curr_passwd,
              new_passwd            : $scope.password.new_passwd,
              confirm_new_passwd    : $scope.password.confirm_passwd,
              send_new_passwd_flag  : $scope.password.flag
            })
            .success(function(user){
              // No error: authentication OK
              //console.log("SUCCESS");
              isClick = false;
              alert("CHANGE PASSWORD SUCCESS !!");
              $http.get('/api/loggedin')
              .success(function(user){
                if(user.type = "Admin")
                  $location.path('/admin/info');
                else if(user.type = "User")
                  $location.path('/user/info');
              })
            })
          }
        };

        $scope.back = function(){
          $location.path('/info');
        }
    });

    phrApp.controller('uploadPHRController', ['$scope', 'Upload' , '$http' , '$location' , function ($scope, Upload, $http, $location) {
        $scope.authorityList = {};
        $scope.attribute_all = {};
        $scope.id_node = 1;
        $scope.userinfo = {} ;
        $scope.description = "";
        $scope.con_level = "";
        $scope.threshold = -1;
        $scope.truted_users = -1;
        $scope.tree_string = "";
        $scope.parent = ""; 
        $scope.canUpload = false;
        $scope.search_selectedAuthority = "";
        $scope.search_username  = "";

        // Cancle upload
        $http.post('/api/cancelUploadPHR')

        // get authority_name_list
        $http.post('/api/authority_name_list')
        .success(function(res){
            $scope.authorityList = res;
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

            // validation tree
            if(!($scope.tree.length != 0 &&  $scope.description != "" && $scope.con_level != "") && 
              !($scope.con_level == "Restricted level" && $scope.threshold > 0 && $scope.truted_users > 0)){
                console.log("WRONG TREE");
                $scope.isClick = false;
            }

            // vaildation file & form
            else if ($scope.form.file.$valid && $scope.file && !$scope.file.$error) {

              // hid form upload
              $scope.canUpload = false;

              // add owner user to tree
              $scope.tree_string += " or (UsernameNode__SUB__" + $scope.userinfo.authorityName + "__SUB__" + $scope.userinfo.username + ')';
              console.log("UPLOAD");
              console.log($scope.file);
              $scope.upload($scope.file);
              $scope.tree_string = "";
            }
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
                $scope.canUpload = res;
                if(!res){
                  alert("Can't find this user Or You do not have the access permission");
                }
               // $location.path('/uploadPHR');
            })
            .error(function(err){
              isClickSearch = false;
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
                $scope.threshold = -1;
                $scope.truted_users = -1;
                $scope.tree_string = "";
                $scope.parent = ""; 
                $scope.canUpload = false;
                $scope.search_selectedAuthority = "";
                $scope.search_username  = "";
                 $scope.progressBar = 0;
      }

      $scope.cancel = function(){
        var r = confirm("Are you sure to cancel Upload Files ?");
             if(r == true) {
                // Cancle upload
                re_value();
                $scope.file.upload.abort();
                $http.post('/api/cancelUploadPHR')
        }
      };

      // upload on file select or drop
      $scope.upload = function (file) {
        var isSuccess = false;

        file.upload =  Upload.upload({
                url: 'api/uploadPHR',
                data: {'phr_owner_name': $scope.userinfo.username, file: file, 'phr_owner_authority_name': $scope.userinfo.authorityName, 
                'data_description': $scope.description,
                'confidentiality_level': $scope.con_level, 'access_policy': $scope.tree_string,
                'threshold' : $scope.threshold, 'truted_users': $scope.truted_users
              }

            })
        file.upload.then(function (resp) {
                console.log('Success ' + resp.config.data.file.name + 'uploaded. Response: ' + resp.data);
                isSuccess = true;
            }, function (resp) {
                console.log('Error status: ' + resp.status);
                $scope.file.upload.abort();
                isSuccess = false;

            }, function (evt) {
                var progressPercentage = parseInt(100.0 * evt.loaded / evt.total);
                $scope.progressBar = progressPercentage;
                //console.log('progress: ' + progressPercentage + '% ' + evt.config.data.file.name);
            })
            .finally(function(){
              if(isSuccess){
                alert("UPLOAD SUCCESS !!");

                // $scope.canUpload = false;
                // $scope.search_username = "";
                // $scope.search_selectedAuthority = "";

                // RE VALUE
                re_value();

                $location.path('/user/info');
              }
              else {
                alert("UPLOAD FAILED !!");
                $location.path('/user/info');
              }
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
        if($scope.selectedRow != null){
          $scope.addToNode("Attribute", $scope.attribute_all[$scope.selectedRow][0]);
        }
      }

      // ADD TO TREE
      $scope.addToNode = function (type, scope) {
          var title = "";
          if($scope.selectedNode != null){

            //console.log("ADD SUB NODE");
            var nodeData = $scope.selectedNode.$modelValue;
            if(type == "Username"){
              title = "User";
            }
            else if(type = "Attribute"){
              title = "Attribute";
            }
            else
              title = type;
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

  
    phrApp.controller('changeEmailController', function($scope, $http, $location, $window) {
        $scope.data = {};
        $scope.info = {};

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
            $http.post('/api/change_email', {
              email                  : $scope.data.email,
              confirm_new_passwd     : $scope.data.password,
            })
            .success(function(user){
              // No error: authentication OK
              //console.log("SUCCESS");
              isClick = false;
              $window.alert("CHANGE EMAIL SUCCESS !!")
              if(type == "Admin")
                $location.path('/admin/info');
              else if(type == "User")
                $location.path('/user/info');
            })
          }
        };

        $scope.back = function(){
          $location.path('/info');
        }
    });

    phrApp.controller('accessPermisController', function($scope, $http, $location, $window) {
        $scope.access_permission_list = {};
        $scope.selectedRow = null;
        $scope.checked = {};

        // get access permission list
        $http.post('/api/access_permission_management_list')
        .success(function(res){
            $scope.access_permission_list = res;
            //console.log(res);
        })     

        // set click row
        $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
        }

        // change location to assign
        $scope.assign = function(){
          $location.path('/user/assignPermission');
        }

        var isClick = false;

        // edit permission
        $scope.edit = function(){
          //console.log($scope.selectedRow);
          if(!isClick){
            isClick = true;
            if($scope.selectedRow != null ){
              //console.log("EDIT " + $scope.access_permission_list[$scope.selectedRow]);
              $http.post('/api/edit_access_permission', {
                row             : $scope.selectedRow,
                uploadflag      : $scope.access_permission_list[$scope.selectedRow][1],
                downloadflag    : $scope.access_permission_list[$scope.selectedRow][2],
                deleteflag      : $scope.access_permission_list[$scope.selectedRow][3]
              })
              .success(function(res){
                if(res == true){
                  //console.log("EDIT SUCCESS");
                  isClick = false;
                  $window.alert("EDIT PERMISSION SUCCESS !!")
                  $location.path('/accessPermissionManagement');
                }
              })
            }
          }
        }

        // delete access permission
        $scope.delete = function(){
          //console.log($scope.selectedRow);
          if($scope.selectedRow != null && !isClick){

            isClick = true;
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
                 isClick = false;
                 $window.alert("DELETE SUCCESS !!")
                $location.path('/accessPermissionManagement');
              }
            })
          }
        }
    });

    phrApp.controller('assignAccessPermissionController', function($scope, $http, $location, $window) {
        $scope.authorityList = {};
        $scope.assign = {};
        $scope.assign.uploadflag = false;
        $scope.assign.downloadflag = false;
        $scope.assign.deleteflag = false;

        // get authority list
        $http.post('/api/authority_name_list')
        .success(function(res){
            $scope.authorityList = res;
        })

        $scope.selectedAuthority = null;
        $scope.assign.username = null;

        var isClick = false;

        $scope.submit = function(index){
          if(($scope.assign.uploadflag || $scope.assign.downloadflag || $scope.assign.deleteflag &&
            ($scope.selectedAuthority != null && $scope.assign.username != null))  && !isClick){
            //console.log("SUCCESS");
            isClick = true;
            $http.post('/api/assign_access_permission', {
                authority : $scope.selectedAuthority,
                username : $scope.assign.username,
                uploadflag : $scope.assign.uploadflag,
                downloadflag : $scope.assign.downloadflag,
                deleteflag : $scope.assign.deleteflag,
            })
            .success(function(res){
              if(res == true){
                isClick = false;
              //  console.log("Assign SUCCESS");
                $window.alert("ASSIGN SUCCESS !!")
                $location.path('/accessPermissionManagement');
              }
            })
          }
          //else
          //  console.log("FAIL");
        }

         $scope.check = function(){
           return ($scope.assign.uploadflag || $scope.assign.downloadflag || $scope.assign.deleteflag);
         }

         $scope.back =  function(){
            $location.path('/accessPermissionManagement');
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
             };

        $scope.cancel = function(){
          var r = confirm("Are you sure to cancel download ?");
          if(r == true) {
            console.log("CANCEL");
            $http.post('/api/cancelDownloadPHR')
            .success(function(){


              re_value();
              $location.path('/downloadSelfPHR'); 
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
            console.log("SEARCH DOWNLOAD");
            isClickSearch =true;
            $http.post('/api/download_phr_list',{
                authorityName :  $scope.selectedAuthority,
                username      :  $scope.username
            })
            .success(function(res){
                isClickSearch = false;
                $scope.phr_list = res;

                if(res == false){
                  alert("CAN'T FIND USER");
                }
                else{
                  $scope.canDownload = true;
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
            $scope.canDownload = false;
            $http.post('/api/downloadPHR', {
              authorityName :  $scope.selectedAuthority,
              username      :  $scope.username,
              index         : $scope.selectedRow,
            })
            .success(function(res){

              re_value();

              //console.log("RESULT : " + res);
                  if(res){
                //  console.log("DOWNLOAD FILESS !!!");
                    $window.open('/api/downloadPHR');
                  }
                  else {
                    alert("DOWNLAOD FAILED (Decryption fail or can't verify user)");
                  }
            })
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

        $http.post('/api/delete_self_phr_list')
        .success(function(res){
            $scope.phr_list = res;
          //   console.log("DELETE LIST : " + res);
        })

        // click row
        $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
        }

        // delete phr
        $scope.delete = function(){
          $http.post('/api/deletePHR', {
            index: $scope.selectedRow
         })
        }
    });

    phrApp.controller('loginController', function($scope,$http,$location, $window, $route){
        $scope.user = {};
       var isClick = false;

        $scope.login = function(){

          if($scope.user.username == null || $scope.user.password == null ||
            $scope.user.type == null){
            $window.alert("LOGIN FAILED !!!");
              $scope.user = {};
              isClick = false;
          }
          else if(!isClick){
         //   console.log("GO LOGIN");
            isClick = true;
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
            .error(function(){
              $window.alert("LOGIN FAILED !!!");
              $window.location.reload();
            })
          }
          else{
        //   console.log("WAIT LOGIN");
          }
      };
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

        // get userinfo
        $http.get('/api/admininfo')
        .success(function(res){
            $scope.info  = res;
            //console.log("INFO " + $scope.info.attribute_list);
        })

        $scope.submit = function(){
          $http.post('/api/changeConfig',{
              audit : $scope.info.audit_server_ip_addr,
              phr   : $scope.info.phr_server_ip_addr,
              emergency : $scope.info.emergency_server_ip_addr,
              passwd : $scope.password
          })
          .success(function(res){
            if(res){
              alert("CHANGE IP SUCCESS !!");
              $location.path("/admin/info");
            }
            else{
              alert("CHANGE IP FAILED !!");
              $location.path("/admin/info");
            }
          })
        }
    });

        // create the controller and inject Angular's $scope
    phrApp.controller('changeMailServerController', function($scope, $http, $location) {
        $scope.info = {};
        $scope.password = "";
        $scope.new_passwd = "";
        $scope.confirm_passwd = "";
        $scope.changepwd = false;

        // get userinfo
        $http.get('/api/admininfo')
        .success(function(res){
            $scope.info  = res;
            //console.log("INFO " + $scope.info.attribute_list);
        })

        $scope.submit = function(){
          $http.post('/api/changemailserver',{
              mailserver : $scope.info.mail_server_url,
              authorityemail   : $scope.info.authority_email_address,
              newpasswd : $scope.new_passwd,
              confirmpasswd : $scope.confirm_passwd,
              changepwd   : $scope.changepwd,
              password    : $scope.password 
          })
          .success(function(res){
            if(res){
              alert("CHANGED SUCCESS !!");
              $location.path("/admin/info");
            }
            else{
              alert("CHANGED FAILED !!");
              $location.path("/admin/info");
            }
          })
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



          $scope.delete = function(){
            var r = confirm("Removing the attribute may affect to an attribute list of some users!!!\n" + 
              "Are you sure to remove this attribute?");
           

            if(r == true) {
               if($scope.selectedRow == -1){
                  alert("Choose row !!");
               }
               else {

                  $http.post('/api/deleteattribute',{
                    attributename : $scope.attribute_table[$scope.selectedRow][0]
                  })
                  .success(function(res){
                      if(res){
                        alert("Delete Success !!");
                        $location.path('/admin/info');
                      }
                      else {
                        alert("Delete Faill !!");
                        $location.path('/admin/info');
                      }
                  })
               }
            } 
          }
    });

    phrApp.controller('registerattributeController', function($scope, $http, $location) {
        $scope.attributename = "";
        $scope.isnumerical = false;

        // get userinfo
        $scope.submit = function(){
          $http.post('/api/registerattribute',{
            attributename : $scope.attributename,
            isnumerical   : $scope.isnumerical
          })
          .success(function(res){
              if(res){
                alert("Register Success !!");
                $location.path('/admin/info');
              }
              else {
                alert("Register Faill !!");
                $location.path('/admin/info');
              }
          })
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
        //if(!isClick){

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
                 start_day_index       : $scope.Date.startDate.getDate(), 
                 start_hour_index      : $scope.Date.startTime.getHours(), 
                 start_minute_index    : $scope.Date.startTime.getMinutes(), 
                 end_year_index        : $scope.Date.endDate.getFullYear(), 
                 end_month_index       : $scope.Date.endDate.getMonth(), 
                 end_day_index         : $scope.Date.endDate.getDate(), 
                 end_hour_index        : $scope.Date.endTime.getHours(), 
                 end_minute_index      : $scope.Date.endTime.getMinutes() 
               })
               .success(function(res){
                 // No error: authentication OK
                 //console.log("SUCCESS");
                 $scope.logs = res;
                 $scope.bigTotalItems = $scope.logs.length;
                 console.log($scope.bigTotalItems);
                 $scope.chooseTable = $scope.transaction_log_type;
                 isClick = false;
                 $location.path('/admin/transaction');
               })
             //}
           }
           else {
             $http.post('/api/admin_transaction_auditing', {
               allFlag               : $scope.allFlag,
               transaction_log_type  : $scope.transaction_log_type
             })
             .success(function(res){
               // No error: authentication OK
               //console.log("SUCCESS");
               $scope.logs = res;
               $scope.chooseTable = $scope.transaction_log_type;
               $scope.bigTotalItems = $scope.logs.length;
               console.log($scope.bigTotalItems);
               isClick = false;
               $location.path('/admin/transaction');
             })
           }
         //}
      }

    });

    phrApp.controller('adminManagementController', function($scope, $http, $location) {
        $scope.admin_list = {};
        $scope.selectedRow = -1;

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
            if($scope.selectedRow == -1){
              alert("Choose row !!");
            }
            else {
              $http.post('/api/initeditadmin',{
                username : $scope.admin_list[$scope.selectedRow][0],
                email : $scope.admin_list[$scope.selectedRow][1]
              })
              .success(function(res){
                if(res){
                  $location.path('/admin/editadmin');
                }
                else {
                  $location.path('/admin/editadmin');
                }
              })
            }
          }

          $scope.delete = function(){
            var r = confirm("Removing the attribute may affect to an attribute list of some users!!!\n" + 
              "Are you sure to remove this attribute?");
           
            if(r == true) {
               if($scope.selectedRow == -1){
                  alert("Choose row !!");
               }
               else {

                  $http.post('/api/deleteadmin',{
                    username : $scope.admin_list[$scope.selectedRow][0]
                  })
                  .success(function(res){
                      if(res){
                        alert("Delete Success !!");
                        $location.path('/admin/info');
                      }
                      else {
                        alert("Delete Faill !!");
                        $location.path('/admin/info');
                      }
                  })
               }
            } 
          }

          $scope.reset = function(){
            var r = confirm("Removing the attribute may affect to an attribute list of some users!!!\n" + 
              "Are you sure to remove this attribute?");
           

            if(r == true) {
               if($scope.selectedRow == -1){
                  alert("Choose row !!");
               }
               else {
                  $http.post('/api/resetpasswordadmin',{
                    username : $scope.admin_list[$scope.selectedRow][0]
                  })
                  .success(function(res){
                      if(res){
                        alert("Reset Password Success !!");
                        $location.path('/admin/info');
                      }
                      else {
                        alert("Reset Password Faill !!");
                        $location.path('/admin/info');
                      }
                  })
               }
            } 
          }
    });

    phrApp.controller('registerAdminController', function($scope, $http, $location) {
        $scope.username = "";
        $scope.email = "";

        // get userinfo
        $scope.submit = function(){
          $http.post('/api/registeradmin',{
            username : $scope.username,
            email   : $scope.email
          })
          .success(function(res){
              if(res){
                alert("Register Success !!");
                $location.path('/admin/info');
              }
              else {
                alert("Register Faill !!");
                $location.path('/admin/info');
              }
          })
        }
    });

    phrApp.controller('editAdminController', function($scope, $http, $location) {
        $scope.username = "";
        $scope.email = "";

        $http.post('/api/info_editadmin')
        .success(function(res){
          $scope.username = res.username;
          $scope.email = res.email;
        })

        // get userinfo
        $scope.submit = function(){
          $http.post('/api/editadmin',{
            username : $scope.username,
            email   : $scope.email
          })
          .success(function(res){
              if(res){
                alert("Edit Success !!");
                $location.path('/admin/info');
              }
              else {
                alert("Edit Faill !!");
                $location.path('/admin/info');
              }
          })
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
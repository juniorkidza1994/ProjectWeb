'use strict';

    // create the module and name it scotchApp
    	// also include ngRoute for all our routing needs

    var myClass;

    var scotchApp = angular.module('scotchApp', ['ngResource', 'ngRoute', 'ngFileUpload', 'ui.tree'])

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
          //console.log("LOGIN");
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

      .when('/uploadPHR', {
        templateUrl : 'uploadPHR.html',
        controller: 'uploadPHRController',
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
    scotchApp.controller('infoController', function($scope, $http, $location) {
        $scope.info = {};

        // get userinfo
        $http.get('/api/userinfo')
        .success(function(res){
            $scope.info  = res;
            //console.log("INFO " + $scope.info.attribute_list);
        })
    });

    scotchApp.controller('changePwdController', function($scope, $http, $location) {
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
              $location.path('/info');
            })
          }
        };

        $scope.cancle = function(){
          $location.path('/info');
        }
    });

    scotchApp.controller('uploadPHRController', ['$scope', 'Upload' , '$http' , '$location' , function ($scope, Upload, $http, $location) {
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

        var isClick = false;

        // upload later on form submit or something similar
        $scope.submit = function() {
          if(!isClick){

            isClick = true;
          // call dfs function
            $scope.dfs($scope.tree);

           // console.log("TREE STRING" + $scope.tree_string);

            // validation tree
            if(!($scope.tree.length != 0 &&  $scope.description != "" && $scope.con_level != "") && 
              !($scope.con_level == "Restricted level" && $scope.threshold > 0 && $scope.truted_users > 0)){
                console.log("WRONG TREE");
              isClick = false;
            }

            // vaildation file & form
            else if ($scope.form.file.$valid && $scope.file && !$scope.file.$error) {

              // add owner user to tree
              $scope.tree_string += " or (UsernameNode__SUB__" + $scope.userinfo.authorityName + "__SUB__" + $scope.userinfo.username + ')';
              console.log("UPLOAD");
              console.log($scope.file);
              $scope.upload($scope.file);
              $scope.tree_string = "";
              isClick = false;
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
                $scope.canUpload = res;
               // $location.path('/uploadPHR');
            })
          }
      }

      // upload on file select or drop
      $scope.upload = function (file) {
            var isSuccess = false;

            Upload.upload({
                url: 'api/uploadPHR',
                data: {file: file, 'phr_owner_authority_name': $scope.userinfo.authorityName, 
                'phr_owner_name': $scope.userinfo.username, 'data_description': $scope.description,
                'confidentiality_level': $scope.con_level, 'access_policy': $scope.tree_string,
                'threshold' : $scope.threshold, 'truted_users': $scope.truted_users
              }

            }).then(function (resp) {
                console.log('Success ' + resp.config.data.file.name + 'uploaded. Response: ' + resp.data);
                isSuccess = true;
            }, function (resp) {
                console.log('Error status: ' + resp.status);
            }, function (evt) {
                var progressPercentage = parseInt(100.0 * evt.loaded / evt.total);
                console.log('progress: ' + progressPercentage + '% ' + evt.config.data.file.name);
            })
            .finally(function(){
              if(isSuccess){
                alert("UPLOAD SUCCESS !!");

                $scope.canUpload = false;
                $scope.search_username = "";
                $scope.search_selectedAuthority = "";

                $location.path('/uploadPHR');
              }
            });
       
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

  
    scotchApp.controller('changeEmailController', function($scope, $http, $location, $window) {
        $scope.data = {};
        $scope.info = {};

        // get userinfo
        $http.get('/api/userinfo')
        .success(function(res){
            $scope.info  = res;
            $scope.data.email = $scope.info.email_address;
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
              $location.path('/info');
            })
          }
        };

        $scope.cancle = function(){
          $location.path('/info');
        }
    });

    scotchApp.controller('accessPermisController', function($scope, $http, $location, $window) {
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
          $location.path('/assignPermission');
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

    scotchApp.controller('assignAccessPermissionController', function($scope, $http, $location, $window) {
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
    });

    scotchApp.controller('downloadController', function($scope, $http, $location, $window) {
        $scope.phr_list = {};
        $scope.selectedRow = null;
        $scope.selectedAuthority = "";
        $scope.username = "";
        $scope.authorityList = "";

        console.log("PHR LIST : " + $scope.phr_list);

        // get authority_name_list
        $http.post('/api/authority_name_list')
        .success(function(res){
            $scope.authorityList = res;
        })

        // click row
        $scope.setClickedRow = function(index){
            $scope.selectedRow = index;
        }

        var isClick = false;

        var isClickSearch = false;

        // search
        $scope.search = function(){
          if(!isClickSearch){
            console.log("SEARCH DOWNLOAD");
            isClickSearch =true;
            $http.post('/api/download_self_phr_list',{
                authorityName :  $scope.selectedAuthority,
                username      :  $scope.username
            })
            .success(function(res){
                isClickSearch = false;
                $scope.phr_list = res;
                console.log($scope.phr_list);
                //$location.path('/downloadSelfPHR');
            })
          }
        }

        // open download window
        $scope.download = function(){
          if(!isClick){
            $http.post('/api/downloadPHR', {
              authorityName :  $scope.selectedAuthority,
              username      :  $scope.username,
              index: $scope.selectedRow,
              myClass: myClass
            })
            .success(function(res){
              //console.log("RESULT : " + res);
                  if(res){
                //  console.log("DOWNLOAD FILESS !!!");
                    $window.open('/api/downloadPHR');
                  }
            })
          }
        }
    });

    scotchApp.controller('deleteController', function($scope, $http, $location) {
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

    scotchApp.controller('loginController', function($scope,$http,$location, $window){
        $scope.user = {};
       var isClick = false;

        $scope.login = function(){
          if(!isClick){
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
              $location.path('/info');

            })
            .error(function(){
              $window.alert("LOGIN FAILED !!!");
              $scope.user = {};
              isClick = false;
            });
          }
          else{
        //   console.log("WAIT LOGIN");
          }
      };
    });

    scotchApp.controller('errorController', function($scope) {
        $scope.message = "Error Don't have this page";
        console.log("TESTTTT ");
    });

    // CLICK ANYWHERE
    scotchApp.directive('clickOff', function($parse, $document) {
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
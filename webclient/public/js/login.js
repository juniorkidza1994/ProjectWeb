angular.module("loginApp", [])
.controller('mainCtrl', function($scope,$http){
	$scope.account = {};

	$scope.login = function(){
		$http.post('/login',$scope.account).success(function(data){
			console.log($scope.account);

		});
	}
})
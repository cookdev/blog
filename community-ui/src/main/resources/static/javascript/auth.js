/**
 * Created by Hahn on 2015-11-04.
 */
"use strict";

(function() {
    App.auth = {};
    App.auth.isAuthenticated = false;
    App.auth.user = {};
    App.auth.credentials = {};
}).call(this);

App.auth.authenticate = function(credentials, callback) {

    var headers = credentials
        ? { authorization : "Basic " + btoa(credentials.username + ":" + credentials.password) }
        : {};

    headers['X-Requested-With'] = 'XMLHttpRequest';
    headers['X-XSRF-TOKEN'] = App.auth.getCookie('XSRF-TOKEN');

    $.ajax({
        async: false,
        url: 'hello',
        method: 'GET',
        headers : headers
    }).success(function(data) {
        App.auth.user = data;
        App.auth.changeState(true);
        callback && callback(true);
    }).error(function() {
        App.auth.changeState(false);
        callback && callback(false);
        alert("로그인 실패");
    });

}

App.auth.login = function() {
    App.auth.authenticate(App.auth.credentials, function(authenticated) {
        var referrer = App.comm.getParameterByName('referrer');

        if('forum' === referrer){
            window.location.href = "https://forum.ssc.com";
        }
<<<<<<< Updated upstream
        else if('blog' === referrer){
            window.location.href = "https://blog.ssc.com";
=======
        else if('blog' === referer){
            window.location.href = "http://localhost:9090";
>>>>>>> Stashed changes
        }
        else {
            window.location.hash = "";
        }
        
    })
};

// 세션에서 내 인증정보를 다시 읽어온다.
App.auth.whoAmI = function(){
    var headers = {};
    //headers['X-Requested-With'] = 'XMLHttpRequest';
    headers['X-XSRF-TOKEN'] = App.auth.getCookie('XSRF-TOKEN');

    $.ajax({
        async: false,
        url: 'who-am-i',
        method: 'GET',
        headers : headers
    }).success(function(data) {
        App.auth.user = data;
        App.auth.changeState(true);
    }).error(function() {
        App.auth.changeState(false);
    });
}

App.auth.logout = function() {
    var headers = {};
    headers['X-XSRF-TOKEN'] = App.auth.getCookie('XSRF-TOKEN');
    $.ajax({
        url: 'logout',
        method: 'GET',
        headers : headers
    }).success(function(data) {
        App.auth.changeState(false);
        alert("로그아웃 되었습니다.");
    }).error(function(data) {
        console.log("Logout failed")
        App.auth.changeState(false);
        alert("로그아웃 실패");
    });

    // 생성된 화면 새로 생성
    App.router.destory();
    App.router = new Router();
    App.router.handlePortalMainView();

    $("#logout").on('click', function(e){
        App.auth.logout()
    });

}

App.auth.changeState = function(isAuthenticated){

    App.auth.isAuthenticated = isAuthenticated;

    App.auth.applyState();
}

App.auth.applyState = function(){
    // 로그인 여부
    var isAuthenticated = App.auth.isAuthenticated;
    if(isAuthenticated){
        $('[data-show="!authenticated"]').hide();
        $('[data-show="authenticated"]').show();
    }else{
        $('[data-show="!authenticated"]').show();
        $('[data-show="authenticated"]').hide();
    }

    // 권한에 따른 Element 제어
    $('[data-authority]').hide();
    var roles = App.auth.user.roles ? App.auth.user.roles : [];
    var isAdmin = false;
    if($.inArray('ROLE_ADMIN', roles) > -1){
        $('[data-authority="ROLE_ADMIN"]').show();
    }
}

App.auth.getCookie = function getCookie(c_name)
{
    var i,x,y,ARRcookies=document.cookie.split(";");
    for (i=0;i<ARRcookies.length;i++)
    {
        x=ARRcookies[i].substr(0,ARRcookies[i].indexOf("="));
        y=ARRcookies[i].substr(ARRcookies[i].indexOf("=")+1);
        x=x.replace(/^\s+|\s+$/g,"");
        if (x==c_name)
        {
            return unescape(y);
        }
    }
}

var oldSync = Backbone.sync;
Backbone.sync = function(method, model, options){
    options || (options = {});

    if (!options.crossDomain) {
        options.crossDomain = true;
    }

    if (!options.xhrFields) {
        options.xhrFields = {withCredentials:false};
    }

    options.beforeSend = function (xhr) {

        // Spring Security에 CSRF Filter를 추가하여
        // 브라우져 쿠키에 CSRF Token을 저장했다.
        // 이를 X-XSRF-TOKEN 헤더에 넣어 요청을 해야 정상적으로 인증에 성공한다.
        xhr.setRequestHeader('X-XSRF-TOKEN',App.auth.getCookie('XSRF-TOKEN'));

        // 로그인 되지 않았을 때,
        // X-Requested-With 헤더가 없다면 Spring Security는 WWW-Authenticate 헤더로 응답한다.
        // 응답에 WWW-Authenticate 헤더가 있으면 브라우져는 기본 인증 Dialog를 띄운다.
        // 이를 방지하기 위해 X-Requested-With: XMLHttpRequest를 헤더에 세팅해준다.
        if(!App.auth.isAuthenticated){
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        }
    }

    options.statusCode = {
        // Unauthorized
        401: function() {
            // 인증실패, 로그인 페이지로 이동
            if(confirm('권한이 없습니다. 로그인 하시겠습니까?')){
                window.location.hash = 'login';
            }
        },
        // Forbidden
        403: function(){
            alert("해당 API에 권한이 없습니다.");
        },

        // Gone
        410: function(){
            // HTTP 세션이 만료됨.
            if(confirm('세션이 만료되었습니다. 로그인 하시겠습니까?')){
                window.location.hash = 'login';
            }else{
                App.auth.logout();
            }
        }
    }
    return oldSync(method, model, options);
};
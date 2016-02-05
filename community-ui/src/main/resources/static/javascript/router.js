/**
 * Created by Hahn on 2015-11-04.
 */
Backbone.Router.prototype.beforeRoute = function () {};
Backbone.Router.prototype.routeCompleted = function () {};
Backbone.Router.prototype.destory = function () {};
Backbone.Router.prototype.route = function (route, name, callback) {
    if (!_.isRegExp(route)) route = this._routeToRegExp(route);
    if (_.isFunction(name)) {
        callback = name;
        name = '';
    }
    if (!callback) callback = this[name];

    var router = this;

    Backbone.history.route(route, function(fragment) {
        var args = router._extractParameters(route, fragment);

        router.beforeRoute.apply(router, arguments);
        callback && callback.apply(router, args);
        router.routeCompleted.apply(router, arguments);

        router.trigger.apply(router, ['route:' + name].concat(args));
        router.trigger('route', name, args);
        Backbone.history.trigger('route', router, name, args);
    });
    return this;
};

// Drawing Portal Main
// Set Router
var Router = Backbone.Router.extend({

    commonHeader: null,
    portalHeader: null,
    footer: null,
    container: null,
    portalMain: null,
    signUp: null,
    login: null,
    myPage: null,
    //passwordValidationPopup: null,
    //passwordChangePopup: null,
    privacyPolicyPopup: null,
    projectOverview: null,
    projectCore: null,
    projectCodeGenerator: null,
    projectQueryManager: null,
    projectOden: null,
    projectLogManager: null,
    projectBatch: null,
    projectIam: null,
    projectMonitoring: null,
    notice: null,
    noticeEditor: null,
    educationSchedule: null,
    searchResult: null,

    initialize: function(){
        this.commonHeader = new CommonHeaderView();
        this.portalHeader = new PortalHeaderView();
        this.footer = new FooterView();
        this.container = new ContainerView({
            el: $("#mainContents")
        });
    },

    destory: function(){
        $(".common-header").html('');
        $(".portal-header").html('');
        $("#mainContents").html('');
        $(".portal-footer").html('');
        $("#popup").html('');
    },

    routes: {
        "": "handlePortalMainView",
        "sign-up": "handlePortalSignUpView",
        "login": "handlePortalLoginView",
        "login/popup": "handlePortalLoginPopupView",
        "my-page": "handleMyPageView",
        "privacy-policy": "handlePrivacyPolicyPopupView",
        "project": "handleProjectOverviewView",
        "project/core": "handleProjectCoreView",
        "project/code-generator": "handleProjectCodeGeneratorView",
        "project/query-manager": "handleProjectQueryManagerView",
        "project/oden": "handleProjectOdenView",
        "project/log-manager": "handleProjectLogManagerView",
        "project/batch": "handleProjectBatchView",
        "project/iam": "handleProjectIamView",
        "project/monitoring": "handleProjectMonitoringView",
        "notice": "handleNoticeView",
        "notice/editor": "handleNoticeEditorView",
        "notice/editor/:noticeId": "handleNoticeEditorView",
        "education-schedule": "handleEducationScheduleView",
        "search-result/:keyword": "handleSearchResultView"

    },

    beforeRoute: function(){
        // SESSION이 존재하면, 세션에서 유저정보를 읽어온다.
        if(App.auth.getCookie("XSRF-TOKEN")){
            App.auth.whoAmI();
        }
    },

    routeCompleted: function () {
        App.auth.applyState();
    },

    handlePortalMainView: function() {
        if(this.portalMain == null){
            this.portalMain = new PortalMainView();
        }
        //this.container.contents = this.portalMain;
        this.container.render(this.portalMain);
    },
    handlePortalSignUpView: function(){
        if(this.signUp == null){
            this.signUp = new SignUpView();
        }
        //this.container.contents = this.signUp;
        this.container.render(this.signUp);
    },
    handlePortalLoginView: function(){
        if(this.login == null){
            this.login = new LoginView();
        }
        //this.container.contents = this.login;
        this.container.render(this.login);
    },
    handlePortalLoginPopupView: function(){
        if(this.container.contents == null){
            window.location.hash = 'login';
        }else{
            if(this.loginPopup == null){
                this.loginPopup = new LoginView();
            }
            var modal = new Backbone.BootstrapModal({
                content: this.loginPopup,
                title: 'Login',
                animate: true,
                allowHeaderCancel: true,
                showFooter: false,
                height: '430px'
            });
            modal.open();
        }
    },
    handleMyPageView: function(){
        if(this.myPage == null){
            this.myPage = new MyPageView();
        }
        //this.container.contents = this.myPage;
        this.container.render(this.myPage);
    },
    handlePrivacyPolicyPopupView: function(){
        var isDirectLink = false;
        if(this.privacyPolicyPopup == null){
            this.privacyPolicyPopup = new PrivacyPolicyPopupView();
        }
        if(this.container.contents == null){
            this.handlePortalMainView();
            isDirectLink = true;
        }
        var modal = new Backbone.BootstrapModal({
            content: this.privacyPolicyPopup,
            title: '개인정보 취급방침',
            animate: true,
            allowHeaderCancel: true,
            allowCancel: false,
            okText: '확인',
            template: ReadOnlyPopupTemplate
        });
        modal.open(function(){
            if(isDirectLink){
                window.location.hash = "#";
            }else{
                window.history.back();
            }
        });
    },
    handleProjectOverviewView: function(){
        if(this.projectOverview == null){
            this.projectOverview = new ProjectOverviewView();
        }
        //this.container.contents = this.projectOverview;
        this.container.render(this.projectOverview);
    },
    handleProjectCoreView: function(){
        if(this.projectCore == null){
            this.projectCore = new ProjectCoreView();
        }
        //this.container.contents = this.projectCore;
        this.container.render(this.projectCore);
    },
    handleProjectCodeGeneratorView: function(){
        if(this.projectCodeGenerator == null){
            this.projectCodeGenerator = new ProjectCodeGeneratorView();
        }
        //this.container.contents = this.projectCodeGenerator;
        this.container.render(this.projectCodeGenerator);
    },
    handleProjectQueryManagerView: function(){
        if(this.projectQueryManager == null){
            this.projectQueryManager = new ProjectQueryManagerView();
        }
        //this.container.contents = this.projectQueryManager;
        this.container.render(this.projectQueryManager);
    },
    handleProjectOdenView: function(){
        if(this.projectOden == null){
            this.projectOden = new ProjectOdenView();
        }
        //this.container.contents = this.projectOden;
        this.container.render(this.projectOden);
    },
    handleProjectLogManagerView: function(){
        if(this.projectLogManager == null){
            this.projectLogManager = new ProjectLogManagerView();
        }
        //this.container.contents = this.projectLogManager;
        this.container.render(this.projectLogManager);
    },
    handleProjectBatchView: function(){
        if(this.projectBatch == null){
            this.projectBatch = new ProjectBatchView();
        }
        //this.container.contents = this.projectBatch;
        this.container.render(this.projectBatch);
    },
    handleProjectIamView: function(){
        if(this.projectIam == null){
            this.projectIam = new ProjectIamView();
        }
        //this.container.contents = this.projectIam;
        this.container.render(this.projectIam);
    },
    handleProjectMonitoringView: function(){
        if(this.projectMonitoring == null){
            this.projectMonitoring = new ProjectMonitoringView();
        }
        //this.container.contents = this.projectMonitoring;
        this.container.render(this.projectMonitoring);

    },
    handleNoticeView: function(){
        if(this.notice == null){
            this.notice = new NoticeView();
        }
        //this.container.contents = this.notice;
        this.container.render(this.notice);
    },
    handleNoticeEditorView: function(noticeId){
        if(this.noticeEditor == null){
            this.noticeEditor = new NoticeEditorView();
        }
        this.noticeEditor.beforeRender(noticeId);
        this.container.render(this.noticeEditor);
    },
    handleEducationScheduleView: function(){
        if(this.educationSchedule == null){
            this.educationSchedule = new EducationScheduleView();
        }
        //this.container.contents = this.educationSchedule;
        this.container.render(this.educationSchedule);
    },
    handleSearchResultView: function(keyword){
        if(this.searchResult == null){
            this.searchResult = new SearchResultView();
        }
        this.searchResult.beforeRender(keyword);
        this.container.render(this.searchResult);
    }

});

// Drawing HeaderView
var CommonHeaderView =  Backbone.View.extend({
    el: $('.common-header'),
    initialize: function(){
        this.render();
    },
    render: function(){
        $(this.el).append(App.comm.getHtml('common-header.html'));
    }
});

// Drawing HeaderView
var PortalHeaderView =  Backbone.View.extend({
    el: $('.portal-header'),
    initialize: function(){
        this.render();
    },
    render: function(){
        $(this.el).append(App.comm.getHtml('portal-header.html'));
    }
});

// Drawing FooterView
var FooterView = Backbone.View.extend({
    el: $('.portal-footer'),
    initialize: function(){
        this.render();
    },
    render: function(){
        $(this.el).append(App.comm.getHtml('footer.html'));
    }

});

var ContainerView = Backbone.View.extend({
    contents: null,
    render: function(view){
        // 권한체크
        if(view.authorities){
            var viewRoles = view.authorities;
            var myRoles = App.auth.user.roles ? App.auth.user.roles : [];
            var accessable = false;
            $.each(viewRoles, function(idx){
                if($.inArray(viewRoles[idx], myRoles) > -1){
                    accessable = true;
                }
            });

            if(!accessable){
                history.back();
                return;
            }
        }

        // 기존꺼 숨김
        if(this.contents != null){
            this.contents.$el.addClass('hide');
        }
        // 화면 렌더
        this.contents = view;
        if($('#mainContents').find(this.contents.el).length === 0){
            this.$el.append(this.contents.$el);
        }else{
            this.contents.$el.removeClass('hide');
        }

        $(document).scrollTop(0);
        this.contents.render();
        return this;
    }
});

// Drawing Portal Main
var PortalMainView = Backbone.View.extend({
    el: '<div id="portal-main"></div>',
    html: 'portal-main.html',
    initialize: function(){
    },
    render: function(){
        $(this.el).html(App.comm.getHtml(this.html));

        var paramLogout = App.comm.getParameterByName('logout');
        var referrer = App.comm.getParameterByName('referrer');

        if(paramLogout == "true"){
            var headers = {};
            headers['X-XSRF-TOKEN'] = App.auth.getCookie('XSRF-TOKEN');
            $.ajax({
                url: 'logout',
                method: 'POST',
                headers : headers
            }).success(function(data) {
                if('forum' === referrer){
                    window.location.href = "https://forum.ssc.com";
                }
                else if('blog' === referrer){
                    window.location.href = "https://blog.ssc.com";
                }
                else {
                    window.location.hash = "";
                }
            }).error(function(data) {
                console.log("Logout failed")
                App.auth.changeState(false);
                alert("로그아웃 실패");
            });
        }
    }
});

var PrivacyPolicyPopupView = Backbone.View.extend({
    html: 'popup/privacy-policy-popup.html',
    initialize: function(){
    },
    render: function(){
        $(this.el).html(App.comm.getHtml(this.html));
    }
});

// Routing Views
App.router = new Router();
Backbone.history.start();

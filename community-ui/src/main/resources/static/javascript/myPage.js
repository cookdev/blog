/**
 * Created by Hahn on 2015-11-26.
 */
var MyPageModel = Backbone.Model.extend({
    urlRoot: '/user'
});
var MyPageView = Backbone.View.extend({
    el: '<div id="my-page"></div>',
    htmlPage: 'my-page.html',
    htmlStr: null,
    model: null,
    data: null,
    form: '.my-page form',
    validationModal: null,
    changeModal: null,
    passwordValidationPopupView: null,
    passwordChangePopupView: null,
    userId: null,

    initialize: function(){
        this.userId = App.auth.user.name;
        this.model = new MyPageModel({id: App.auth.user.name});
        this.getUserInfo();
    },
    render: function(){
        if(this.htmlStr == null){
            this.htmlStr = App.comm.getHtml(this.htmlPage);
        }
        $(this.el).html(this.htmlStr);

        if(this.data == null){
            this.getUserInfo();
        }else{
            this.setUser();
        }
        return this;
    },
    events: {
        'click #btnUserModify': function (e) {
            e.preventDefault();
            this.passwordValidation();
        },
        'click #btnPasswordModify': function (e) {
            e.preventDefault();
            this.passwordChange();
        },
        'click #btnUserDelete': function (e) {
            e.preventDefault();
            this.userDelete();
        },
        'click #okBtn': function(e){
            e.preventDefault();
            this.ok();
        },
        'click #backBtn': function(e){
            e.preventDefault();
            this.back();
        }
    },
    getUserInfo: function(){
        var that = this;
        this.model.fetch({
            success: function (collection, response){
                that.data = response;
                that.setUser();
            }
        });
    },
    setUser: function(){
        $('.my-page-form').find('input[name="userId"]').val(this.data.userId);
        $('.my-page-form').find('input[name="userName"]').val(this.data.userName);
        $('.my-page-form').find('input[name="email"]').val(this.data.email);
    },
    passwordValidation: function(){
        if(this.validationModal == null){
            this.passwordValidationPopupView = new PasswordValidationPopupView(this.userId, this);
            this.validationModal = new Backbone.BootstrapModal({
                content: this.passwordValidationPopupView,
                title: 'Password Confirm',
                animate: true,
                allowHeaderCancel: true,
                allowCancel: false,
                showFooter: false,
                height: '300px'
            });
        }else{
            this.passwordValidationPopupView.delegateEvents();
        }
        this.validationModal.open();
    },
    validationModalClose: function(){
        this.validationModal.close();
    },
    changeModalClose: function(){
        this.changeModal.close();
    },
    changeViewForModify: function() {

        //View mode change
        $('.my-page-form fieldset').removeProp('disabled');
        $('#btnGroupMyInfo').removeClass('hidden');

        //this.userId = $('.my-page-form').find('input[name="userId"]').val();
        //this.userName = $('.my-page-form').find('input[name="userName"]').val();
        //this.email = $('.my-page-form').find('input[name="email"]').val();
    },
    passwordChange: function(){
        if(this.changeModal == null){
            this.passwordChangePopupView = new PasswordChangePopupView(this.userId, this);
            this.changeModal = new Backbone.BootstrapModal({
                content: this.passwordChangePopupView,
                title: 'Password Change',
                animate: true,
                allowHeaderCancel: true,
                allowCancel: false,
                showFooter: false,
                height: '350px'
            });
        }else{
            this.passwordChangePopupView.delegateEvents();
        }
        this.changeModal.open();
    },
    userDelete: function() {
        if (confirm("탈퇴하시겠습니까?")){
            this.model.set(this.userId);
            this.model.destroy({
                contentType: 'application/json',
                dataType: 'text',
                success: function () {
                    alert('탈퇴가 완료되었습니다');
                    window.location.hash = "login";
                    this.userId = null;
                    $('.my-page-form').find('input[name="userId"]').val('');
                    $('.my-page-form').find('input[name="userName"]').val('');
                    $('.my-page-form').find('input[name="email"]').val('');
                },
                error: function () {
                    alert("Error");
                }
            });
        }
    },
    ok: function(){
        var that = this;
        var data = this.$el.find(this.form).serializeObject();
        this.model.set(data);
        this.model.save({}, {
            success: function(a,b,c){
                alert('회원정보가 수정되었습니다');
                that.back();
                that.getUserInfo();
            },
            error: function(a,b,c){
                alert("Error");
            }
        });
    },
    back: function(){
        $('.my-page-form').find('input[name="userId"]').val(this.userId);
        $('.my-page-form').find('input[name="userName"]').val(this.data.userName);
        $('.my-page-form').find('input[name="email"]').val(this.data.email);

        $('.my-page-form fieldset').prop('disabled', true);
        $('#btnGroupMyInfo').addClass('hidden');

        //this.userId = null;
        //this.userName = null;
        //this.email = null;
    }
});

var PasswordValidationModel = Backbone.Model.extend({
    url: '/user/password/validation'
});
var PasswordValidationPopupView = Backbone.View.extend({
    //el: '#popup',
    model: null,
    htmlPage: 'popup/password-validation.html',
    htmlStr: null,
    form: '.password-validation .password-form',
    userId: null,
    myPage: null,

    initialize: function(userId, parent){
        this.myPage = parent;
        this.userId = userId;
        this.model = new PasswordValidationModel({id: userId});
    },
    render: function(){
        if(this.htmlStr == null){
            this.htmlStr = App.comm.getHtml(this.htmlPage);
        }
        $(this.el).html(this.htmlStr);

        this.$el.find(this.form).find('input[name="userId"]').val(this.userId);
        $('.password-validation input[name="password"]').focus();
        return this;
    },
    events: {
        'click #validatePassword': function (e) {
            e.preventDefault();
            this.passwordValidation();
        },
        'click #closePopup': function (e) {
            e.preventDefault();
            this.closePopup();
        }
    },
    passwordValidation: function(){
        var that = this;
        var data = this.$el.find(this.form).serializeObject();
        this.model.set(data);
        this.model.save({},{
            success: function(a,b,c){
                alert("정상적으로 인증되었습니다");
                that.closePopup(true);
            },
            error: function(a,b,c){
                alert("잘못된 패스워드 입니다");
                $('.password-validation input[name="password"]').val('');
                $('.password-validation input[name="password"]').focus();
            },
            type: "POST"
        });
    },
    closePopup: function(isSuccess){
        if(isSuccess){
            $('.password-validation input[name="password"]').val('');
            $('.password-validation input[name="password"]').focus();
            this.myPage.changeViewForModify();
        }
        this.myPage.validationModalClose();
    }
});

var PasswordChangeModel = Backbone.Model.extend({
    url: '/user/password/change'
});
var PasswordChangePopupView = Backbone.View.extend({
    //el: '#popup',
    model: null,
    htmlPage: 'popup/password-change.html',
    htmlStr: null,
    form: '.password-change .password-form',
    userId: null,
    myPage: null,

    initialize: function(userId, parent){
        this.myPage = parent;
        this.userId = userId;
        this.model = new PasswordChangeModel({id: userId});
    },
    render: function(){
        if(this.htmlStr == null){
            this.htmlStr = App.comm.getHtml(this.htmlPage);
        }
        $(this.el).html(this.htmlStr);

        this.$el.find(this.form).find('input[name="userId"]').val(this.userId);
        $('.password-change input[name="existPassword"]').focus();
        return this;
    },
    events: {
        'click #changePassword': function (e) {
            e.preventDefault();
            this.passwordChange();
        },
        'click #closePopup': function (e) {
            e.preventDefault();
            this.closePopup();
        }
    },
    passwordChange: function(){
        var that = this;
        var existPassword = $('.password-change input[name="existPassword"]').val();
        var password = $('.password-change input[name="password"]').val();
        var confirmPassword = $('.password-change input[name="confirmPassword"]').val();

        if(existPassword != '') {
            if (password == confirmPassword && (password != '' && confirmPassword != '')) {
                var data = this.$el.find(this.form).serializeObject();
                this.model.set(data);
                this.model.save({}, {
                    success: function (a, b, c) {
                        alert("정상적으로 변경되었습니다");
                        that.closePopup(true);
                    },
                    error: function (model, response) {
                        alert(response.responseJSON.message);
                        $('.password-change input[name="existPassword"]').val('');
                        $('.password-change input[name="password"]').val('');
                        $('.password-change input[name="confirmPassword"]').val('');

                        $('.password-change input[name="existPassword"]').focus();
                    },
                    type: "PUT"
                });
            } else if(password == '') {
                alert("신규 패스워드를 입력하세요");
                $('.password-change input[name="password"]').focus();
            } else if(confirmPassword == '') {
                alert("신규 패스워드 확인을 입력하세요");
                $('.password-change input[name="confirmPassword"]').focus();
            } else if(password != confirmPassword){
                alert("신규 패스워드가 일치하지 않습니다");
            }else{
                alert("패스워드를 확인해주세요");
            }
        }else{
            alert("현재 패스워드를 입력하세요.");
            $('.password-change input[name="existPassword"]').focus();
        }
    },
    closePopup: function(isSuccess){
        if(isSuccess) {
            $('.password-change input[name="existPassword"]').val('');
            $('.password-change input[name="password"]').val('');
            $('.password-change input[name="confirmPassword"]').val('');

            $('.password-change input[name="existPassword"]').focus();
        }
        this.myPage.changeModalClose();
    }
});

$.fn.serializeObject = function ( ) {
    var modelData = {};
    var formArray = this.find('input');
    $.each(formArray, function(idx, obj){
        var $obj = $(this), value;

        if('checkbox' === $obj.attr('type')){
            value = $obj.is(':checked');
        }else{
            value = $obj.val();
        }
        modelData[$obj.attr('name')] = value;
    })
    return modelData;
};

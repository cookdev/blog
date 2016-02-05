var SignUpModel = Backbone.Model.extend({
    urlRoot: 'user',
    validation: {
        userId: [
            {
                required: true,
                msg: 'ID를 입력하십시오. '
            },{
                isExistedID: false,
                msg: '이미 존재하는 ID 입니다.'
            }
        ],
        userName: [
            {
                required: true,
                msg: '사용자 이름을 입력하십시오.'
            },{
                isExistedUserName: false,
                msg: '이미 존재하는 사용자 이름입니다.'
            }
        ],
        email: {
            required: true,
            pattern: 'email',
            msg: '이메일 주소를 입력하십시오.'
        },
        password: {
            minLength: 4,
            msg: '패스워드는 최소 10자리 이상이어야 합니다.'
        },
        repeatPassword: {
            equalTo: 'password',
            msg: '패스워드가 일치하지 않습니다.'
        },
        isPrivacyPolicyAgreed: {
            isAgreed: true,
            msg: '개인정보 수집 및 이용 정책에 동의해 주십시오'
        },
        isLicenseAgreed: {
            isAgreed: true,
            msg: '라이선스 정책에 동의해 주십시오'
        }
    }
});

// Drawing SignUp View
var SignUpView = Backbone.View.extend({
    el: '<div id="sign-up"></div>',
    model: new SignUpModel(),
    form: '.sign-up form',
    html: 'sign-up.html',

    initialize: function(){
        Backbone.Validation.bind(this);
    },
    render: function(){
        $(this.el).html(App.comm.getHtml(this.html));
    },

    events: {
        'click #signUpBtn': function (e) {
            e.preventDefault();
            this.signUp();
        }
    },

    signUp: function () {
        var data = this.$el.find(this.form).serializeObject();
        this.model.set(data);
        if(this.model.isValid(true)){
            this.model.save({}, {
                success: function(model, response){
                    alert('회원가입이 완료되었습니다. 로그인 페이지로 이동합니다.');
                    window.location.hash = "login";
                },
                error: function(model, response){
                    alert(response.responseJSON.message);
                }
            });
        }
    },

    remove: function() {
        // Remove the validation binding
        // See: http://thedersen.com/projects/backbone-validation/#using-form-model-validation/unbinding
        Backbone.Validation.unbind(this);
        return Backbone.View.prototype.remove.apply(this, arguments);
    }
});

// https://github.com/hongymagic/jQuery.serializeObject
//$.fn.serializeObject = function () {
//    "use strict";
//    var a = {}, b = function (idx, obj) {
//        var d = a[obj.name];
//        "undefined" != typeof d && d !== null ? $.isArray(d) ? d.push(obj.value) : a[obj.name] = [d, obj.value] : a[obj.name] = obj.value
//    };
//    return $.each(this.serializeArray(), b);
//};

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
}

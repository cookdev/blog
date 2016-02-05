var LoginModel = Backbone.Model.extend({
    validation: {
        username: [
            {
                required: true,
                msg: 'ID를 입력하십시오.'
            },{
                isExistedID: false,
                msg: '이미 존재하는 ID입니다.'
            }
        ]
    }
});

// Drawing Login View
var LoginView = Backbone.View.extend({
    el: '<div id="login"></div>',
    model: new LoginModel(),
    form: '.login form',
    html: 'login.html',

    initialize: function(){
        Backbone.Validation.bind(this);
    },
    render: function(){
        $(this.el).html(App.comm.getHtml(this.html));
    },

    events: {
        'click #loginBtn': function (e) {
            e.preventDefault();
            this.login();
        },
        'keydown .login-form': function(e) {
            if (e.keyCode == 13){
                e.preventDefault();
                this.login();
            }
        }
    },

    login: function () {
        var data = this.$el.find(this.form).serializeObject();
        App.auth.credentials = {username:data.username, password:data.password};
        App.auth.login();
        //data.password = sha256_digest(data.password);
        //this.model.set(data);

        // Check if the model is valid before saving
        // See: http://thedersen.com/projects/backbone-validation/#methods/isvalid
        //if(this.model.isValid(true)){
        //    this.model.save({},{
        //        beforeSend: function(xhr){
        //            xhr.setRequestHeader('Authorization', ("Basic ".concat(new App.comm.Base64().encode('auth:authSecret'))));
        //            xhr.setRequestHeader('Content-Type', "application/x-www-form-urlencoded");
        //            //xhr.setRequestHeader('X-XSRF-TOKEN', App.comm.getCookie('XSRF-TOKEN'));
        //        },
        //        success: function(a,b,c){
        //            alert("정상적으로 인증되었습니다.");
        //            that.closePopup(true);
        //        },
        //        error: function(a,b,c){
        //            alert("잘못된 Password 입니다.");
        //            $('.password-validation input[name="password"]').val('');
        //            $('.password-validation input[name="password"]').focus();
        //        },
        //        type: "POST"
        //    });
        //}
        //$.ajax({
        //    url: 'http://localhost:8888/uaa/oauth/token',
        //    method: 'post',
        //    data: "grant_type=password&username=anyframe&password=45fdf7f2b79f473d128704969032905657056d9a8733ff961c75b1a21cc5ca8f",
        //    headers: {
        //        "Authorization": 'Basic YXV0aDphdXRoU2VjcmV0',
        //        "Content-Type": "application/x-www-form-urlencoded",
        //        "Accept": "application/json"
        //    }
        //}).success(function (data, textStatus, jqXHR) {
        //    debugger;
        //}).error(function (jqXHR,  textStatus,  errorThrown){
        //    debugger;
        //})

    },

    remove: function() {
        // Remove the validation binding
        // See: http://thedersen.com/projects/backbone-validation/#using-form-model-validation/unbinding
        Backbone.Validation.unbind(this);
        return Backbone.View.prototype.remove.apply(this, arguments);
    }
});
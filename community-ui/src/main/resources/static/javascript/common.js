/**
 * Created by Hahn on 2015-11-04.
 */
"use strict";

(function() {

    // this === window
    this.App = {};
    this.App.comm = {};
    this.App.var = {};

}).call(this);

$(document).ready(function(){

    var host = $(location).attr("host");
    if (host.match("localhost")){
        App.comm.rootBlog = "http://localhost:9090/anyblog";
        App.comm.rootForum = "http://localhost:9090/anyblog";
    }

    // Dropdown 활성화시 Collapse 안 닫히는 현상 컨트롤
    $('.dropdown').on('show.bs.dropdown', function () {
        $('#navbar-collapse').collapse('hide')
    });

    $('input[type="checkbox"]').on('change', function(e){
        if($(e.target).is(':checked')){
            $(e.target).val('on');
        }else{
            $(e.target).val('off');
        }
    });

    /* 반응형WEB 구현을 위해
     * Window Resize에 따른 주요 컴포넌트 CSS조정 */
    $(window).on('resize', function WriteScreen(){
        var width = $(document).width();
        var height = $(document).height();

        // 공통헤더 Collapse 접기(.in 제거)
        $('#navbar-collapse').collapse('hide');

        // 공통네비게이션 검색창
        //if($('.navbar-form input')){
        //    if (width < 883){
        //        $('.navbar-form input').addClass('hide-with-animation');
        //    }else{
        //        $('.navbar-form input').removeClass('hide-with-animation');
        //    }
        //}

        // 팝업
        if($('.modal-body')){
            if(width < 1140){
                $('.modal-body').css('height', window.innerHeight - 125 + 'px');
            }else{
                $('.modal-body').css('height', window.innerHeight - 165 + 'px');
            }
        }
    });

    $("#logout").on('click', function(e){
        App.auth.logout()
    });
});

_.extend(Backbone.Validation.callbacks, {
    valid: function (view, attr, selector) {
        var $el = view.$('[name=' + attr + ']'),
            $group = $el.closest('.form-group');
        var dataValidateType = $el.attr('data-validate-type');

        if('text' === dataValidateType) {
            $group.removeClass('has-error');
            $group.find('.help-block').html('').addClass('hidden');
        }
        else if ('checkbox' === dataValidateType){
            //$el.parents('.checkbox-wrapper').removeClass('error');
            //$el.parents('.checkbox-wrapper').find('.error-block').html('').addClass('hidden');
            $group.removeClass('has-error');
            $group.find('.help-block').html('').addClass('hidden');
        }
    },
    invalid: function (view, attr, error, selector) {
        var $el = view.$('[name=' + attr + ']'),
            $group = $el.closest('.form-group');
        var dataValidateType = $el.attr('data-validate-type');

        if('text' === dataValidateType){
            $group.addClass('has-error');
            $group.find('.help-block').html(error).removeClass('hidden');
        }
        else if ('checkbox' === dataValidateType){
            //$el.parents('.checkbox-wrapper').find('.panel').addClass('error');
            //$el.parents('.checkbox-wrapper').find('.error-block').html(error).removeClass('hidden');
            $group.addClass('has-error');
            $group.find('.help-block').html(error).removeClass('hidden');
        }
    }
});

_.extend(Backbone.Validation.validators, {
    isAgreed: function(value, attr, customValue, model) {
        if(value !== customValue){
            return 'error';
        }
    },
    isExistedID: function(value, attr, customValue, model) {
        var isExistedIDAtRestAPIServer = (function(){
            if('admin' === value){
                return true;
            }
            return false;
        })();
        if(isExistedIDAtRestAPIServer){
            return 'error';
        }
    },
    isExistedUserName: function(value, attr, customValue, model) {
        var isExistedUserNameAtRestAPIServer = (function(){
            if('admin' === value){
                return true;
            }
            return false;
        })();
        if(isExistedUserNameAtRestAPIServer){
            return 'error';
        }
    }
});
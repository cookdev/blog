var Notice = Backbone.Model.extend({
    idAttribute: 'noticeId',
    initialize: function () {
    },
    constructor: function (attributes, options) {
        Backbone.Model.apply(this, arguments);
    },
    // urlRoot 변경
    urlRoot: 'notice/portal-notice/notice'
});

var NoticeCollection = Backbone.PageableCollection.extend({
    model: Notice,
    url: "notice/portal-notice/notices",

    // Paginator Options
    mode: "server",
    state: {
        pageSize: 4,
        firstPage: 0,
        currentPage: 0
    },
    queryParams: {
        pageSize: "pageSize",
        currentPage: "currentPage"
    }
});

var renderNoticeItems = function (collection) {
    _.each(collection.models, function (model) {
        $('#noticeItems').append(noticeItemTemplate(model.toJSON()));
    });

    $("#noticeItems > .list-item .content").readmore({
        collapsedHeight: 50,
        moreLink: '<div class="btn-group btn-group-justified" role="group" aria-label="readMore-btn-group"> ' +
        ' <a href="#" class="btn btn-default" role="button">더보기</a>' +
        '</div>',
        lessLink: '<div class="btn-group btn-group-justified" role="group" aria-label="readMore-btn-group"> ' +
        ' <a href="#" class="btn btn-default" role="button">접기</a>' +
        '</div>'
    });
};

var NoticeView = Backbone.View.extend({
    el: '<div id="notice"></div>',
    htmlPage: 'notice.html',
    htmlStr: null,
    noticeCollection: null,

    initialize: function() {
    },
    events: {
        'click .notice-update-editor': function(){
            window.location.hash = 'notice/editor';
        }
    },
    render: function(){
        this.unbind(this.noticeCollection);
        this.noticeCollection = new NoticeCollection();
        this.delegateEvents();

        if(this.htmlStr == null){
            this.htmlStr = App.comm.getHtml(this.htmlPage);
        }
        $(this.el).html(this.htmlStr);

        this.getFirstNotices();
    },
    infinitePaging: function(e){
        var currentRoute = Backbone.history.getFragment();
        if($(window).scrollTop() + $(window).height() == $(document).height()) {
            if(currentRoute == "notice") {
                e.data.getNextNotices();
            }
        }
    },
    getFirstNotices: function() {
        var self = this;
        this.noticeCollection.getFirstPage({
            success: function (collection, response, options){
                if (options.xhr.status == 200) {
                    renderNoticeItems(collection);
                    // Infinite Scroll Event binding
                    $(window).on('scroll', null, self, self.infinitePaging);
                } else if (options.xhr.status == 204) {
                    $(window).unbind('scroll', self.infinitePaging);
                }
            }
        });
    },
    getNextNotices: function(){
        var self = this;
        this.noticeCollection.getNextPage({
            success: function (collection, response, options) {
                if (options.xhr.status == 200) {
                    renderNoticeItems(collection);
                } else if (options.xhr.status == 204) {
                    $(window).unbind('scroll', self.infinitePaging);
                }
            }
        });
    }
});
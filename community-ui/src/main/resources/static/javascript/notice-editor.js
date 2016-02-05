var NoticeEditorView = Backbone.View.extend({
    el: '<div id="notice-editor"></div>',
    htmlPage: 'notice-editor.html',
    htmlStr: null,
    noticeId: null,
    model: null,
    authorities: ['ROLE_ADMIN'],
    initialize: function() {},
    events: {
        'click #noticeAddBtn': function(e) {
            e.preventDefault();
            this.create();
        },
        'click #noticeRemoveBtn': function(e) {
            e.preventDefault();
            this.remove();
        },

        'click #noticeCancelBtn': function(e) {
            e.preventDefault();
            this.cancel();
        }
    },
    beforeRender: function(noticeId) {
        this.noticeId = noticeId;
        this.model = null;
    },
    render: function(){
        if(this.htmlStr == null){
            this.htmlStr = App.comm.getHtml(this.htmlPage);
        }
        $(this.el).html(this.htmlStr);

        this.delegateEvents();

        if (this.noticeId){
            this.read();
            $('#noticeRemoveBtn').css("display", "inline");
        } else {
            $('#noticeRemoveBtn').css("display", "none");
        }

        $('#txtEditor').Editor();
    },
    read: function () {
        this.model = new Notice({ noticeId: this.noticeId });
        this.model.fetch({
            success: function(response){
                $('#noticeEditorTitle').val(response.get("title"));
                $('#txtEditor').Editor("setText", response.get("content"));
            },
            error: function(){
                alert("실패하였습니다.");
            }
        });
    },
    create: function(){
        if(this.model) {
            this.model.set({
                title: $('#noticeEditorTitle').val(),
                content: $('#txtEditor').Editor("getText")
            })
        }
        else {
            this.model = new Notice({
                title: $('#noticeEditorTitle').val(),
                content: $('#txtEditor').Editor("getText"),
                date: new Date("yyyy/MM/dd hh:mm:ss")
            });

        }
        this.model.save({},
            {
                success: function (response) {
                    window.location.hash = 'notice';
                },
                error: function (response) {
                    alert("실패하였습니다.");
                },
                complete: function () {
                }
            }
        );
    },
    remove: function(){
        if (confirm("삭제하시겠습니까?")) {
            this.model.destroy(
                {
                    success: function (response) {
                        window.location.hash = 'notice';
                    },
                    error: function (response) {
                        alert("실패하였습니다.");
                    },
                    complete: function(){
                    }
                }
            );
        }
    },
    cancel: function(){
        window.location.hash = 'notice';
    }
})
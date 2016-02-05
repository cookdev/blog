var Search = Backbone.Model.extend({
});

var SearchCollection = Backbone.PageableCollection.extend({
    model: Search,
    initialize: function(models, options){
        this.url = options.url;
        this.parseRecords = options.parseRecords;
    },
    mode: "server",
    state: {
        pageSize: 10,
        firstPage: 1,
        currentPage: 1
    },
    queryParams: {
        pageSize: "pageSize",
        currentPage: "pageIndex"
    },
    parseState: function(response, queryParams, state, options){
        return {totalRecords: response.totalCount};
    }
});

var SearchResultView = Backbone.View.extend({
    el: '<div id="search-result"></div>',
    htmlPage: 'search-result.html',
    htmlStr: null,
    keyword: null,
    searchCollection: null,
    paginator: null,
    searchUrl: null,
    tab: null,

    initialize: function() { },
    events: {
        'click #anyframe-presentation>a' : function(e){
            e.preventDefault();
            $("#anyframe-tab").css("display", "block");
            $("#blog-tab").css("display", "none");
            $("#forum-tab").css("display", "none");

            $("#anyframe-presentation").attr("class", "active");
            $("#blog-presentation").attr("class", "");
            $("#forum-presentation").attr("class", "");

            this.search("anyframe");
        },
        'click #blog-presentation>a' : function(e){
            e.preventDefault();
            $("#anyframe-tab").css("display", "none");
            $("#blog-tab").css("display", "block");
            $("#forum-tab").css("display", "none");

            $("#anyframe-presentation").attr("class", "");
            $("#blog-presentation").attr("class", "active");
            $("#forum-presentation").attr("class", "");

            this.search("blog");
        },
        'click #forum-presentation>a' : function(e){
            e.preventDefault();
            $("#anyframe-tab").css("display", "none");
            $("#blog-tab").css("display", "none");
            $("#forum-tab").css("display", "block");

            $("#anyframe-presentation").attr("class", "");
            $("#blog-presentation").attr("class", "");
            $("#forum-presentation").attr("class", "active");

            this.search("forum");
        },
        'submit #search-result-search-form': function(e){
            e.preventDefault();
            $("#search-form input[type=text]").val("");
            this.keyword = $("#search-result-search-form input[type=text]").val();
            if (this.keyword.length > 1){
                this.search("anyframe");
            } else {
                alert("두 글자 이상 입력하세요");
            }
            return;
        },
        'click #search-result-search-form .search-btn': function(e){
            e.preventDefault();
            $("#search-result-search-form").submit();
        }
    },
    search: function(tabName) {
        $("#refresh-animate").css("display", "block");

        switch(tabName) {
            case "anyframe":
                this.searchUrl = 'search/solr?query=' + this.keyword;
                this.tab = $("#anyframe-tab");
                break;
            case "blog":
                this.searchUrl = 'search/blog?query=' + this.keyword;
                this.tab = $("#blog-tab");
                break;
            case "forum":
                this.searchUrl = 'search/forum?query=' + this.keyword;
                this.tab = $("#forum-tab");
                break;
        }

        var self = this;
        self.tab.find(".total-count> h4").empty();
        $(".search-result>.paginator").empty();

        this.searchCollection = new SearchCollection({}, {
            url: this.searchUrl,
            parseRecords: function(response, options){
                $("#refresh-animate").css("display", "none");
                self.tab.find(".search-result-items").empty();

                _.each(response.result, function(model){
                    self.tab.find(".search-result-items").append(searchResultItemTemplate(model));
                });

                return response.result;
            }
        });


        this.searchCollection.getFirstPage({
            success: function(collection, response, options){
                self.tab.find(".total-count> h4").text('"' + self.keyword + '"' + " 에 대한 검색 결과 " + response.totalCount + "건 (" + (response.time * 0.001) + "초)");
                self.paginator = new Backgrid.Extension.Paginator({
                    collection: self.searchCollection,
                    windowSize: 10
                });

                $(".search-result>.paginator").append(self.paginator.render().$el);
            }
        });
    },
    beforeRender: function(keyword) {
        this.keyword = keyword;
    },
    render: function() {
        this.delegateEvents();

        if(this.htmlStr == null){
            this.htmlStr = App.comm.getHtml(this.htmlPage);
        }
        $(this.el).html(this.htmlStr);

        $("#search-result-search-form input[type=text]").val(this.keyword);
        this.search("anyframe");
    }
});